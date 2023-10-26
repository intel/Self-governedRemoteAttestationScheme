import logging
import json
import ctypes
import os
import sys
import time
import hashlib
import grpc_client
from Cryptodome.Hash import SHA384
from ecdsa import SigningKey, VerifyingKey, NIST384p
from Cryptodome.PublicKey import RSA
from crypto_utils import crypto_utility
from quote_verification import verify_dcap_quote
import ratls
from policies import Policies
from utility import config as pconfig

# Load .so
lib = ctypes.CDLL('./relying_party_enclave/keys_generation/generate_key_pair.so') 
# Define types of params and returns
lib.generate_rsa_keypair.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]
lib.generate_rsa_keypair.restype = None
lib.generate_ecdsa_keypair.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]
lib.generate_ecdsa_keypair.restype = None

logger = logging.getLogger(__name__)

class RPE:
    def __init__(self):
        self.conf = self.load_conf()
        conf = self.conf["rpe"]
        self.signing_keys = None
        self.encryption_keys = None
        self.grpc_server_address = conf["grpc_server_address"]
        self.rpo_address = conf["rpo_address"]
        self.rpo_port = conf["rpo_port"]
        self.rpe_port = conf["rpe_port"]
        self.local_rpe = {
            "rpe_id": conf["rpe_id"]
        }
        self.rpes = None
        self.session_id = None
        self.rpe_ids = None
        self.rpe_mr = None
        self.rpe_mrsigner = None
        self.rpe_isvprodid = None
        self.rpe_isvsvn = None
        self.policies_obj = None
        self.collaterals = None
        self.num_rpes_in_policies = None
        self.rpo_verification_result = None
        self.ratls = ratls.RATLS()
    
    def start(self):
        # Generate signing keys and encryption keys
        logger.info("Generating keys...")
        self.generate_keys_openssl()
        logger.info("public signing key:\n%s" % self.signing_keys["public"].to_pem().decode())
        logger.info("public encryption key:\n%s" % self.encryption_keys["public"].export_key("PEM").decode())
        logger.info("done.")
        
        # =============== Phase one ===============
        logger.info("======================= Starting phase one... =======================")
        self.ratls.initpublickeys(self.signing_keys["public"].to_pem(), self.encryption_keys["public"].export_key("PEM"))
        # RA-TLS to RPO
        success = self.ratls.client(self.rpo_address, self.rpo_port)
        
        # Get policies
        policies = None
        if not success:
            return
        policies = self.ratls.getPolicies()
        # logger.info("Policies: %s" % policies)

        # Get verification result
        if policies is None:
            logger.error("Get policies from RPO failed")
            return
        self.rpo_verification_result = self.ratls.getVerificaitionResult()
        logger.info("RPE successfully attested by RPO, verification result: %s" % self.rpo_verification_result)
        # logger.info("RPO verification result length : %d" % len(self.rpo_verification_result))

        # Parse policies
        policies_json = json.loads(policies)
        self.policies_obj = Policies(policies_json)
        self.session_id = self.policies_obj.getSesssionId()
        self.rpe_mr = self.policies_obj.getRPEMR()
        self.rpe_mrsigner = self.policies_obj.getRPEMRSigner()
        self.rpe_isvprodid = self.policies_obj.getRPEISVProdID()
        self.rpe_isvsvn = self.policies_obj.getRPEISVSVN()
        self.num_rpes_in_policies = self.policies_obj.getNumberOfRPE()
            
        # Load collateral
        logger.info("Loading collateral...")
        tcb_ids = self.policies_obj.getTcbIds()
        collateral_dict = dict()
        for tcb_id in tcb_ids:
            file_path = "collaterals/" + tcb_id + ".dat"
            collateral = self.load_collateral(file_path)
            collateral_dict[tcb_id] = collateral
        self.collaterals = collateral_dict
        logger.info("Done.")
        
        # Compute the hash of session id
        session_id_hash_bytes = None
        if self.session_id is not None:
            session_id_hash_bytes = self.compute_message_hash(bytes(self.session_id, "UTF-8"), SHA384)
        
        # Store the local rpe details
        self.local_rpe["details"] = {
            "session_id_hash": str(session_id_hash_bytes),
            "rpe_public_signing_key": self.signing_keys["public"].to_pem().decode(),
            "rpe_public_encryption_key": self.encryption_keys["public"].export_key("PEM").decode(),
            "rpo_verification_result": json.loads(self.rpo_verification_result)
        }
        rpe_verification_info = {
            "rpe_id": self.local_rpe["rpe_id"],
            "details": self.local_rpe["details"]
        }
        
        # Send rpe verification info to fabric-service
        logger.info("Sending verification result and RPO's signature to blockchian...")
        rpe_verification_info = json.dumps(rpe_verification_info)
        if not grpc_client.sendRPEVerificationInfo(self.grpc_server_address, rpe_verification_info):
            logger.error("Send RPE verification info to blockchain failed !")
            return
        logger.info("Done.")
        
        # Continiously get the other rpe's verification info from fabric-service, and if the number of 
        # rpes is equal to that in the policies and the cert(RPOs' identity) is valid, we will 
        # start the phase two verification.
        status, rpes_from_fabric = grpc_client.queryRPEs(self.grpc_server_address, self.num_rpes_in_policies)
        if not status:
            logger.error("Get other RPE info failed !")
            return

        # Store the rpes
        if rpes_from_fabric is not None:
            logger.info("RPEs' verification result attested by RPOs from blockchain: %s", rpes_from_fabric)
            rpes_from_fabric_list = json.loads(rpes_from_fabric)
            rpes = dict()
            logger.info("Verify signature of counter-part...")
            for rpe in rpes_from_fabric_list:
                rpe_id = rpe["worker_id"]
                rpo_public_signing_key = self.policies_obj.getPublicSigningKey(rpe_id)
                qeids = self.policies_obj.getRPEQEID(rpe_id)
                tcb_ids, tcb_infos = self.policies_obj.getRPETCBInfo(rpe_id)
                tcb_id = tcb_ids[0]
                collateral_base64_hash_from_policies = tcb_infos[tcb_id]
                for id, collateral in self.collaterals.items():
                    if id ==  tcb_id:
                        collateral_base64 = collateral
                        break
                
                # Verify the collateral read from file is the same as that in policies
                collateral_hash_compute = self.compute_message_hash(collateral_base64.encode('UTF-8'), SHA384)
                collateral_base64_hash_compute = crypto_utility.byte_array_to_base64(collateral_hash_compute)
                if collateral_base64_hash_from_policies != collateral_base64_hash_compute:
                    logger.error("Collateral hash computed for rpe %s is not the same as that in policies", rpe_id)
                    logger.info("collateral_base64_hash_from_policies: %s", collateral_base64_hash_from_policies)
                    logger.info("collateral_base64_hash_compute: %s", collateral_base64_hash_compute)
                    return
                
                details = json.loads(rpe["details"])
                rpes[rpe_id] = {
                    "rpe_id": rpe_id,
                    "rpo_public_signing_key": rpo_public_signing_key,
                    "rpo_verification_result": details["rpo_verification_result"],
                    "collateral": collateral_base64,
                    "qeid": qeids,
                    "details": details
                }
                # Verify rpos' signature for rpe to make sure the rpe is valid
                rpo_public_signing_key_obj = VerifyingKey.from_pem(rpo_public_signing_key.encode(), hashfunc=hashlib.sha384)
                signature_bytes = crypto_utility.base64_to_byte_array(details["rpo_verification_result"]["sig"])
                if not rpo_public_signing_key_obj.verify(signature_bytes, 
                                        bytes(json.dumps(details["rpo_verification_result"]["rpe_keys"]), "UTF-8")):
                    logger.error("rpo's sig verification failed, rpe_id is %s" % rpe_id)
                    return
            self.rpes = rpes
        
        logger.info("Verify signature Succeed! ")
        logger.info("======================= Phase one finished =======================\n")
        
        # =============== Phase two ===============
        logger.info("======================= Starting phase two... =======================")
        if self.rpes is not None:
            rpe_ids = ""
            for rpe_id in self.rpes.keys():
                rpe_ids += rpe_id + ","
            self.rpe_ids = rpe_ids[:len(rpe_ids)-1]
        
        # Generate quote
        quote = None
        if policies is not None:
            quote = self.generate_quote(policies)
        else:
            logger.error(" Get policies failed ! Can't generate quote !")
        
        # Send quote to fabric-service
        if quote is not None:
            logger.info("Sending quote to blockchain...")
            if not grpc_client.sendQuote(self.grpc_server_address, self.local_rpe["rpe_id"], quote):
                logger.error(" Send quote to fabric failed !")
                return
            logger.info("Done")
        else:
            logger.error(" Generate qoute failed !")
            return
        
        # Waiting for blockchain update
        time.sleep(1)
        
        # Get the other rpes' quote from fabric-service and do RA for them
        if self.rpes is not None:
            for rpe_id, rpe_info in self.rpes.items():
                rpe_details = rpe_info["details"]
                if policies is None:
                    break
                logger.info("Getting rpe %s quote from blockchain...")
                status, base64_encoded_quote = grpc_client.queryQuote(self.grpc_server_address, rpe_id)
                if not status:
                    return
                logger.info("Done")
                quote_bytes = crypto_utility.base64_to_byte_array(base64_encoded_quote)
                collateral = rpe_info["collateral"]
                # Dcap attestation
                logger.info("Verifying rpe %s quote" % rpe_id)
                ret = verify_dcap_quote.teeVerifyQuote(base64_encoded_quote, len(quote_bytes), collateral)
                logger.info("quote verification for rpe %s result: %x" % (rpe_id, ret))
                if ret != 0 and ret != 0xa002:
                    return
                logger.info("quote verification finished !")
                # Verify MR_ENCLAVE, MR_SIGNER, QEID and report_data
                report_data = self.generate_report_data(
                    rpe_details["rpe_public_signing_key"],
                    rpe_details["rpe_public_encryption_key"],
                    policies)
                # logger.info("report_data: %s", report_data.hex())
                base64_encoded_report_data = crypto_utility.byte_array_to_base64(report_data)
                rpe_policies_to_verify = {
                    "mr_enclave": self.rpe_mr,
                    "mr_signer": self.rpe_mrsigner,
                    "isv_prod_id": self.rpe_isvprodid,
                    "isv_svn": self.rpe_isvsvn,
                    "base64_encoded_report_data": base64_encoded_report_data,
                    "qeid": rpe_info["qeid"][0]
                }
                rpe_policies_to_verify = json.dumps(rpe_policies_to_verify)
                ret = verify_dcap_quote.sgxVerifyQuoteBody(base64_encoded_quote, rpe_policies_to_verify)
                logger.info("quote body verification finished !")
                if ret != 0:
                    return
            
        # Sign the verification result
        signature_bytes = self.signing_keys['private'].sign(bytes("true", "UTF-8"))
        signature = crypto_utility.byte_array_to_base64(signature_bytes)
        verification_result_json = {
            "result": "true",
            "sig": signature
        }
        verification_result = json.dumps(verification_result_json)
        
        # logger.info("verify_result before upload: %s" % verification_result)
        
        # Send verification_result to RPO
        self.ratls.something_client(self.rpo_address, self.rpo_port, verification_result)

        # Send verification result to fabric service
        logger.info("Sending verification result to fabric service...")
        status = grpc_client.sendVerificationResult(self.grpc_server_address, self.local_rpe["rpe_id"], verification_result)
        if not status:
            logger.error(" Sending verification result to fabric failed !")
            return
        logger.info("Done")
        # Waiting for blockchain update
        time.sleep(1)
        
        # Get verify final result from fabric service
        logger.info("Getting other verification result from fabric service...")
        status, verification_final_result = grpc_client.queryVerificationFinalResult(self.grpc_server_address, self.rpe_ids)
        if not status:
            logger.error(" Get other verification result from fabric failed !")
            return
        logger.info("Done")
        
        # Verify the others' verification result
        if verification_final_result is not None:
            logger.info("RPEs's mutual verification result: %s", verification_final_result)
            logger.info("Verify the signature")
            verification_final_result_json = json.loads(verification_final_result)
            for rpe_id, verification_result_json in verification_final_result_json.items():
                if verification_result_json["result"] != "true":
                    logger.error(" Get verify result failed: rpe %s!" % rpe_id)
                    return
                public_signing_key = self.rpes[rpe_id]["details"]["rpe_public_signing_key"]
                public_signing_key_obj = VerifyingKey.from_pem(public_signing_key.encode(), hashfunc=hashlib.sha384)
                signature_bytes = crypto_utility.base64_to_byte_array(verification_result_json["sig"])
                if not public_signing_key_obj.verify(signature_bytes, bytes("true", "UTF-8")):
                    logger.error(" Verify verification result sig failed: rpe %s!" % rpe_id)
                    return
            logger.info("Done.")
            logger.info("======================= Phase two finished =======================\n")

        # =============== Phase three ===============
        logger.info("======================= Starting phase three... =======================")
        ce_tcb_ids = self.policies_obj.getCETcbIds(self.local_rpe["rpe_id"])
        ce_collateral_dict = dict()
        for ce_tcb_id in ce_tcb_ids:
            ce_collateral_dict[ce_tcb_id] = json.loads(self.collaterals[ce_tcb_id])
        ce_collaterals = json.dumps(ce_collateral_dict)
        self.ratls.initTCBInfo(ce_collaterals)
        
        # RPE starts server port.
        ret = self.ratls.server_init(self.rpe_port)
        if ret != 1:
            logger.error("RA-TLS verification failed!")
        tcb_id = self.ratls.getTCBid()
        ce_id = self.ratls.getCEid()
        ces_info = self.policies_obj.getCEinfo(self.local_rpe["rpe_id"], ce_id)
        logger.info("ces info managed by local rpe: %s" % ces_info)
        ret, job_id = self.ratls.verifyCE(ces_info)
        
        if ret == 1:
            # Check if tcb id is in the job
            if not self.policies_obj.checkTcbId(job_id, tcb_id):
                logger.error("RA-TLS verification failed! The tcb is not match")
                return
            
            logger.info("RPE successfully attested CE")
            
            # Get CE public keys
            CESigningkey, CEEncryptionkey = self.ratls.getCEPubKeys() 
            
            # Sign CE public keys
            signature_bytes = self.signing_keys['private'].sign(CESigningkey + CEEncryptionkey)
            signature = crypto_utility.byte_array_to_base64(signature_bytes)
            
            # Send CE public keys to fabric service
            logger.info("Sending CE's public keys and signature to blockchain")
            gramines = [{
                "public_signing_key": CESigningkey.decode(),
                "public_encryption_key": CEEncryptionkey.decode()
            }]
            ce = {
                "gramines": gramines,
                "sig": signature
            }
            
            status = grpc_client.sendCEInfo(self.grpc_server_address, job_id, json.dumps(ce))
            if not status:
                logger.error(" send CE info failed !")
            
            logger.info("Done")
            # Waiting for blockchain update
            time.sleep(1)
            
        # Get other's CE RA info and verify these RA info
        # If the verification is successful, get counterpart CE public keys according to policies
        # Find the ce to connect
        jobs = self.policies_obj.getCorrespondingJobs(job_id)
        logger.info("jobs: %s" % jobs)
        if jobs is None:
            return
        
        # Get corresponding CE public keys from fabric service
        job_ids_str = ""
        for job_dict in jobs:
            for job_id in job_dict["jobs"]:
                job_ids_str += job_id + ","
        job_ids_str = job_ids_str[:len(job_ids_str)-1]
        logger.info("job_ids_str: %s" % job_ids_str)
        status, CEsInfo = grpc_client.queryCEsInfo(self.grpc_server_address, job_ids_str)
        if not status:
            return
        logger.info("Got counter-part CEs: %s" % CEsInfo)
        logger.info("Verify CEs signature")
        
        # Verify signature of CE
        CEsInfo_json = json.loads(CEsInfo)
        for job_id, ce in CEsInfo_json.items():
            ce_json = json.loads(ce)
            rpe_id = self.policies_obj.getCorrespondingRPE(job_id)
            public_signing_key = self.rpes[rpe_id]["details"]["rpe_public_signing_key"]
            public_signing_key_obj = VerifyingKey.from_pem(public_signing_key.encode(), hashfunc=hashlib.sha384)
            signature_bytes = crypto_utility.base64_to_byte_array(ce_json["sig"])
            gramine = ce_json["gramines"][0]
            ce_public_keys = gramine["public_signing_key"].encode() + gramine["public_encryption_key"].encode()
            if not public_signing_key_obj.verify(signature_bytes, ce_public_keys):
                logger.error(" Verify ce sig failed: job id is %s!" % job_id)
                return
        logger.info("Done")
        logger.info("======================= Phase three finished =======================\n")
        
        # Sign yes for CE cuccessful verification
        signature_bytes = self.signing_keys['private'].sign(bytes("true", "UTF-8"))
        signature = crypto_utility.byte_array_to_base64(signature_bytes)
        ce_verification_result = {
            "result": "true",
            "sig": signature
        }
    
        # Send ce_verification_result to RPO
        ce_verification_result = json.dumps(ce_verification_result)
        # logger.info("verify_result before sending to rpo: " + ce_verification_result)
        self.ratls.something_client(self.rpo_address, self.rpo_port, ce_verification_result)
        
        # =============== Phase four ===============
        logger.info("======================= Starting phase four... =======================")
        
        # Send counterpart CE's public key
        for job_dict in jobs:
            job_ids = job_dict["jobs"]
            job_dict["jobs"] = list()
            for job_id in job_ids:
                job_public_keys = json.loads(CEsInfo_json[job_id])["gramines"][0]
                job_dict["jobs"].append(job_public_keys)
        logger.info("jobs to send to local ce: %s" % jobs)
        jobs_str = json.dumps(jobs)

        while True:
            if ret==1:
                ret = self.ratls.passData(jobs_str)
            if ret==2:
                logger.info("key+__+_______________d" )
            if ret==3:
                ret = self.ratls.something()

    def generate_keys(self):
        private_signing_key = SigningKey.generate(curve=NIST384p, hashfunc=hashlib.sha384)
        public_signing_key = private_signing_key.get_verifying_key()
        self.signing_keys = {
            "public": public_signing_key,
            "private": private_signing_key
        }
        
        private_encryption_key = RSA.generate(3072)
        public_encryption_key = private_encryption_key.publickey()
        self.encryption_keys = {
            "public": public_encryption_key,
            "private": private_encryption_key
        }
        
    def generate_keys_openssl(self):
        
        # Generate secp384r1 ECDSA key pair
        ecdsa_private_pem, ecdsa_public_pem = self.generate_ecdsa_keypair()
        # Generate RSA3072 key pair
        rsa_private_pem, rsa_public_pem = self.generate_rsa_keypair()
        
        # Import rsa and ecdsa key pair
        private_signing_key = SigningKey.from_pem(ecdsa_private_pem, hashfunc=hashlib.sha384)
        public_signing_key = VerifyingKey.from_pem(ecdsa_public_pem, hashfunc=hashlib.sha384)
        self.signing_keys = {
            "public": public_signing_key,
            "private": private_signing_key
        }
        
        private_encryption_key = RSA.import_key(rsa_private_pem)
        public_encryption_key = RSA.import_key(rsa_public_pem)
        self.encryption_keys = {
            "public": public_encryption_key,
            "private": private_encryption_key
        }
        
    def generate_rsa_keypair(self):
        private_pem = ctypes.c_char_p()
        public_pem = ctypes.c_char_p()
        lib.generate_rsa_keypair(ctypes.byref(private_pem), ctypes.byref(public_pem))
        private_pem_str = private_pem.value.decode()
        public_pem_str = public_pem.value.decode()
        lib.free(private_pem)
        lib.free(public_pem)
        return private_pem_str, public_pem_str

    def generate_ecdsa_keypair(self):
        private_pem = ctypes.c_char_p()
        public_pem = ctypes.c_char_p()
        lib.generate_ecdsa_keypair(ctypes.byref(private_pem), ctypes.byref(public_pem))
        private_pem_str = private_pem.value.decode()
        public_pem_str = public_pem.value.decode()
        lib.free(private_pem)
        lib.free(public_pem)
        return private_pem_str, public_pem_str
        
    def generate_quote(self, user_data):
        try:
            logger.info("Generating Quote...")
            fd = os.open("/dev/attestation/user_report_data", os.O_RDWR)
            report_data = self.generate_report_data(
                self.signing_keys["public"].to_pem().decode(),
                self.encryption_keys["public"].export_key("PEM").decode(),
                user_data)
            os.write(fd, report_data)
            os.close(fd)
            # logger.info("report data hex = {}".format(report_data.hex()))
            with open('/dev/attestation/quote', 'rb') as fd:
                data = fd.read()
            logger.info("Quote generated")
            quote = crypto_utility.byte_array_to_base64(data)
            return quote
        except Exception as e:
            logger.error(
                "Generate quote failed!"
                " Error message %(%s)" % str(e) )
    
    def generate_report_data(self, vkey_pem, ekey_pem, user_data):
        try:
            worker_data = vkey_pem + ekey_pem
            keys_bytes = self.compute_message_hash(
                    worker_data.encode('UTF-8'), SHA384)
            user_data_bytes = self.compute_message_hash(
                    user_data.encode('UTF-8'), SHA384)
            return bytes(keys_bytes) + bytes(user_data_bytes)
        except Exception as e:
            logger.error(
                "Generate report data failed!"
                " Error message %(%s)" % str(e) )

    def load_conf(self):
        try:
            conf = pconfig.parse_configuration_files(
                    ["config.toml"],
                    ["/"])
            return conf
        except pconfig.ConfigurationException as e:
            logger.error(str(e))
            sys.exit(-1)
            
    def load_collateral(self, filepath):
        try:
            with open(filepath, "r") as fd:
                data = fd.read()
                fd.close()
            return data
        except Exception as e:
            logger.error(
                "Load collateral from %s failed!"
                " Error message %(%s)" % (filepath, str(e)) )
            return None
            
    def compute_message_hash(self, message_bytes, shafunc):
        """
        Computes message hash.

        Parameters :
            message_bytes: Message in bytes
        Returns :
            SHA* message hash.
        """
        hash_obj = shafunc.new()
        hash_obj.update(message_bytes)
        return hash_obj.digest()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    rpe = RPE()
    rpe.start()
