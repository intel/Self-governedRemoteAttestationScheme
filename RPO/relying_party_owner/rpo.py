import logging
import json
import sys
from ecdsa import SigningKey, VerifyingKey
from crypto_utils import crypto_utility
from utility import config as pconfig
import hashlib

import ratls
import policies

logger = logging.getLogger(__name__)

class RPO:
    def __init__(self):
        self.conf = self.load_conf()
        conf = self.conf["rpo"]
        self.policies_path = conf["policies_path"]
        self.private_key_path = conf["private_key_path"]
        self.evience_path = conf["evidence_path"]
        self.policies = policies.Policies()
        self.ratls = ratls.RATLS()

        self.signing_keys = dict()

        self.port = conf["port"]
        self.managed_rpe = conf["rpe_id"]

        self.rpe_mr = None
        self.rpe_mrsigner = None
        self.rpe_isvprodid = None
        self.rpe_isvsvn = None
        self.rpe_qeid = None
        self.tcb_info = None
        self.collaterals = None

        self.policies_data = None
    
    def start(self):
        # =============== RPO initialization ===============
        logger.info("RPO initialization...")
        # Load private signing key
        self.load_private_signing_key()

        # Parsing Policies.
        self.policies_data = self.policies.load(self.policies_path)
        self.rpe_mr = self.policies.getRPEMR()
        self.rpe_mrsigner = self.policies.getRPEMRSigner()
        self.rpe_isvprodid = self.policies.getRPEISVProdID()
        self.rpe_isvsvn = self.policies.getRPEISVSVN()
        self.rpe_qeid = self.policies.getRPEQEID(self.managed_rpe)
        self.tcb_info = self.policies.getTCBInfo(self.managed_rpe)
        public_signing_key = self.policies.getPublicSigningKey(self.managed_rpe)
        logger.info("Loading rpe collateral...")
        tcb_ids = self.policies.getRpeTcbIds(self.managed_rpe)
        collateral_dict = dict()
        for tcb_id in tcb_ids:
            file_path = "collaterals/" + tcb_id + ".dat"
            collateral = self.load_collateral(file_path)
            collateral_dict[tcb_id] = collateral
        self.collaterals = collateral_dict
        logger.info("Done.")
        logger.info("public_signing_key:\n %s" % public_signing_key)
        self.signing_keys["public_signing_key"]  = VerifyingKey.from_pem(public_signing_key)

        # =============== Phase one ===============
        logger.info("======================= Starting phase one... =======================")

        # Prepare verfication info that RPO verifies RPE including QEID and tcb info
        self.ratls.initMeasurements(self.rpe_mr, self.rpe_mrsigner, self.rpe_isvprodid, self.rpe_isvsvn)
        self.ratls.initQEID(self.rpe_qeid)
        self.ratls.initTCBInfo(self.collaterals[tcb_ids[0]])

        # RPO starts server port.
        ret = self.ratls.server_init(self.port)
        if ret != 1:
            logger.error("RA-TLS verification failed!")
            return
        
        logger.info("RPO successfully attested RPE")
        
        # Get RPE's keys
        RPESigningkey, RPEEncryptionkey = self.ratls.getRPEPublicKeys()
        
        # Sign rpe's key.
        rpe_keys = {
            "public_signing_key": RPESigningkey.decode(),
            "public_encryption_key": RPEEncryptionkey.decode()
        }
        signature_bytes = self.signing_keys['private_signing_key'].sign(
                                    bytes(json.dumps(rpe_keys), "UTF-8"))
        signature = crypto_utility.byte_array_to_base64(signature_bytes)
        rpo_verification_result_json = {
            "rpe_keys": rpe_keys,
            "sig": signature
        }
        rpo_verification_result = json.dumps(rpo_verification_result_json)
        logger.info("verify_result sending to rpe: " + rpo_verification_result)
        # logger.info("lengh: %d", len(rpo_verification_result))

        # Pass policy data, which will pass to RPE if the RPE verification is successful 
        ret = self.ratls.passPolicyData(self.policies_data, rpo_verification_result)

        # Get rpe_verification_result once phase two is done
        rpe_verification_result = self.ratls.getSomethingBuf()
        logger.info("======================= Phase two verification has finished =======================")
        logger.info("RPEs verifcation result: %s" % rpe_verification_result)
        
        if ret == 3:
            ret = self.ratls.something()
        else:
            logger.error("Policies and phase one verification result transform failed")
            return
        
        ce_verification_result = self.ratls.getSomethingBuf() 
        logger.info("======================= Phase three verification has finished =======================")
        logger.info("CE verifcation result: %s" % ce_verification_result)
                
        # Get CE's keys from RPE once phase three is done
        verification_result = {
            "rpo_verification_result": rpo_verification_result,
            "rpe_verification_result": rpe_verification_result,
            "ce_verification_result": ce_verification_result
        }
        verification_result_bytes = bytes(json.dumps(verification_result), "UTF-8")
        
        # Write evidences to file
        try:
            with open(self.evience_path, 'wb') as fd:
                fd.write(verification_result_bytes)
        except Exception as e:
            logger.error(
                "Write evidence failed!"
                " Error message %(%s)" % str(e) )
            
        while True:
             if ret==3:
                ret = self.ratls.something()
             else:
                 return


    def load_private_signing_key(self):
        logger.info("Read private signing key")
        try:
            with open(self.private_key_path, 'rb') as fd:
                data = fd.read()
            self.signing_keys["private_signing_key"] = SigningKey.from_pem(data.decode(), hashfunc=hashlib.sha384)
        except Exception as e:
            logger.error(
                "Read private key failed!"
                " Error message %(%s)" % str(e) )
    
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
    
    def load_conf(self):
        try:
            conf = pconfig.parse_configuration_files(
                    ["config.toml"],
                    ["./"])
            return conf
        except pconfig.ConfigurationException as e:
            logger.error(str(e))
            sys.exit(-1)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    rpo = RPO()
    rpo.start()