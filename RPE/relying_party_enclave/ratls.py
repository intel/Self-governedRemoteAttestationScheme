import logging
import json
import os
import time
import ctypes

RAtls = ctypes.CDLL('./relying_party_enclave/RATLS_Conn/libRAtls.so')

logger = logging.getLogger(__name__)

class RATLS:
    def __init__(self):
        # self.signing_keys = "aaa"
        # self.encryption_keys = "bbb"
        # self.rpe_address = '192.168.122.50:50051'
        # self.local_rpe = None
        # self.rpes = None
        self.policies_data = None

    def something_client(self, address, port, something):
        try:
            RAtls.something_client.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
            RAtls.something_client.restype = ctypes.c_int

            b_address = address.encode('utf-8')
            b_port = port.encode('utf-8')
            b_something = something.encode('utf-8')
           
            return RAtls.something_client(ctypes.c_char_p(b_address), ctypes.c_char_p(b_port), ctypes.c_char_p(b_something))

        except Exception as e:
            raise
            logger.error(
                "Unable to retrieve worker information from %(url)s."
                " Error message %(message)" % 
                { "url": url, "message": str(e) })
            

    def initpublickeys(self, signing_key, encryption_keys):
        RAtls.init_pubkeys.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        #RAtlsclient.init_pubkeys.restype = ctypes.c_char_p

        RAtls.init_pubkeys(ctypes.c_char_p(signing_key), ctypes.c_char_p(encryption_keys))
    
    def client(self, address, port):
        try:
            RAtls.ra_tls_client.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            RAtls.ra_tls_client.restype = ctypes.c_char_p

            b_address = address.encode('utf-8')
            b_port = port.encode('utf-8')
           
            result = RAtls.ra_tls_client(ctypes.c_char_p(b_address), ctypes.c_char_p(b_port))
            self.policies_data = ctypes.string_at(result).decode()
            # RAtlsclient.free(result)
            if self.policies_data == "None":
                logger.error("\n")
                logger.error(" RA connection failed !")
                return False

            return True

        except Exception as e:
            raise
            logger.error(
                "Unable to retrieve worker information from %(url)s."
                " Error message %(message)" % 
                { "url": url, "message": str(e) })
            
        return True
            
    def getPolicies(self):
        return self.policies_data
    
    def getVerificaitionResult(self):
        RAtls.get_verification_result.argtypes = []
        RAtls.get_verification_result.restype = ctypes.c_char_p

        result = RAtls.get_verification_result()
        return ctypes.string_at(result).decode()
    

    def getCEMR(self):
        RAtls.get_ce_mr.argtypes = []
        RAtls.get_ce_mr.restype = ctypes.c_char_p

        result = RAtls.get_ce_mr()
        return ctypes.string_at(result).hex()
    
    def getCEMRSigner(self):
        RAtls.get_ce_mrsigner.argtypes = []
        RAtls.get_ce_mrsigner.restype = ctypes.c_char_p

        result = RAtls.get_ce_mrsigner()
        return ctypes.string_at(result).hex()
    
    def getCEISVProdid(self):
        RAtls.get_ce_isvprodid.argtypes = []
        RAtls.get_ce_isvprodid.restype = ctypes.c_char_p

        result = RAtls.get_ce_isvprodid()
        return ctypes.string_at(result).decode()
    
    def getCEISVSvn(self):
        RAtls.get_ce_isvsvn.argtypes = []
        RAtls.get_ce_isvsvn.restype = ctypes.c_char_p

        result = RAtls.get_ce_isvsvn()
        return ctypes.string_at(result).decode()


    def getCEQEid(self):
        RAtls.get_ce_qeid.argtypes = []
        RAtls.get_ce_qeid.restype = ctypes.c_char_p

        result = RAtls.get_ce_qeid()
        return ctypes.string_at(result).hex()
    
    def getCEid(self):
        RAtls.get_ce_id.argtypes = []
        RAtls.get_ce_id.restype = ctypes.c_char_p

        result = RAtls.get_ce_id()
        return ctypes.string_at(result).decode()
    
    def getTCBid(self):
        RAtls.get_tcb_id.argtypes = []
        RAtls.get_tcb_id.restype = ctypes.c_char_p

        result = RAtls.get_tcb_id()
        return ctypes.string_at(result).decode()

    def initTCBInfo(self, tcb_info):
        RAtls.init_tcb_info.argtypes = [ctypes.c_char_p]
        # RAtls.init_measurements.restype = ctypes.c_int
        # s = ''.join(str(x+' ') for x in tcb_info)
        s = tcb_info
        b_tcb_info = s.encode('utf-8')
        RAtls.init_tcb_info(ctypes.c_char_p(b_tcb_info))
    
    def server_init(self, port):
        try:
            RAtls.ra_tls_server_init.argtypes = [ctypes.c_char_p]
            RAtls.ra_tls_server_init.restype = ctypes.c_int

            b_port = port.encode('utf-8')
            result = RAtls.ra_tls_server_init(ctypes.c_char_p(b_port))

            return result
          
            logger.info(os.listdir())
          

        except Exception as e:
            raise
            logger.error(
                "Unable to retrieve worker information from %(url)s."
                " Error message %(message)" % 
                { "url": url, "message": str(e) })
            
    def verifyCE(self, ce_info):
        # {'job-1': {'rpe': 'rpe-1', 
        #            'cust_qeid_allowed': ['first qeid'], 
        #            'tcb_allowed': ['tcb-1'], 
        #            'mrenclave_allow_any': True, 
        #            'mrsigner_allow_any': True, 
        #            'isvprodid_allow_any': True, 
        #            'isvsvn_allow_any': True}, 
        #  'job-2': {'rpe': 'rpe-1', 
        #            'cust_qeid_allowed': ['second qeid'], 
        #            'tcb_allowed': ['tcb-1'], 
        #            'mrenclave': '4ea60548cce6f25ab0b02c6f326d33222bdd74e73df817a39fbbd2af562f77bd', 
        #            'mrsigner': 'mrsigner value', 
        #            'isv_prod_id': '0', 
        #            'isv_svn': '0'}, 
        #  'job-3': {'rpe': 'rpe-2', 
        #            'cust_qeid_allowed': ['third qeid', 'efbac5bb8d8cd796a8379405e5e846e2'], 
        #            'tcb_allowed': ['tcb-1', 'tcb-2'], 
        #            'mrenclave': '4ea60548cce6f25ab0b02c6f326d33222bdd74e73df817a39fbbd2af562f77bd', 
        #            'mrsigner': 'mrsigner value', 
        #            'isv_prod_id': '0', 
        #            'isv_svn': '0'}
        # }

        # {'job-2': {'rpe': 'rpe-1', 
        #            'cust_qeid_allowed': ['second qeid', 'efbac5bb8d8cd796a8379405e5e846e2'], 
        #            'tcb_allowed': ['tcb-1'], 
        #            'mrenclave': '4ea60548cce6f25ab0b02c6f326d33222bdd74e73df817a39fbbd2af562f77bd', 
        #            'mrsigner': 'mrsigner value', 
        #            'isv_prod_id': '0', 
        #            'isv_svn': '0'}
        # }
        job = None
        for key in ce_info.keys():
            job = key
            # verify ce mr
            if 'mrenclave' in ce_info[key].keys() and self.getCEMR() != ce_info[key]['mrenclave']:
                logger.error(" CE mr verification failed !")
                logger.info("mrenclave: %s", self.getCEMR())
                return -1, None
            elif 'mrenclave_allow_any' in ce_info[key].keys() and ce_info[key]['mrenclave_allow_any'] != True:
                logger.error(" CE mr verification failed !")
                return -1, None
            
            if 'mrsigner' in ce_info[key].keys() and self.getCEMRSigner() != ce_info[key]['mrsigner']:
                logger.error(" CE mrsigner verification failed !")
                return -1, None
            elif "mrsigner_allow_any" in ce_info[key].keys() and ce_info[key]['mrsigner_allow_any'] != True:
                logger.error(" CE mrsigner verification failed !")
                return -1, None
            
            if 'isv_prod_id' in ce_info[key].keys() and self.getCEISVProdid() != ce_info[key]['isv_prod_id'] and ce_info[key]['isv_prod_id'] != "0":
                logger.error(" CE isv_prod_id verification failed !")
                return -1, None
            elif "isvprodid_allow_any" in ce_info[key].keys() and ce_info[key]['isvprodid_allow_any'] != True:
                logger.error(" CE isv_prod_id verification failed !")
                return -1, None
            
            if 'isv_svn' in ce_info[key].keys() and self.getCEISVSvn() != ce_info[key]['isv_svn'] and ce_info[key]['isv_svn'] != "0":
                logger.error(" CE isv_svn verification failed !")
                return -1, None
            elif "isvsvn_allow_any" in ce_info[key].keys() and ce_info[key]['isvsvn_allow_any'] != True:
                logger.error(" CE isv_svn verification failed !")
                return -1, None
            
            # verify ce qeid
            flag = False
            for id in ce_info[key]['cust_qeid_allowed']:
                if id == self.getCEQEid():
                    flag = True
                    break
            if flag is False:
                logger.info(" CE qe id verification failed !")
                return -1, None

            # TODO: verify ce tcb

        return 1, job


    def getCEPubKeys(self):
        RAtls.get_ce_signingkey.argtypes = []
        RAtls.get_ce_signingkey.restype = ctypes.c_char_p
        RAtls.get_ce_encryptionkey.argtypes = []
        RAtls.get_ce_encryptionkey.restype = ctypes.c_char_p

        return RAtls.get_ce_signingkey(), RAtls.get_ce_encryptionkey()


            
    def passData(self, data):
        RAtls.pass_data.argtypes = [ctypes.c_char_p]
        RAtls.pass_data.restype = ctypes.c_int
        b_data = data.encode('utf-8')
        result = RAtls.pass_data(ctypes.c_char_p(b_data))
        return result
    
    def something(self):
        RAtls.wait.argtypes = []
        RAtls.wait.restype = ctypes.c_int

        result = RAtls.wait()
        return result      