import logging
import json
import os
import time
import ctypes

RAtlsserver = ctypes.CDLL('./relying_party_owner/RATLS_Conn/libRAtlsserver.so')

logger = logging.getLogger(__name__)

class RATLS:
    def initMeasurements(self, mr, mrsigner, isvprodid, isvsvn):
        RAtlsserver.init_measurements.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
        # RAtlsserver.init_measurements.restype = ctypes.c_int
        b_mr = mr.encode('utf-8')
        b_mrsigner = mrsigner.encode('utf-8')
        b_isvprodid = isvprodid.encode('utf-8')
        b_isvsvn = isvsvn.encode('utf-8')
        RAtlsserver.init_measurements(ctypes.c_char_p(b_mr), ctypes.c_char_p(b_mrsigner),
                                      ctypes.c_char_p(b_isvprodid), ctypes.c_char_p(b_isvsvn))

    def initQEID(self, qeid):
        RAtlsserver.init_qeid.argtypes = [ctypes.c_char_p]
        # RAtlsserver.init_measurements.restype = ctypes.c_int
        s = ''.join(str(x+' ') for x in qeid)
        b_qeid = s.encode('utf-8')
        RAtlsserver.init_qeid(ctypes.c_char_p(b_qeid))

    def initTCBInfo(self, tcb_info):
        RAtlsserver.init_tcb_info.argtypes = [ctypes.c_char_p]
        # RAtlsserver.init_measurements.restype = ctypes.c_int
        # s = ''.join(str(x+' ') for x in tcb_info)
        # b_tcb_info = s.encode('utf-8')
        b_tcb_info = tcb_info.encode('utf-8')
        RAtlsserver.init_tcb_info(ctypes.c_char_p(b_tcb_info))
    
    def server_init(self, port):
        try:
            RAtlsserver.ra_tls_server_init.argtypes = [ctypes.c_char_p]
            RAtlsserver.ra_tls_server_init.restype = ctypes.c_int

            b_port = port.encode('utf-8')
            result = RAtlsserver.ra_tls_server_init(ctypes.c_char_p(b_port))

            return result
        
        except Exception as e:
            logger.error(
                "Server_init error"
                " Error message %(message)" % 
                { "message": str(e) })
            raise

    def getRPEPublicKeys(self):
        RAtlsserver.get_public_keys.argtypes = []
        # RAtlsserver.get_public_keys.restype = ctypes.c_int
        
        RAtlsserver.get_rpe_signingkey.argtypes = []
        RAtlsserver.get_rpe_signingkey.restype = ctypes.c_char_p

        RAtlsserver.get_rpe_encryptionkey.argtypes = []
        RAtlsserver.get_rpe_encryptionkey.restype = ctypes.c_char_p

        RAtlsserver.get_public_keys()

        return RAtlsserver.get_rpe_signingkey(), RAtlsserver.get_rpe_encryptionkey()


            
    def passPolicyData(self, policies_data, verification_result):
        RAtlsserver.pass_policy_data.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        RAtlsserver.pass_policy_data.restype = ctypes.c_int
        b_policies_data = policies_data.encode('utf-8')
        b_verification_result = verification_result.encode('utf-8')
        result = RAtlsserver.pass_policy_data(ctypes.c_char_p(b_policies_data), ctypes.c_char_p(b_verification_result))
        return result
    
    def something(self):
        RAtlsserver.wait.argtypes = []
        RAtlsserver.wait.restype = ctypes.c_int

        result = RAtlsserver.wait()
        return result    

    def getSomethingBuf(self):
        RAtlsserver.get_something_buf.argtypes = []
        RAtlsserver.get_something_buf.restype = ctypes.c_char_p
      
        return ctypes.string_at(RAtlsserver.get_something_buf()).decode() 
            