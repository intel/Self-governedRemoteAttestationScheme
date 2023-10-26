import logging
import json
import os
import time
import ctypes

RAtlsclient = ctypes.CDLL('./customer_enclave/RATLS_Conn/libRAtlsclient.so')

logger = logging.getLogger(__name__)

class RATLS:
    def __init__(self):
        # self.signing_keys = "aaa"
        # self.encryption_keys = "bbb"
        # self.rpe_address = '192.168.122.50:50051'
        # self.local_rpe = None
        # self.rpes = None
        self.data = None

    def initpublickeys(self, signing_key, encryption_keys):
        RAtlsclient.init_pubkeys.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        #RAtlsclient.init_pubkeys.restype = ctypes.c_char_p

        RAtlsclient.init_pubkeys(ctypes.c_char_p(signing_key), ctypes.c_char_p(encryption_keys))

    def initCEID(self, ce_id):
        RAtlsclient.init_ce_id.argtypes = [ctypes.c_char_p]
        #RAtlsclient.init_pubkeys.restype = ctypes.c_char_p
        b_ce_id = ce_id.encode('utf-8')  

        RAtlsclient.init_ce_id(ctypes.c_char_p(b_ce_id))
    
    def sendKeys2RPE(self, address, port):
        try:
            RAtlsclient.ra_tls_client.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            RAtlsclient.ra_tls_client.restype = ctypes.c_char_p

            b_address = address.encode('utf-8')
            b_port = port.encode('utf-8')
           
            result = RAtlsclient.ra_tls_client(ctypes.c_char_p(b_address), ctypes.c_char_p(b_port))
            self.data = ctypes.string_at(result).decode()
            # RAtlsclient.free(result)
            if self.data == "None":
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
            
    def getCounterpartKeys(self):
        return self.data
