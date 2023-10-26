import logging
import ctypes
import sys
import hashlib
from ecdsa import SigningKey, VerifyingKey, NIST384p
from Cryptodome.PublicKey import RSA
from utility import config as pconfig
import ratls

# Load .so
lib = ctypes.CDLL('./customer_enclave/keys_generation/generate_key_pair.so') 
# Define types of params and returns
lib.generate_rsa_keypair.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]
lib.generate_rsa_keypair.restype = None
lib.generate_ecdsa_keypair.argtypes = [ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_char_p)]
lib.generate_ecdsa_keypair.restype = None

logger = logging.getLogger(__name__)

class RPE:
    def __init__(self):
        self.conf = self.load_conf()
        conf = self.conf["ce"]
        self.signing_keys = None
        self.encryption_keys = None
        self.local_ce = conf["local_ce"]   
        self.rpe_address = conf["rpe_address"]
        self.rpe_port = conf["rpe_port"]
        self.rpes = None
        self.ratls = ratls.RATLS()
    
    def start(self):
        # Generate signing keys and encryption keys
        logger.info("Generating keys...")
        self.generate_keys_openssl()
        logger.info("public signing key:\n%s" % self.signing_keys["public"].to_pem().decode())
        logger.info("public signing key size:%d" % len(self.signing_keys["public"].to_pem()))
        logger.info("public encryption key:\n%s" % self.encryption_keys["public"].export_key("PEM").decode())
        logger.info("public encryption key size:%d" % len(self.encryption_keys["public"].export_key("PEM")))
        logger.info("done.")
        
        # =============== Phase one ===============
        logger.info("======================= Starting ... =======================")
        # RA-TLS to RPE
        self.ratls.initCEID(self.local_ce)
        self.ratls.initpublickeys(self.signing_keys["public"].to_pem(), self.encryption_keys["public"].export_key("PEM"))
        success = self.ratls.sendKeys2RPE(self.rpe_address, self.rpe_port)
        
        # Get conterpart public keys
        pubkeys = None
        if success:
            pubkeys = self.ratls.getCounterpartKeys()
        logger.info("Counterpart public keys info: %s",pubkeys)
    
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
    
    def load_conf(self):
        try:
            conf = pconfig.parse_configuration_files(
                    ["config.toml"],
                    ["/"])
            return conf
        except pconfig.ConfigurationException as e:
            logger.error(str(e))
            sys.exit(-1)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    rpe = RPE()
    rpe.start()