import logging
import json
import os
import time
import ctypes

logger = logging.getLogger(__name__)

class Policies:
    def __init__(self):
        self.policies_data_json = None
    
    def load(self, path):
        try:
            # load policies.json    
            logger.info(" load policies from %s", path)
            data = None
            with open(path, 'rb') as fd:
                data = fd.read()
            if data is None:
                logger.error("No policies to read")
                return None
            self.policies_data_json = json.loads(data)

        except Exception as e:
            logger.error(
                "Load policies.json error"
                " Error message %(message)" % 
                { "message": str(e) })
            raise
            
        return json.dumps(self.policies_data_json)
            
    def get_policies_data(self):
        policies_data_json = self.policies_data_json
        return json.dumps(policies_data_json)
    
    def getRpeTcbIds(self, rpe_id):
        # Get rpe tcb id from policies 
        logger.info(" get rpe tcb id from policies")
        policies_data_json = self.policies_data_json
        tcb_ids = None
        for rpe in policies_data_json["rpe"]:
            if rpe["id"] == rpe_id:
                tcb_ids = rpe["tcb_allowed"]
        return tcb_ids
    
    def getPublicSigningKey(self, rpe_id):
        # Get public signing key from policies.json 
        logger.info(" get public signing key from policies.json")
        policies_data_json = self.policies_data_json
        public_signing_key = None
        for rpe in policies_data_json["rpe"]:
            if rpe["id"] == rpe_id:
                public_signing_key = rpe["ca_signing_key_cert"]
                break
        if public_signing_key is None:
            logger.error("Cannot resolve public signing key of managed_rpe %s" % rpe_id)
            return None
        return public_signing_key

    def getRPEMR(self):
        # Get rpe mr from policies.json 
        logger.info("get rpe mr from policies.json")
        policies_data_json = self.policies_data_json
        return policies_data_json["rpe_info"]["mrenclave"]

    def getRPEMRSigner(self):
        # Get rpe mrsigner from policies.json 
        logger.info("get rpe mrsigner from policies.json")
        policies_data_json = self.policies_data_json
        return policies_data_json["rpe_info"]["mrsigner"]

    def getRPEISVProdID(self):
        # Get rpe isvproid from policies.json 
        logger.info("get rpe isvproid from policies.json")
        policies_data_json = self.policies_data_json
        return policies_data_json["rpe_info"]["isv_prod_id"]

    def getRPEISVSVN(self):
        # Get rpe isvsvn from policies.json 
        logger.info("get rpe isvsvn from policies.json")
        policies_data_json = self.policies_data_json
        return policies_data_json["rpe_info"]["isv_svn"]

    def getRPEQEID(self, rpe_id):
        # Get rpe qeid from policies.json 
        logger.info("get rpe qeid from policies.json")
        rpe_qeid = None
        policies_data_json = self.policies_data_json
        for rpe_item in policies_data_json["rpe"]:
            if rpe_item["id"] == rpe_id:
                rpe_qeid = rpe_item["qeid_allowed"]
                break
        if rpe_qeid is None:
            logger.error("Cannot resolve qeid of managed_rpe")
            return None
        if not isinstance(rpe_qeid, list):
            logger.error("Format error in policies: Qeid of managed_rpe, reqired list()")
            return rpe_qeid
        return rpe_qeid

    def getTCBInfo(self, rpe_id):
        # Get rpe tcb info from policies.json 
        logger.info("get rpe tcb info from policies.json")
        tcb_ids = None
        tcb_infos = list()
        policies_data_json = self.policies_data_json
        
        # Find the tcb allowed of the rpe
        for rpe_item in policies_data_json["rpe"]:
            if rpe_item["id"] == rpe_id:
                tcb_ids = rpe_item["tcb_allowed"]
                break
        if tcb_ids is None:
            logger.error("Cannot resolve tcb_ids of managed_rpe")
            return None
        
        # Get tcb infos
        for tcb_id in tcb_ids:
            tcb_info = None
            for tcb_item in policies_data_json["tcb"]:
                if tcb_item["id"] == tcb_id:
                    tcb_info = tcb_item["data"]
                    break
            if tcb_info is None:
                logger.error("Cannot resolve data of managed_tcb: tcb_id %s" % tcb_id)
                return None
            tcb_infos.append(tcb_info)
        return tcb_infos
