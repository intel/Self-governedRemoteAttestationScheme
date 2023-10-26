import logging
import json
import time

from dist.other_pkgs.avalon_sdk.connector.blockchains.fabric.fabric_worker_registry import \
    FabricWorkerRegistryImpl
from dist.other_pkgs.avalon_sdk.worker.worker_details import WorkerType, WorkerStatus
from dist.other_pkgs.avalon_sdk.connector.blockchains.common.contract_response import \
        ContractResponse

logger = logging.getLogger(__name__)

class Connector:
    def __init__(self, conf):
        self.conf = conf

    def worker_lookup(self):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        result = worker_registry.worker_lookup(
                    worker_type=WorkerType.MPC)

        if len(result) != 3:
            logger.error("Unable to get worker IDs from Fabric block "
                         "chain.")
            return []

        return result[2]

    def get_workers_detail(self, worker_ids):
        workers = []
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        for worker_id in worker_ids:
            worker = self.get_worker_detail(worker_registry, worker_id)
            if worker is not None:
                workers.append(worker)

        return workers

    def get_all_workers(self):
        workers = []
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        result = worker_registry.worker_lookup(
                    worker_type=WorkerType.MPC)

        if len(result) != 3:
            logger.error("Unable to get worker IDs from Fabric block "
                         "chain.")
            return []

        worker_ids = result[2]

        workers = []
        for worker_id in worker_ids:
            worker = self.get_worker_detail(worker_registry, worker_id)
            if worker is not None:
                workers.append(worker)

        return workers

    def update_worker(self, worker):
        while True:
            try:
                #return self._update_worker(worker)
                ret = self._update_worker(worker)
                time.sleep(5)
                if ret == True:
                    worker_registry = FabricWorkerRegistryImpl(self.conf)
                    current_details = self.get_worker_detail(worker_registry,worker['worker_id'])
                    current_details = current_details['details']
                    logger.info("Worker_id: " + worker['worker_id'] + " details")
                    logger.info(current_details)
                    if current_details == worker['details']:
                        return True
            except Exception as e:
                logger.error("error when updating worker to Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)


    def _update_worker(self, worker):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        ret = worker_registry.worker_update(
                  worker['worker_id'],
                  json.dumps(worker['details']))
        return ret == ContractResponse.SUCCESS


    def remove_worker(self, worker_ids):
        while True:
            try:
                return self._remove_worker(worker_ids)
            except Exception as e:
                logger.error("error when removing worker from Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)


    def _remove_worker(self, worker_ids):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        for wid in worker_ids:
            ret = worker_registry.worker_set_status(
                      wid,
                      WorkerStatus.DECOMMISSIONED)
            if ret != ContractResponse.SUCCESS:
                return False

        return True


    def add_worker(self, worker):
        while True:
            try:
                return self._add_worker(worker)
            except Exception as e:
                logger.error("error when adding worker to Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)


    def _add_worker(self, worker):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        ret = worker_registry.worker_register(
                  worker['worker_id'],
                  WorkerType.MPC,
                  worker['organization_id'],
                  [worker['application_type_id']],
                  json.dumps(worker['details'])
            )

        return ret == ContractResponse.SUCCESS


    def get_worker_detail(self, worker_registry, worker_id):
        result = worker_registry.worker_retrieve(worker_id)

        if len(result) != 5:
            logger.error("Unable to get details of worker %s from "
                         "Fabric block chain." % worker_id)
            return None

        _, worker_type, org_id, app_type_id, details = result

        worker = {
            "worker_id": worker_id,
            "details": details
        }

        return worker


    def _set_worker_status(self,worker_id,status):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        ret = worker_registry.worker_set_status(
                      worker_id,
                      status)
        if ret != ContractResponse.SUCCESS:
            return False

        return True

    def set_worker_status(self,worker_id,status):
        while True:
            try:
                ret = self._set_worker_status(worker_id,status)
                time.sleep(5)
                if ret == True:
                    current_status = self._get_worker_status(worker_id)
                    if current_status == status.value:
                        return True
            except Exception as e:
                logger.error("error when setting worker status from Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)

    def _get_worker_status(self,worker_id):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        result = worker_registry\
                        .worker_retrieve(worker_id)
        if len(result) != 5:
            return None

        worker_status_onchain, _, _, _, _ = result
        return worker_status_onchain

    def get_worker_status(self,worker_id):
        while True:
            try:
                return self._get_worker_status(worker_id)
            except Exception as e:
                logger.error("error when getting worker status from Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)

    def generate_nonce(self, worker_id, nonce):
        while True:
            try:
                return self._generate_nonce(worker_id, nonce)
            except Exception as e:
                logger.error("error when generate nonce in Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)

    def _generate_nonce(self, worker_id, nonce):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        ret = worker_registry.generate_nonce(worker_id, nonce)
        return ret == ContractResponse.SUCCESS

    def get_nonce(self, worker_ids):
        while True:
            try:
                return self._get_nonce(worker_ids)
            except Exception as e:
                logger.error("error when get nonce from Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)

    def _get_nonce(self, worker_ids):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        return worker_registry.get_nonce(worker_ids)[0]

    def remove_nonce(self, worker_id):
        while True:
            try:
                return self._remove_nonce(worker_id)
            except Exception as e:
                logger.error("error when remove nonce in Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)

    def _remove_nonce(self, worker_id):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        ret = worker_registry.remove_nonce(worker_id)
        return ret == ContractResponse.SUCCESS

    def upload_quote(self, worker_id, quote):
        while True:
            try:
                return self._upload_quote(worker_id, quote)
            except Exception as e:
                logger.error("error when uploading quote to Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)

    def _upload_quote(self, worker_id, quote):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        ret = worker_registry.upload_quote(
                  worker_id,
                  str(quote)
            )
        return ret == ContractResponse.SUCCESS

    def get_quote(self, worker_id):
        while True:
            try:
                return self._get_quote(worker_id)
            except Exception as e:
                logger.error("error when get quote from Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)

    def _get_quote(self, worker_id):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        return worker_registry.get_quote(worker_id)[1]

    def upload_verify_result(self, worker_id, verify_results):
        while True:
            try:
                return self._upload_verify_result(worker_id, verify_results)
            except Exception as e:
                logger.error("error when uploading verify result to Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)

    def _upload_verify_result(self, worker_id, verify_results):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        ret = worker_registry.upload_verify_result(
                  worker_id,
                  verify_results
            )

        return ret == ContractResponse.SUCCESS

    def get_verify_final_result(self, worker_ids):
        while True:
            try:
                return self._get_verify_final_result(worker_ids)
            except Exception as e:
                logger.error("error when get verify final result from Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)

    def _get_verify_final_result(self, worker_ids):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        return worker_registry.get_verify_final_result(worker_ids)[0]

    def upload_graphenes(self, worker_id, graphenes):
        while True:
            try:
                return self._upload_graphenes(worker_id, graphenes)
            except Exception as e:
                logger.error("error when uploading graphenes to Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)

    def _upload_graphenes(self, worker_id, graphenes):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        ret = worker_registry.upload_graphenes(worker_id, graphenes)
        return ret == ContractResponse.SUCCESS

    def get_all_graphenes(self, worker_ids):
        while True:
            try:
                return self._get_all_graphenes(worker_ids)
            except Exception as e:
                logger.error("error when getting all graphenes from Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)

    def _get_all_graphenes(self, worker_ids):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        return worker_registry.get_all_graphenes(worker_ids)[0]

    def send_heartbeat(self, worker_id):
        while True:
            try:
                return self._send_heartbeat(worker_id)
            except Exception as e:
                logger.error("error when send heartbeat to Fabric "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)

    def _send_heartbeat(self, worker_id):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        ret = worker_registry.send_heartbeat(worker_id)
        return ret == ContractResponse.SUCCESS

    def check_heartbeat(self, worker_id, worker_ids):
        while True:
            try:
                return self._check_heartbeat(worker_id, worker_ids)
            except Exception as e:
                logger.error("error when check heartbeat "
                             "block chain. error message: %s. Retry "
                             "after 10 seconds." % e)
                time.sleep(10)

    def _check_heartbeat(self, worker_id, worker_ids):
        worker_registry = FabricWorkerRegistryImpl(self.conf)
        return worker_registry.check_heartbeat(worker_id, worker_ids)[0]