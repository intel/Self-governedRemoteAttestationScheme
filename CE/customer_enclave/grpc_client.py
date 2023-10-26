from __future__ import print_function

import grpc
import logging
import ce_pb2
import ce_pb2_grpc

logger = logging.getLogger(__name__)

def sendInfo(address, info):
    with grpc.insecure_channel(address) as channel:
        stub = ce_pb2_grpc.CeServiceStub(channel)
        response = stub.SendInfo(ce_pb2.Info(info=info))
        if response.status != 0:
            logger.error("Fail to send info: %s", response.content)
            return False
        return True

def queryInfo(address, params):
    with grpc.insecure_channel(address) as channel:
        stub = ce_pb2_grpc.CeServiceStub(channel)
        response = stub.QueryInfo(ce_pb2.Params(params=params))
        if response.status != 0:
            logger.error("Fail to query info: %s", response.content)
            return False, None
        return True, response.content