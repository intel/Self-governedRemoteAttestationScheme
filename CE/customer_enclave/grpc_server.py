from concurrent import futures
import logging
import json
import asyncio
import time

import grpc
import ce_pb2
import ce_pb2_grpc

logger = logging.getLogger(__name__)

class CeService:
   
    def SendInfo(self, request, context):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        logger.info("Info: %s" % request.info)
        return ce_pb2.Response(status=0, content="")
    
    def QueryInfo(self, request, context):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        logger.info("Params: %s" % request.params)
        return ce_pb2.Response(status=0, content="")

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    ce_pb2_grpc.add_CeServiceServicer_to_server(CeService(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()
