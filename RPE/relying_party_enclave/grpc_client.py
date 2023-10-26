from __future__ import print_function

import grpc
import logging
import rpe_pb2
import rpe_pb2_grpc

logger = logging.getLogger(__name__)

def sendRPEVerificationInfo(address, rpeVerificationInfo):
    if address is None:
        return False
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.SendRPEVerificationInfo(rpe_pb2.RPEVerificationInfo(rpeVerificationInfo=rpeVerificationInfo))
        if response.status != 0:
            logger.error("Fail to send rpe verification info: %s", response.content)
            return False
        return True

def queryRPEs(address, requiredRPENumber):
    if address is None:
        return False, None
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.QueryRPEs(rpe_pb2.RequiredRPENumber(requiredRPENumber=requiredRPENumber))
        if response.status != 0:
            logger.error("Fail to query rpes: %s", response.content)
            return False, None
        return True, response.content

def sendQuote(address, rpeId, base64EncodedQuote):
    if address is None:
        return False
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.SendQuote(rpe_pb2.RpeIdAndQuote(
            rpeId=rpeId,
            base64EncodedQuote=base64EncodedQuote))
        if response.status != 0:
            logger.error("Fail to send Quote: %s", response.content)
            return False
        return True
    
def queryQuote(address, rpeId):
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.QueryQuote(rpe_pb2.RpeId(rpeId=rpeId))
        if response.status != 0:
            logger.error("Fail to query Quote: %s", response.content)
            return False, None
        return True, response.content
    
def sendVerificationResult(address, rpeId, verificationResult):
    if address is None:
        return False
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.SendVerificationResult(rpe_pb2.VerificationResult(
            rpeId=rpeId,
            verificationResult=verificationResult))
        if response.status != 0:
            logger.error("Fail to send Verification result: %s", response.content)
            return False
        return True
    
def queryVerificationFinalResult(address, rpeIds):
    if address is None:
        return False, None
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.QueryVerificationFinalResult(rpe_pb2.RpeIds(rpeIds=rpeIds))
        if response.status != 0:
            logger.error("Fail to query verificationFinalResult: %s", response.content)
            return False, None
        return True, response.content
    
def sendCEInfo(address, jobId, ceInfo):
    if address is None:
        return False
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.SendCEInfo(rpe_pb2.CEInfo(
            jobId=jobId,
            ceInfo=ceInfo))
        if response.status != 0:
            logger.error("Fail to send CE info: %s", response.content)
            return False
        return True
    
def queryCEsInfo(address, jobIds):
    if address is None:
        return False, None
    with grpc.insecure_channel(address) as channel:
        stub = rpe_pb2_grpc.RpeServiceStub(channel)
        response = stub.QueryCEsInfo(rpe_pb2.JobIds(jobIds=jobIds))
        if response.status != 0:
            logger.error("Fail to query CEs' info: %s", response.content)
            return False, None
        return True, response.content