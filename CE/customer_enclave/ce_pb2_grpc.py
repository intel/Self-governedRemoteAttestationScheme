# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc

import ce_pb2 as ce__pb2


class CeServiceStub(object):
    """====== CeService =======
    """

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.SendInfo = channel.unary_unary(
                '/ce.CeService/SendInfo',
                request_serializer=ce__pb2.Info.SerializeToString,
                response_deserializer=ce__pb2.Response.FromString,
                )
        self.QueryInfo = channel.unary_unary(
                '/ce.CeService/QueryInfo',
                request_serializer=ce__pb2.Params.SerializeToString,
                response_deserializer=ce__pb2.Response.FromString,
                )


class CeServiceServicer(object):
    """====== CeService =======
    """

    def SendInfo(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def QueryInfo(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_CeServiceServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'SendInfo': grpc.unary_unary_rpc_method_handler(
                    servicer.SendInfo,
                    request_deserializer=ce__pb2.Info.FromString,
                    response_serializer=ce__pb2.Response.SerializeToString,
            ),
            'QueryInfo': grpc.unary_unary_rpc_method_handler(
                    servicer.QueryInfo,
                    request_deserializer=ce__pb2.Params.FromString,
                    response_serializer=ce__pb2.Response.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'ce.CeService', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))


 # This class is part of an EXPERIMENTAL API.
class CeService(object):
    """====== CeService =======
    """

    @staticmethod
    def SendInfo(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/ce.CeService/SendInfo',
            ce__pb2.Info.SerializeToString,
            ce__pb2.Response.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)

    @staticmethod
    def QueryInfo(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(request, target, '/ce.CeService/QueryInfo',
            ce__pb2.Params.SerializeToString,
            ce__pb2.Response.FromString,
            options, channel_credentials,
            insecure, call_credentials, compression, wait_for_ready, timeout, metadata)