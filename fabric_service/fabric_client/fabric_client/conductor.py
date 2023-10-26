import logging
from rpe_conn import grpc_server

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    grpc_server.serve()