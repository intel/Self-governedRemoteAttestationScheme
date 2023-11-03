import logging
import sys

logger = logging.getLogger(__name__)

def read_file(filename):
    try:
        with open(filename, "r") as fd:
            data = fd.read()
            fd.close()
        return data
    except Exception as e:
        logger.error(
            "Load collateral from file failed!"
            " Error message %(%s)" % str(e) )
        return None
    
    
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')
    filename = "collateral.dat"
    # filename = "test.dat"
    collateral1 = read_file(filename)
    print(collateral1)
    input()
    collateral2 = read_file(filename)
    print(collateral2)
    if collateral1 == collateral2:
        logger.info("The same collateral")
    else:
        logger.info("Not the same")
        if len(collateral1) != len(collateral2):
            logger.info("length of the two collater is not the same")
            sys.exit(-1)
        for i in range(len(collateral1)):
            if collateral1[i] != collateral2[i]:
                print(collateral1, end='')