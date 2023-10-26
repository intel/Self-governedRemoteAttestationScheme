from hfc.fabric import client
import asyncio
import os
import time
cli = client.Client(net_profile="fixtures/network.json")
org1_admin = cli.get_user(org_name='org1.example.com', name='Admin') # get the admin user from local path
org2_admin = cli.get_user(org_name='org2.example.com', name='Admin')
orderer_admin = cli.get_user(org_name='orderer.example.com', name='Admin')
loop = asyncio.get_event_loop()
response = True
response = loop.run_until_complete(cli.channel_create(
            orderer='orderer.example.com',
            channel_name='mychannel',
            requestor=org1_admin,
            config_yaml='fixtures/network/',
            channel_profile='TwoOrgsChannel'
            ))
print("Create channel:",response)
if response == True:
    responses = loop.run_until_complete(cli.channel_join(
               requestor=org1_admin,
               channel_name='mychannel',
               peers=['peer0.org1.example.com',
                      'peer1.org1.example.com'],
               orderer='orderer.example.com'
               ))
    if len(responses) == 2:
        response = True
    else:
        response = False
    print("Join org1:",response)
if response == True:
    responses = loop.run_until_complete(cli.channel_join(
               requestor=org2_admin,
               channel_name='mychannel',
               peers=['peer0.org2.example.com',
                      'peer1.org2.example.com'],
               orderer='orderer.example.com'
               ))
    if len(responses) == 2:
        response = True
    else:
        response = False
    print("Join org2:",response)
'''config_tx_file = 'fixtures/network/configtx.yaml'
responses = loop.run_until_complete(cli.channel_update(
        orderer='orderer.example.com',
        channel_name='mychannel',
        requestor=orderer_admin,
        config_tx=config_tx_file))'''
if response == True:
    cli.new_channel('mychannel')
    gopath_bak = os.environ.get('GOPATH', '')
    gopath = os.path.normpath(os.path.join(
                      os.path.dirname(os.path.realpath('__file__')),
                      'fixtures/chaincode'
                     ))
    os.environ['GOPATH'] = os.path.abspath(gopath)
    responses = loop.run_until_complete(cli.chaincode_install(
               requestor=org1_admin,
               peers=['peer0.org1.example.com',
                      'peer1.org1.example.com'],
               cc_path='worker/go',
               cc_name='worker',
               cc_version='v1.0'
               ))
    if len(responses) == 2:
        response = True
    else:
        response = False
    print("Install chaincode on org1:%s" % response)

    responses = loop.run_until_complete(cli.chaincode_install(
               requestor=org2_admin,
               peers=['peer0.org2.example.com',
                      'peer1.org2.example.com'],
               cc_path='worker/go',
               cc_name='worker',
               cc_version='v1.0'
               ))
    if len(responses) == 2:
        response = True
    else:
        response = False
    print("Install chaincode on org2:%s" % response)
    
if response == True:
    args = []
    policy = {
    'identities': [
        {'role': {'name': 'member', 'mspId': 'Org1MSP'}},
    ],
    'policy': {
        '1-of': [
            {'signed-by': 0},
        ]
    }
}
    responses = loop.run_until_complete(cli.chaincode_instantiate(
               requestor=org1_admin,
               channel_name='mychannel',
               peers=['peer0.org1.example.com',
                      'peer0.org2.example.com'],
               args=args,
               cc_name='worker',
               cc_version='v1.0',
               cc_endorsement_policy=policy, # optional, but recommended
               collections_config=None, # optional, for private data policy
               transient_map=None, # optional, for private data
               wait_for_event=True # optional, for being sure chaincode is instantiated
               ))
    if 'name' in responses and 'version' in responses and 'policy' in responses and 'data' in responses and 'id' in responses:
        response = True
    else:
        response = False
    print("Instantiate chaincode in org1 and org2:%s" % response)


    policy = {
    'identities': [
        {'role': {'name': 'member', 'mspId': 'Org2MSP'}},
    ],
    'policy': {
        '1-of': [
            {'signed-by': 0},
        ]
    }
}
    # responses = loop.run_until_complete(cli.chaincode_instantiate(
    #            requestor=org2_admin,
    #            channel_name='mychannel',
    #            peers=['peer0.org2.example.com'],
    #            args=args,
    #            cc_name='worker',
    #            cc_version='v1.0',
    #            cc_endorsement_policy=None, # optional, but recommended
    #            collections_config=None, # optional, for private data policy
    #            transient_map=None, # optional, for private data
    #            wait_for_event=True # optional, for being sure chaincode is instantiated
    #            ))
    # if 'name' in responses and 'version' in responses and 'policy' in responses and 'data' in responses and 'id' in responses:
    #     response = True
    # else:
    #     response = False
    #     print(str(responses))
    # print("Instantiate chaincode in org2:%s" % response)

'''
if response == True:
    args = ['f3436f50b2f7f1613ad142dbce1d24801d9daaabc45ecb2db909251a214c9840']
    fcn='generateTimestamp'
    responses = loop.run_until_complete(cli.chaincode_invoke(
               requestor=org1_admin,
               channel_name='mychannel',
               peers=['peer0.org1.example.com'],
               fcn=fcn,
               args=args,
               cc_name='worker'
               ))
    print(responses)

time.sleep(5)

if response == True:
    args = ['f3436f50b2f7f1613ad142dbce1d24801d9daaabc45ecb2db909251a214c9840']
    fcn='getTimestamp'
    responses = loop.run_until_complete(cli.chaincode_invoke(
               requestor=org1_admin,
               channel_name='mychannel',
               peers=['peer0.org1.example.com'],
               fcn=fcn,
               args=args,
               cc_name='worker'
               ))
    print(responses)
'''
