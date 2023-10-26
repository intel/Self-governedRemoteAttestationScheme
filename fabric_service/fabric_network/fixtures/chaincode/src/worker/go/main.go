/*
Copyright IBM Corp. 2020 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

//Off Chain Trusted Compute Service Work Registry Chaincode
import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

var logger = shim.NewLogger("WorkerRegistry")

// getWorkerByID - This function retrieve the worker register with its ID
// params:
//   byte32 workerID
func (t *WorkerRegistry) getWorkerByID(stub shim.ChaincodeStubInterface, workerID string) (*WorkerRegistry, error) {
	var param WorkerRegistry
	Avalbytes, err := stub.GetState(workerID)
	if err != nil {
		return nil, err
	}

	if Avalbytes == nil {
		return nil, errors.New("Worker with ID '" + workerID + "' does not exist")
	}

	err = json.Unmarshal(Avalbytes, &param)
	if err != nil {
		logger.Errorf("Error trying to decode the worker: %s", err)
		return nil, err
	}

	return &param, nil
}

// Init the init function of the chaincode
func (t *WorkerRegistry) Init(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Info("WorkerRegistry Init")
	return shim.Success(nil)
}

// workerRegister - This function registers a Worker
// params:
//   byte32 workerID
//   uint256 workerType
//   bytes32 organizationID
//   bytes32[] applicationTypeId
//   string details
// returns:
func (t *WorkerRegistry) workerRegister(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("workerRegister")
	if len(args) != 5 {
		logger.Errorf("Too many parameters, expect 5, received %d", len(args))
		return shim.Error("workerRegister must include 5 arguments, workerID, workerType, organizationID, applicationTypeId, and details")
	}

	var param WorkerRegistry
	param.WorkerID = args[0]
	arg1, err := strconv.ParseUint(args[1], 10, 64)
	if err != nil {
		logger.Errorf("Worker Type must be an integer")
		return shim.Error("Worker Type must be an integer")
	}
	param.WorkerType = arg1
	param.OrganizationID = args[2]
	param.ApplicationTypeId = strings.Split(args[3], ",")
	param.Details = args[4]
	param.Status = WORKERACTIVE

	//Serialize the value
	value, err := json.Marshal(param)
	if err != nil {
		return shim.Error(err.Error())
	}

	logger.Infof("The worker ID: %s", param.WorkerID)
	err = stub.PutState(param.WorkerID, value)
	if err != nil {
		return shim.Error(err.Error())
	}

	// Need to add compositeKey so that the search would work
	// The composite key is made of OBJECTTYPE, workerType, organizationID and appTypeID
	compValue := []byte(param.WorkerID)
	for _, appTypeID := range param.ApplicationTypeId {
		key1 := fmt.Sprintf(UINT64FORMAT, param.WorkerType)
		key2 := fmt.Sprintf(BYTE32FORMAT, param.OrganizationID)
		key3 := fmt.Sprintf(BYTE32FORMAT, appTypeID)
		key4 := fmt.Sprintf(BYTE32FORMAT, param.WorkerID)
		compKey, err := stub.CreateCompositeKey(OBJECTTYPE,
			[]string{key1, key2, key3, key4})
		if err != nil {
			return shim.Error(err.Error())
		}
		logger.Infof("The composite key: %s, length: %d", compKey, len(compKey))
		err = stub.PutState(compKey, compValue)
		if err != nil {
			return shim.Error(err.Error())
		}
	}

	// Handling payload for the event
	eventData := map[string]interface{}{"workerID": param.WorkerID}
	eventPayload, err := json.Marshal(eventData)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.SetEvent("workerRegistered", eventPayload)
	if err != nil {
		return shim.Error(err.Error())
	}

	logger.Info("Finished workerRegister")
	return shim.Success(nil)
}

// workerUpdate - This function sets the detail of a Worker
// params:
//   byte32 workerID
//   string detail
// returns:
func (t *WorkerRegistry) workerUpdate(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("workerSetStatus")
	logger.Infof("query workerID: %s", args[0])

	if len(args) != 2 {
		logger.Errorf("Expected parameters are 2, received %d", len(args))
		return shim.Error("workerUpdate must include 2 arguments, workerID and details")
	}

	wr, err := t.getWorkerByID(stub, args[0])
	if err != nil {
		return shim.Error(err.Error())
	}

	wr.Details = args[1]
	//Serialize the value
	value, err := json.Marshal(wr)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutState(wr.WorkerID, value)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(value)
}

// WorkerSetStatus - This function sets the status of a Worker
// params:
//   byte32 workerID
//   uint256 status
// returns:
func (t *WorkerRegistry) workerSetStatus(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("workerSetStatus")
	logger.Infof("query workerID: %s", args[0])

	if len(args) != 2 {
		logger.Errorf("Expected parameters are 2, received %d", len(args))
		return shim.Error("workerSetStatus must include 2 arguments, workID and status")
	}

	arg1, err := strconv.ParseUint(args[1], 10, 64)
	if err != nil {
		logger.Errorf("Worker status must be integer, received %v", args[1])
		return shim.Error(err.Error())
	}

	wr, err := t.getWorkerByID(stub, args[0])
	if err != nil {
		return shim.Error(err.Error())
	}

	wr.Status = arg1
	//Serialize the value
	value, err := json.Marshal(wr)
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutState(wr.WorkerID, value)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(value)
}

// WorkerLookUp - This function retrieves a list of Worker ids that match input
// parameter. The Worker must match to all input parameters (AND mode) to be
// included in the list.
// params:
//   uint8 workerType
//   bytes32 organizationId
//   bytes32 applicationTypeId
// returns:
//   int totalCount
//   string LookupTag
//   bytes32[] ids
func (t *WorkerRegistry) workerLookUp(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("workerLookUp")

	if len(args) != 3 {
		logger.Errorf("Expected parameters are 3, received %d", len(args))
		return shim.Error("workerLookUp must include 3 arguments, workType, organizationID and applicationTypeId")
	}

	args = append(args, "")
	return t.workerLookUpNext(stub, args)
}

// WorkerLookUpNext - This function is called to retrieve additional results of the
// Worker lookup initiated byworkerLookUp call.
// params:
//   uint8 workerType
//   bytes32 organizationId
//   bytes32 applicationTypeId
//   string lookUpTag
// returns:
//   int totalCount
//   string newLookupTag
//   bytes32[] ids
func (t *WorkerRegistry) workerLookUpNext(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("workerLookUpNext")

	if len(args) != 4 {
		logger.Errorf("Expected parameters are 4, received %d", len(args))
		return shim.Error("workerLookUpNext must include 4 arguments, workerType, organizationID, applicationTypeId and lookupTag")
	}

	attrs, err := processAttributes(args[0:3], []string{UINT64FORMAT, BYTE32FORMAT, BYTE32FORMAT})
	if err != nil {
		return shim.Error(err.Error())
	}
	logger.Infof("The lookup key: %v", attrs)

	iter, metadata, err := stub.GetStateByPartialCompositeKeyWithPagination(OBJECTTYPE, attrs,
		int32(PAGESIZE+1), args[3])
	if err != nil {
		logger.Errorf("Error trying to query with partial composite key: %s", err)
		return shim.Error(err.Error())
	}

	var resparam WorkerLookUpResParam
	resparam.IDs = []string{}
	for iter.HasNext() {
		item, _ := iter.Next()
		logger.Infof("The value: %v", item)
		resparam.IDs = append(resparam.IDs, string(item.Value))
		if len(resparam.IDs) == PAGESIZE {
			break
		}
	}
	logger.Info("Result metadata: %v", metadata)
	resparam.LookupTag = metadata.GetBookmark()
	resparam.TotalCount = uint64(len(resparam.IDs))

	//Serialize the response
	value, err := json.Marshal(resparam)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(value)
}

// WorkerRetrieve - This function retrieves information for the Worker and it can be
// called from any authorized publickey (Ethereum address) or DID
// params:
//   byte32 workerId
// returns:
//   uint256 status
//   uint8 workerType
//   bytes32 organizationId
//   bytes32[] applicationTypeId
//   string details
func (t *WorkerRegistry) workerRetrieve(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("workerRetrieve")
	if len(args) != 1 {
		logger.Errorf("Expected parameter is 1, received %d", len(args))
		return shim.Error("workerRetrieve must include 1 argument, workerID")
	}

	logger.Infof("worker retrieve workerID: %s", args[0])

	wr, err := t.getWorkerByID(stub, args[0])
	if err != nil {
		return shim.Error(err.Error())
	}

	var resparam WorkerRetrieveResParam
	resparam.Status = wr.Status
	resparam.WorkerType = wr.WorkerType
	resparam.OrganizationID = wr.OrganizationID
	resparam.ApplicationTypeId = wr.ApplicationTypeId
	resparam.Details = wr.Details

	//Serialize the response
	value, err := json.Marshal(resparam)
	if err != nil {
		return shim.Error(err.Error())
	}

	//logger.Info("value: \n" + string(value))

	return shim.Success(value)
}

// query - This function retrieves information by worker id
// params:
//   byte32 workerId
// returns:
//   uint8 workerType
//   string workerTypeDataUri
//   bytes32 organizationId
//   bytes32[] applicationTypeId
func (t *WorkerRegistry) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("query")

	// Get the state from the ledger
	logger.Infof("query workerID: %s", args[0])
	Avalbytes, err := stub.GetState(args[0])
	if err != nil {
		return shim.Error(err.Error())
	}

	if Avalbytes == nil {
		return shim.Error("WorkerID '" + args[0] + "' does not exist")
	}

	return shim.Success(Avalbytes)
}

// Invoke - this function simply satisfies the main requirement of chaincode
func (t *WorkerRegistry) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	logger.Info("Invoke")
	function, args := stub.GetFunctionAndParameters()
	if function == "workerRegister" {
		return t.workerRegister(stub, args)
	} else if function == "workerUpdate" {
		return t.workerUpdate(stub, args)
	} else if function == "workerSetStatus" {
		return t.workerSetStatus(stub, args)
	} else if function == "workerLookUp" {
		return t.workerLookUp(stub, args)
	} else if function == "workerLookUpNext" {
		return t.workerLookUpNext(stub, args)
	} else if function == "workerRetrieve" {
		return t.workerRetrieve(stub, args)
	} else if function == "query" {
		return t.query(stub, args)
	} else if function == "generateNonce" {
		return t.generateNonce(stub, args)
	} else if function == "getNonce" {
		return t.getNonce(stub, args)
	} else if function == "removeNonce" {
		return t.removeNonce(stub, args)
	} else if function == "uploadQuote" {
		return t.uploadQuote(stub, args)
	} else if function == "getQuote" {
		return t.getQuote(stub, args)
	} else if function == "uploadVerifyResult" {
		return t.uploadVerifyResult(stub, args)
	} else if function == "getVerifyFinalResult" {
		return t.getVerifyFinalResult(stub, args)
	} else if function == "uploadGraphenes" {
		return t.uploadGraphenes(stub, args)
	} else if function == "getAllGraphenes" {
		return t.getAllGraphenes(stub, args)
	} else if function == "sendHeartbeat" {
		return t.sendHeartbeat(stub, args)
	} else if function == "checkHeartbeat" {
		return t.checkHeartbeat(stub, args)
	}

	return shim.Error("Invalid invoke function name: " + function)
}

// processAttributes - This function formalizes the input attributes. It
// will transform the variable length of a parameter value into a fixed
// length string value
// params:
//   []string arg1, the value of attributes
//   []string arg2, the type of the values to be formatted to. For example, if
//            this value is UINT64FORMAT, then the value will be left padded 0.
//            if this value is BYTE32FORMAT, then the value will be right padded
//            spaces
// returns:
//   []string the fixed length
func processAttributes(arg1 []string, arg2 []string) ([]string, error) {
	var attrs []string
	for i, argType := range arg2 {
		switch argType {
		case UINT64FORMAT:
			// If search argument workerType is 0 then ignore parameter
			arg, err := strconv.ParseUint(arg1[i], 10, 64)
			if err != nil {
				return nil, err
			}
			if arg != 0 {
				attrs = append(attrs, fmt.Sprintf(UINT64FORMAT, arg))
			}
		case BYTE32FORMAT:
			// If search arguments orgId and appId are empty then ignore parameter
			arg := fmt.Sprintf("%v", arg1[i])
			if len(arg) > 0 {
				attrs = append(attrs, fmt.Sprintf(BYTE32FORMAT, arg1[i]))
			}
		}
	}
	return attrs, nil
}

// getNonce - This function xxx
//
func getNonce(stub shim.ChaincodeStubInterface, workerIDs_string string) (string, error) {
	logger.Infof("Wokerids: %s", workerIDs_string)
	workerIDs := strings.Split(workerIDs_string, ",")

	nonce_array := []string{}

	for _, workerID := range workerIDs {
		nonceBytes, err := stub.GetState("NONCE_" + workerID)
		if err != nil {
			return "", err
		}
		if nonceBytes == nil {
			return "", errors.New("Nonce for worker " + workerID +
				" has not been generated or has been removed")
		}
		var nonce string
		err = json.Unmarshal(nonceBytes, &nonce)
		if err != nil {
			return "", err
		}
		nonce_array = append(nonce_array, nonce)
		logger.Infof("Nonce for worker %s is %s", workerID, nonce)
	}

	sort.Sort(sort.StringSlice(nonce_array))

	var nonce_result string
	for _, nonce := range nonce_array {
		nonce_result += nonce
	}

	return nonce_result, nil
}

// getNonce - This function xxx
//
// func (t *WorkerRegistry) getNonce(stub shim.ChaincodeStubInterface) pb.Response {
// 	logger.Info("getNonce")
// 	args := [][]byte{[]byte("GetChainInfo"), []byte(stub.GetChannelID())}
// 	response := stub.InvokeChaincode("qscc", args, stub.GetChannelID())
// 	if response.GetStatus() == 200 {
// 		nonce := stub.GetTxTimestamp().String()
// 		return shim.Success([]byte(nonce))
// 	}

// 	return shim.Error(response.GetMessage())
// }

// generateNonce - This function xxx
//
func (t *WorkerRegistry) generateNonce(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("generateNonce")

	if len(args) != 2 {
		logger.Errorf("Expected parameter is 2, received %d", len(args))
		return shim.Error("generateNonce must include 2 argument, workerID, nonce")
	}

	// Store the nonce
	nonceBytes, err := json.Marshal(args[1])
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState("NONCE_"+args[0], nonceBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// getNonce - This function xxx
//
func (t *WorkerRegistry) getNonce(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("getNonce")

	if len(args) != 1 {
		logger.Errorf("Expected parameter is 1, received %d", len(args))
		return shim.Error("getNonce must include 1 argument, workerIDs")
	}

	nonce, err := getNonce(stub, args[0])
	if err != nil {
		return shim.Error(err.Error())
	}

	var workerNonceResParam WorkerNonceResParam
	workerNonceResParam.Nonce = nonce

	// Marshal the result
	workerNonceResParamBytes, err := json.Marshal(workerNonceResParam)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(workerNonceResParamBytes)
}

// removeNonce - This function xxx
//
func (t *WorkerRegistry) removeNonce(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("removeNonce")

	if len(args) != 1 {
		logger.Errorf("Expected parameter is 1, received %d", len(args))
		return shim.Error("removeNonce must include 1 argument, workerID")
	}

	err := stub.DelState("NONCE_" + args[0])
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

func (t *WorkerRegistry) uploadQuote(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("uploadQuote")
	if len(args) != 2 {
		logger.Errorf("Expected parameter is 2, received %d", len(args))
		return shim.Error("uploadQuote must include 2 argument, workerID, workerAvr")
	}

	// Get nonce
	// nonce, err := getNonce(stub, args[1])
	// if err != nil {
	// 	return shim.Error(err.Error())
	// }

	// Put quote to ledger
	quoteBytes, err := json.Marshal(args[1])
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState("QUOTE_"+args[0], quoteBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// getQuote - This function xxx
//
func (t *WorkerRegistry) getQuote(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("getQuote")
	if len(args) != 1 {
		logger.Errorf("Expected parameter is 1, received %d", len(args))
		return shim.Error("getQuote must include 1 argument, workerID")
	}

	// Get nonce
	// nonce, err := getNonce(stub, args[1])
	// if err != nil {
	// 	return shim.Error(err.Error())
	// }

	// Get quote for the worker
	quoteBytes, err := stub.GetState("QUOTE_" + args[0])
	if err != nil {
		return shim.Error(err.Error())
	}
	var quote string
	err = json.Unmarshal(quoteBytes, &quote)
	if err != nil {
		return shim.Error(err.Error())
	}
	var workerQuoteResParam WorkerQuoteResParam
	workerQuoteResParam.WorkerID = args[0]
	workerQuoteResParam.Quote = quote
	workerQuoteResParamBytes, err := json.Marshal(workerQuoteResParam)
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(workerQuoteResParamBytes)
}

// uploadVeriyfyResult - This function xxx
//
func (t *WorkerRegistry) uploadVerifyResult(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("uploadVerifyResult")
	if len(args) != 2 {
		logger.Errorf("Expected parameter is 2, received %d", len(args))
		return shim.Error("uploadVerifyResult must include 2 argument, workerID, verifyResult")
	}

	// Parse the verify result
	verify_result := strings.Replace(args[1], "'", "\"", -1)
	verifyResult := make(map[string]string)
	err := json.Unmarshal([]byte(verify_result), &verifyResult)
	if err != nil {
		logger.Error("Error when convert verifyResult json to map: " + err.Error())
		return shim.Error(err.Error())
	}

	var workerVerifyResult WorkerVerifyResult
	workerVerifyResult.WorkerID = args[0]
	workerVerifyResult.VerifyResult = verifyResult
	value, err := json.Marshal(workerVerifyResult)
	if err != nil {
		return shim.Error(err.Error())
	}

	// Get nonce
	// nonce, err := getNonce(stub, args[1])
	// if err != nil {
	// 	return shim.Error(err.Error())
	// }

	// add verify result to ledger
	err = stub.PutState("VERIFY_RESULT_"+workerVerifyResult.WorkerID, value)
	if err != nil {
		return shim.Error(err.Error())
	}

	logger.Info("Added verify result: WorkerID " + workerVerifyResult.WorkerID)

	return shim.Success(nil)
}

// getVerifyFinalResult - This function xxx
//
func (t *WorkerRegistry) getVerifyFinalResult(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("getVerifyFinalResult")
	if len(args) != 1 {
		logger.Errorf("Expected parameter is 1, received %d", len(args))
		return shim.Error("getVerifyFinalResult must include 1 argument, workerIDs")
	}

	// Get the workerIDs from param
	workerIDs := strings.Split(args[0], ",")

	// Initialize the final results data structure
	workerVerifyFinalResultsMap := make(map[string]map[string]string)
	for _, workerID := range workerIDs {
		verifyFinalResultsMap := make(map[string]string)
		workerVerifyFinalResultsMap[workerID] = verifyFinalResultsMap
	}

	// Get nonce
	// nonce, err := getNonce(stub, args[0])
	// if err != nil {
	// 	return shim.Error(err.Error())
	// }

	// If the verify final result is generated, it can be find directely
	workerVerifyFinalResultBytes, err := stub.GetState("VERIFY_FINAL_RESULT_" + workerIDs[0])
	if err != nil {
		return shim.Error(err.Error())
	}
	if workerVerifyFinalResultBytes != nil {
		for _, workerID := range workerIDs {
			workerVerifyFinalResultBytes, err = stub.GetState("VERIFY_FINAL_RESULT_" + workerID)
			if err != nil {
				return shim.Error(err.Error())
			}
			var workerVerifyFinalResult WorkerVerifyFinalResult
			err = json.Unmarshal(workerVerifyFinalResultBytes, &workerVerifyFinalResult)
			if err != nil {
				return shim.Error(err.Error())
			}
			workerVerifyFinalResultsMap[workerID] = workerVerifyFinalResult.VerifyFinalResult
		}

	} else {
		// If not, get the verify result
		for _, workerID := range workerIDs {
			workerVerifyResultBytes, err := stub.GetState("VERIFY_RESULT_" + workerID)
			if err != nil {
				return shim.Error(err.Error())
			}
			if workerVerifyResultBytes == nil {
				return shim.Error("Worker " + workerID + " has not uploaded its verify result")
			}
			var workerVerifyResult WorkerVerifyResult
			err = json.Unmarshal(workerVerifyResultBytes, &workerVerifyResult)
			if err != nil {
				return shim.Error(err.Error())
			}

			workerVerifyFinalResultsMap[workerID] = workerVerifyResult.VerifyResult
			// for key, value := range workerVerifyResult.VerifyResult {
			// 	workerVerifyFinalResultsMap[key][workerID] = value
			// }
		}

		// write the verify final result to ledger
		// for _, workerID := range workerIDs {
		// 	var workerVerifyFinalResult WorkerVerifyFinalResult
		// 	workerVerifyFinalResult.WorkerID = workerID
		// 	workerVerifyFinalResult.VerifyFinalResult = workerVerifyFinalResultsMap[workerID]
		// 	workerVerifyFinalResultBytes, err := json.Marshal(workerVerifyFinalResult)
		// 	if err != nil {
		// 		return shim.Error(err.Error())
		// 	}
		// 	err = stub.PutState("VERIFY_FINAL_RESULT_"+workerID, workerVerifyFinalResultBytes)
		// 	if err != nil {
		// 		return shim.Error(err.Error())
		// 	}
		// }
	}

	// return the final result to client
	var workerVerifyFinalResultsResParam WorkerVerifyFinalResultsResParam
	workerVerifyFinalResultsResParam.WorkerVerifyFinalResultsMap = workerVerifyFinalResultsMap
	workerVerifyFinalResultsResParamBytes, err := json.Marshal(workerVerifyFinalResultsResParam)
	if err != nil {
		return shim.Error(err.Error())
	}

	logger.Info("verifyFinalResult: " + string(workerVerifyFinalResultsResParamBytes))

	return shim.Success(workerVerifyFinalResultsResParamBytes)
}

// uploadGraphenes - This function xxx
//
func (t *WorkerRegistry) uploadGraphenes(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("uploadGraphenes")
	if len(args) != 2 {
		logger.Errorf("Expected parameter is 2, received %d", len(args))
		return shim.Error("uploadGraphenes must include 2 argument, workerID, graphenes")
	}
	graphenesBytes, err := json.Marshal(args[1])
	if err != nil {
		return shim.Error(err.Error())
	}

	err = stub.PutState("GRAPHENES_"+args[0], graphenesBytes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(nil)
}

// getAllGraphenes - This function xxx
//
func (t *WorkerRegistry) getAllGraphenes(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("getAllGraphenes")
	if len(args) != 1 {
		logger.Errorf("Expected parameter is 1, received %d", len(args))
		return shim.Error("uploadGraphenes must include 1 argument, workerIDs")
	}

	// Get the workerIDs from param
	workerIDs := strings.Split(args[0], ",")

	// Get graphenes
	allGraphenes := make(map[string]string)
	for _, workerID := range workerIDs {
		graphenesBytes, err := stub.GetState("GRAPHENES_" + workerID)
		if err != nil {
			return shim.Error(err.Error())
		}
		if graphenesBytes == nil {
			return shim.Error("The graphenes of worker " + workerID + " has not been uploaded")
		}
		var graphenes string
		err = json.Unmarshal(graphenesBytes, &graphenes)
		if err != nil {
			return shim.Error(err.Error())
		}
		allGraphenes[workerID] = graphenes
	}

	var workerAllGraphenes WorkerAllGraphenes
	workerAllGraphenes.AllGraphenes = allGraphenes
	workerAllGraphenesBytes, err := json.Marshal(workerAllGraphenes)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(workerAllGraphenesBytes)
}

// sendHeartbeat - This function xxx
//
func (t *WorkerRegistry) sendHeartbeat(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("sendHeartbeat")
	if len(args) != 1 {
		logger.Errorf("Expected parameter is 1, received %d", len(args))
		return shim.Error("sendHeartbeat must include 1 argument, workerID")
	}
	heartbeatCountBytes, err := stub.GetState("HEARTBEAT_" + args[0])
	if err != nil {
		return shim.Error(err.Error())
	}
	// if there is not heatbeatCount in ledger, put 0 into ledger; else, add 1 on the exists
	var heartbeatCount int
	if heartbeatCountBytes != nil {
		err = json.Unmarshal(heartbeatCountBytes, &heartbeatCount)
		if err != nil {
			return shim.Error(err.Error())
		}
		heartbeatCount += 1
	} else {
		heartbeatCount = 0
	}
	heartbeatCountBytes, err = json.Marshal(heartbeatCount)
	if err != nil {
		return shim.Error(err.Error())
	}
	err = stub.PutState("HEARTBEAT_"+args[0], heartbeatCountBytes)
	if err != nil {
		return shim.Error(err.Error())
	}
	return shim.Success(nil)
}

// checkHeartbeat - This function xxx
//
func (t *WorkerRegistry) checkHeartbeat(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	logger.Info("checkHeartbeat")
	if len(args) != 2 {
		logger.Errorf("Expected parameter is 2, received %d", len(args))
		return shim.Error("checkHeartbeat must include 2 argument, workerID, workerIDs")
	}

	// Get the workerIDs from param
	workerIDs := strings.Split(args[1], ",")

	// Get its own heartbeat count
	heartbeatCountBytes, err := stub.GetState("HEARTBEAT_" + args[0])
	if err != nil {
		return shim.Error(err.Error())
	}
	if heartbeatCountBytes == nil {
		return shim.Error("The heartbeat of its own has not sent to fabric")
	}
	var selfHeartbeatCount int
	err = json.Unmarshal(heartbeatCountBytes, &selfHeartbeatCount)
	if err != nil {
		return shim.Error(err.Error())
	}

	var heartbeatCount int
	checkHeartbeatResult := make(map[string]string)
	// Get other heartbeat count and check if the deviation between itself and whom is more than 3
	for _, worker_id := range workerIDs {
		// Get its own heartbeat count
		heartbeatCountBytes, err = stub.GetState("HEARTBEAT_" + worker_id)
		if err != nil {
			return shim.Error(err.Error())
		}
		if heartbeatCountBytes != nil {
			err = json.Unmarshal(heartbeatCountBytes, &heartbeatCount)
			if err != nil {
				return shim.Error(err.Error())
			}
		} else {
			heartbeatCount = 0
		}

		// Compare the heartbeat from worker and itself
		if selfHeartbeatCount-heartbeatCount > 3 {
			checkHeartbeatResult[worker_id] = "false"
		} else {
			checkHeartbeatResult[worker_id] = "true"
		}
	}

	// Pack the check result of heartbeat
	var workerCheckHeartbeatResParam WorkerCheckHeartbeatResParam
	workerCheckHeartbeatResParam.CheckHeartbeatResult = checkHeartbeatResult
	checkHeartbeatResParamBytes, err := json.Marshal(workerCheckHeartbeatResParam)
	if err != nil {
		return shim.Error(err.Error())
	}

	return shim.Success(checkHeartbeatResParamBytes)
}

func main() {
	err := shim.Start(new(WorkerRegistry))
	if err != nil {
		logger.Errorf("Error starting WorkerRegistry chaincode: %s", err)
	}
}
