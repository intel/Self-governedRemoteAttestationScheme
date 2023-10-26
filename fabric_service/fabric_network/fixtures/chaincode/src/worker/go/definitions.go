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

// Worker related constants
const (
	WORKERACTIVE         = 1
	WORKEROFFLINE        = 2
	WORKERDECOMMISSIONED = 3
	WORKERCOMPROMISED    = 4

	OBJECTTYPE   = "WorkerRegister"
	PAGESIZE     = 10
	UINT64FORMAT = "%020d"
	BYTE32FORMAT = "%-32v"
)

// WorkerRegistry workerRegister object saved
type WorkerRegistry struct {
	WorkerID          string   `json:"workerID"`
	WorkerType        uint64   `json:"workerType"`
	OrganizationID    string   `json:"organizationID"`
	ApplicationTypeId []string `json:"applicationTypeId,omitempty"`
	Details           string   `json:"details"`
	Status            uint64   `json:"status,omitempty"`
}

// WorkerRetrieveResParam workerRetrieve response json object
type WorkerRetrieveResParam struct {
	Status            uint64   `json:"status,omitempty"`
	WorkerType        uint64   `json:"workerType"`
	OrganizationID    string   `json:"organizationID"`
	ApplicationTypeId []string `json:"applicationTypeId,omitempty"`
	Details           string   `json:"details"`
}

//WorkerLookUpResParam workLookup response json object
type WorkerLookUpResParam struct {
	TotalCount uint64   `json:"totalCount"`
	LookupTag  string   `json:"lookupTag"`
	IDs        []string `json:"ids"`
}

// WorkerVerifyResult workerVerifyResult json object
type WorkerVerifyResult struct {
	WorkerID     string            `json:"workerID"`
	VerifyResult map[string]string `json:"verifyresult"`
}

// WorkerVerifyFinalResult workerVerifyFinalResult json object
type WorkerVerifyFinalResult struct {
	WorkerID          string            `json:"workerID"`
	VerifyFinalResult map[string]string `json:"verifyFinalResult"`
}

// WorkerVerifyFinalResultResParam
type WorkerVerifyFinalResultsResParam struct {
	WorkerVerifyFinalResultsMap map[string]map[string]string `json:"workerVerifyFinalResultsMap"`
}

// WorkerNonceResParam workerNonceResult json object
type WorkerNonceResParam struct {
	Nonce string `json:"nonce"`
}

// WorkerQuote workerQuoteResParam json object
type WorkerQuoteResParam struct {
	WorkerID string `json:"wokerID"`
	Quote    string `json:"quote"`
}

// WorkerCheckHeartbeatResParam json object
type WorkerCheckHeartbeatResParam struct {
	CheckHeartbeatResult map[string]string `json:"checkHeartbeatResult"`
}

// WorkerAllGraphenes json object
type WorkerAllGraphenes struct {
	AllGraphenes map[string]string `json:"allGraphenes"`
}
