package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

// SmartContract manages component tokens across a generic automotive supply
// chain (Tier-2 -> Tier-1 -> OEM -> Dealer). Org MSP names below are
// deliberately generic (OrgXMSP) rather than a named manufacturer; map them
// to your real MSP identifiers at network-configuration time (see README).
type SmartContract struct {
	contractapi.Contract
}

// ComponentToken is the on-chain record for a single component or an
// assembled product.
//
// Two fields deserve special note because they were previously a source of
// confusion between "cryptographic proof" and "self-reported business data":
//
//   - SubmittingOrgMSP is the MSP ID of the client identity that actually
//     submitted this transaction. Fabric verifies this cryptographically via
//     the client's TLS/X.509 identity (ctx.GetClientIdentity()); it is
//     reliable client authorisation evidence.
//   - CoAttestingOrgs is a caller-supplied list of additional organisations
//     that are claimed to jointly attest this record (e.g. "Tier-1 and OEM
//     both agree this component passed QC"). It is NOT independently
//     verified by this chaincode and is NOT the same thing as Fabric's
//     channel-level endorsement policy, which is enforced by the ordering
//     and validation system before a transaction ever commits, entirely
//     outside this code's control. A caller could in principle list an org
//     that did not genuinely co-attest. Treat CoAttestingOrgs as a
//     business-level annotation, not a security control.
//
// Ledger registration (this struct existing at TokenID) also only proves
// that *some* authorised client wrote this record; it does not, by itself,
// prove that the physical component being scanned in the real world is the
// genuine article the record describes (see CounterfeitScan's doc comment).
type ComponentToken struct {
	DocType          string    `json:"docType"` // "component" or "product"
	TokenID          string    `json:"tokenId"`
	BatchID          string    `json:"batchId"`
	RecipeID         string    `json:"recipeId,omitempty"`
	Status           string    `json:"status"` // MANUFACTURED, QC_PASSED, SHIPPED, ASSEMBLED, DELIVERED, RECALLED, REPAIRED, REPLACED, RETIRED
	Owner            string    `json:"owner"`
	DataHash         string    `json:"dataHash,omitempty"` // SHA-256 hex digest of the off-chain test report
	SubmittingOrgMSP string    `json:"submittingOrgMspId"` // cryptographically verified by Fabric for this transaction
	CoAttestingOrgs  []string  `json:"coAttestingOrgs"`    // self-declared, not independently verified (see type doc comment)
	Timestamp        time.Time `json:"timestamp"`          // from ctx.GetStub().GetTxTimestamp(), not time.Now()
	Reason           string    `json:"reason,omitempty"`   // original recall reason, never overwritten
	ReasonHistory    []string  `json:"reasonHistory,omitempty"`
	Components       []string  `json:"components,omitempty"` // for assembled product tokens
	UsageAvgTempC    *float64  `json:"usageAvgTempC,omitempty"`
}

const (
	minCoAttestingOrgs  = 2
	oemOrgMSP           = "Org1MSP" // generic OEM org; map to your real MSP identifier at deployment (see README)
	regulatorOrgMSP     = "Org3MSP" // requires a third network organisation; see Limitations
	batchComponentIndex = "batch~component"
)

// recordCoAttestation returns the sorted, de-duplicated set of the caller's
// own MSP (cryptographically known) plus any additional orgs the caller
// declares. Sorting makes the resulting slice byte-identical across every
// endorsing peer, which matters: an earlier version of this chaincode built
// this list by iterating a Go map, and Go deliberately randomises map
// iteration order. Two peers executing the same proposal could therefore
// have produced different JSON for the same logical value, so their
// read-write sets would not match and the transaction would fail
// endorsement even though both peers computed the "same" result.
func recordCoAttestation(ctx contractapi.TransactionContextInterface, declaredOrgs []string) (callerMSP string, coAttestors []string, err error) {
	callerMSP, err = ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", nil, fmt.Errorf("failed to get caller MSP: %v", err)
	}
	set := map[string]bool{callerMSP: true}
	for _, o := range declaredOrgs {
		if o != "" {
			set[o] = true
		}
	}
	out := make([]string, 0, len(set))
	for o := range set {
		out = append(out, o)
	}
	sort.Strings(out)
	return callerMSP, out, nil
}

// txTimestamp returns the transaction's Fabric-assigned timestamp rather
// than the executing peer's local clock. time.Now() would read a different
// wall-clock value on every peer that (re-)executes this chaincode during
// endorsement, producing different bytes in the write set on each peer and
// causing endorsement to fail non-deterministically. GetTxTimestamp() is
// part of the proposal itself, so every peer that simulates the same
// transaction proposal computes the same value.
func txTimestamp(ctx contractapi.TransactionContextInterface) (time.Time, error) {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get tx timestamp: %v", err)
	}
	return time.Unix(ts.Seconds, int64(ts.Nanos)).UTC(), nil
}

// RegisterComponent mints a new component token at manufacture time.
//
//	CHECK:  GetState(componentID) == nil (reject if already registered)
//	CREATE TOKEN -> PutState -> maintain batch~component index -> EMIT ComponentRegistered
func (s *SmartContract) RegisterComponent(ctx contractapi.TransactionContextInterface,
	componentID string, batchID string, supplierID string, testReport string, coAttestingOrgsCSV string) error {

	if componentID == "" || batchID == "" {
		return fmt.Errorf("registerComponent rejected: componentID and batchID are required")
	}

	callerMSP, coAttestors, err := recordCoAttestation(ctx, splitCSV(coAttestingOrgsCSV))
	if err != nil {
		return err
	}
	if len(coAttestors) < minCoAttestingOrgs {
		return fmt.Errorf("registerComponent rejected: needs >=%d co-attesting orgs, got %d (%v)", minCoAttestingOrgs, len(coAttestors), coAttestors)
	}

	existing, err := ctx.GetStub().GetState(componentID)
	if err != nil {
		return fmt.Errorf("failed to read world state: %v", err)
	}
	if existing != nil {
		return fmt.Errorf("registerComponent rejected: component %s is already registered", componentID)
	}

	ts, err := txTimestamp(ctx)
	if err != nil {
		return err
	}
	token := ComponentToken{
		DocType:          "component",
		TokenID:          componentID,
		BatchID:          batchID,
		Status:           "MANUFACTURED",
		Owner:            supplierID,
		DataHash:         hashHex(testReport),
		SubmittingOrgMSP: callerMSP,
		CoAttestingOrgs:  coAttestors,
		Timestamp:        ts,
	}
	if err := s.putToken(ctx, &token, "ComponentRegistered"); err != nil {
		return err
	}
	return s.addToBatchIndex(ctx, batchID, componentID)
}

// RecordTest commits the off-chain QC test report's hash on-chain. Requires
// the component to currently be MANUFACTURED, so a component cannot be
// tested twice or tested before it exists.
func (s *SmartContract) RecordTest(ctx contractapi.TransactionContextInterface, componentID string, testReport string, coAttestingOrgsCSV string) error {
	token, err := s.mustGetToken(ctx, componentID)
	if err != nil {
		return err
	}
	if err := requireStatus(token, "MANUFACTURED"); err != nil {
		return err
	}
	callerMSP, coAttestors, err := recordCoAttestation(ctx, splitCSV(coAttestingOrgsCSV))
	if err != nil {
		return err
	}
	if len(coAttestors) < minCoAttestingOrgs {
		return fmt.Errorf("recordTest rejected: needs >=%d co-attesting orgs", minCoAttestingOrgs)
	}
	token.DataHash = hashHex(testReport)
	token.SubmittingOrgMSP = callerMSP
	token.CoAttestingOrgs = coAttestors
	token.Status = "QC_PASSED"
	return s.putToken(ctx, token, "TestRecorded")
}

// RecordShipment transfers custody to the next organisation in the chain.
// Requires the component to currently be QC_PASSED.
func (s *SmartContract) RecordShipment(ctx contractapi.TransactionContextInterface, componentID string, fromOwner string, toOrg string, coAttestingOrgsCSV string) error {
	token, err := s.mustGetToken(ctx, componentID)
	if err != nil {
		return err
	}
	if err := requireStatus(token, "QC_PASSED"); err != nil {
		return err
	}
	if err := requireOwner(token, fromOwner); err != nil {
		return err
	}
	callerMSP, coAttestors, err := recordCoAttestation(ctx, splitCSV(coAttestingOrgsCSV))
	if err != nil {
		return err
	}
	if len(coAttestors) < minCoAttestingOrgs {
		return fmt.Errorf("recordShipment rejected: needs >=%d co-attesting orgs", minCoAttestingOrgs)
	}
	token.Owner = toOrg
	token.SubmittingOrgMSP = callerMSP
	token.CoAttestingOrgs = coAttestors
	token.Status = "SHIPPED"
	return s.putToken(ctx, token, "ShipmentRecorded")
}

// RecordAssembly combines component tokens into a single product token (the
// "Token Recipe" pattern). Every listed component must currently be SHIPPED
// and not already used in another assembly; the product ID must not already
// exist. All components must additionally share the same batch, since a
// mixed-batch assembly would make batch-scoped recall ambiguous.
func (s *SmartContract) RecordAssembly(ctx contractapi.TransactionContextInterface, productID string, componentIDsCSV string, recipeID string, coAttestingOrgsCSV string) error {
	if productID == "" {
		return fmt.Errorf("recordAssembly rejected: productID is required")
	}
	existingProduct, err := ctx.GetStub().GetState(productID)
	if err != nil {
		return fmt.Errorf("failed to read world state: %v", err)
	}
	if existingProduct != nil {
		return fmt.Errorf("recordAssembly rejected: product %s is already registered", productID)
	}

	callerMSP, coAttestors, err := recordCoAttestation(ctx, splitCSV(coAttestingOrgsCSV))
	if err != nil {
		return err
	}
	if len(coAttestors) < minCoAttestingOrgs {
		return fmt.Errorf("recordAssembly rejected: needs >=%d co-attesting orgs", minCoAttestingOrgs)
	}

	componentIDs := splitCSV(componentIDsCSV)
	if len(componentIDs) == 0 {
		return fmt.Errorf("recordAssembly rejected: componentIDsCSV must list at least one component")
	}

	seen := map[string]bool{}
	tokens := make([]*ComponentToken, 0, len(componentIDs))
	var batchID string
	for i, cid := range componentIDs {
		if seen[cid] {
			return fmt.Errorf("recordAssembly rejected: component %s listed more than once", cid)
		}
		seen[cid] = true

		tok, err := s.mustGetToken(ctx, cid)
		if err != nil {
			return err
		}
		if err := requireStatus(tok, "SHIPPED"); err != nil {
			return fmt.Errorf("recordAssembly rejected for component %s: %v", cid, err)
		}
		if i == 0 {
			batchID = tok.BatchID
		} else if tok.BatchID != batchID {
			return fmt.Errorf("recordAssembly rejected: component %s is from batch %s, expected %s (mixed-batch assembly is not permitted)", cid, tok.BatchID, batchID)
		}
		tokens = append(tokens, tok)
	}

	// Only mutate world state after every precondition above has passed, so
	// a rejected assembly never leaves some components half-updated.
	for _, tok := range tokens {
		tok.Status = "ASSEMBLED"
		tok.Owner = productID
		if err := s.putToken(ctx, tok, ""); err != nil {
			return err
		}
	}

	ts, err := txTimestamp(ctx)
	if err != nil {
		return err
	}
	product := ComponentToken{
		DocType:          "product",
		TokenID:          productID,
		BatchID:          batchID,
		RecipeID:         recipeID,
		Status:           "ASSEMBLED",
		Owner:            oemOrgMSP,
		Components:       componentIDs,
		SubmittingOrgMSP: callerMSP,
		CoAttestingOrgs:  coAttestors,
		Timestamp:        ts,
	}
	if err := s.putToken(ctx, &product, "AssemblyRecorded"); err != nil {
		return err
	}
	return s.addToBatchIndex(ctx, batchID, productID)
}

// RecordDelivery sets the final owner to the dealer. Requires the product to
// currently be ASSEMBLED, and cascades the same ownership/status update to
// every component the product was built from, so a query on a component
// after delivery reflects reality instead of still showing it owned by the
// assembler.
func (s *SmartContract) RecordDelivery(ctx contractapi.TransactionContextInterface, productID string, dealerID string, coAttestingOrgsCSV string) error {
	token, err := s.mustGetToken(ctx, productID)
	if err != nil {
		return err
	}
	if err := requireStatus(token, "ASSEMBLED"); err != nil {
		return err
	}
	callerMSP, coAttestors, err := recordCoAttestation(ctx, splitCSV(coAttestingOrgsCSV))
	if err != nil {
		return err
	}
	if len(coAttestors) < minCoAttestingOrgs {
		return fmt.Errorf("recordDelivery rejected: needs >=%d co-attesting orgs", minCoAttestingOrgs)
	}

	// Preload every component token before mutating anything, so a missing
	// or inconsistent component aborts the whole transaction rather than
	// leaving the product delivered but its components stale.
	componentTokens := make([]*ComponentToken, 0, len(token.Components))
	for _, cid := range token.Components {
		ctok, err := s.mustGetToken(ctx, cid)
		if err != nil {
			return fmt.Errorf("recordDelivery rejected: component %s referenced by %s could not be read: %v", cid, productID, err)
		}
		componentTokens = append(componentTokens, ctok)
	}

	token.Owner = dealerID
	token.SubmittingOrgMSP = callerMSP
	token.CoAttestingOrgs = coAttestors
	token.Status = "DELIVERED"
	if err := s.putToken(ctx, token, "DeliveryRecorded"); err != nil {
		return err
	}
	for _, ctok := range componentTokens {
		ctok.Owner = dealerID
		ctok.Status = "DELIVERED"
		if err := s.putToken(ctx, ctok, ""); err != nil {
			return err
		}
	}
	return nil
}

// RecordUsageLog stores field telemetry used by the warranty-dispute
// scenario. Requires the component to have been delivered (there is no
// meaningful "usage" before a customer has the product).
func (s *SmartContract) RecordUsageLog(ctx contractapi.TransactionContextInterface, componentID string, avgTempC float64, coAttestingOrgsCSV string) error {
	token, err := s.mustGetToken(ctx, componentID)
	if err != nil {
		return err
	}
	if token.Status == "RECALLED" {
		return fmt.Errorf("recordUsageLog rejected: component %s is currently RECALLED", componentID)
	}
	callerMSP, coAttestors, err := recordCoAttestation(ctx, splitCSV(coAttestingOrgsCSV))
	if err != nil {
		return err
	}
	if len(coAttestors) < minCoAttestingOrgs {
		return fmt.Errorf("recordUsageLog rejected: needs >=%d co-attesting orgs", minCoAttestingOrgs)
	}
	token.UsageAvgTempC = &avgTempC
	token.SubmittingOrgMSP = callerMSP
	token.CoAttestingOrgs = coAttestors
	return s.putToken(ctx, token, "")
}

// WarrantyCheck applies a simple, illustrative threshold rule. Read-only.
// See the dissertation's discussion of parameter sensitivity: this rule's
// units, calibration tolerance and equality semantics are simplifications,
// not a validated engineering fault-analysis policy.
func (s *SmartContract) WarrantyCheck(ctx contractapi.TransactionContextInterface, componentID string, thresholdC float64) (string, error) {
	token, err := s.mustGetToken(ctx, componentID)
	if err != nil {
		return "", err
	}
	if token.UsageAvgTempC == nil {
		return "", fmt.Errorf("no usage log recorded for %s", componentID)
	}
	fault := "MANUFACTURER"
	result := "WARRANTY_HONORED"
	if *token.UsageAvgTempC > thresholdC {
		fault = "USER"
		result = "WARRANTY_VOID"
	}
	out, _ := json.Marshal(map[string]interface{}{
		"componentId": componentID,
		"avgTempC":    *token.UsageAvgTempC,
		"thresholdC":  thresholdC,
		"fault":       fault,
		"result":      result,
	})
	return string(out), nil
}

// CounterfeitScan checks whether a token exists and was registered with the
// required number of co-attesting organisations. Read-only.
//
// Important scope limitation, stated explicitly rather than only in prose
// elsewhere: this function verifies ledger presence and co-attestation
// count, not physical authenticity. A counterfeit manufacturer could copy a
// genuine componentID onto a fake part; scanning that copied ID would still
// return "registered" here, because this chaincode has no way to bind a
// digital record to the specific physical object in front of the scanner.
// The JSON field is named accordingly.
func (s *SmartContract) CounterfeitScan(ctx contractapi.TransactionContextInterface, componentID string) (string, error) {
	bytes, err := ctx.GetStub().GetState(componentID)
	if err != nil {
		return "", fmt.Errorf("failed to read world state: %v", err)
	}
	if bytes == nil {
		out, _ := json.Marshal(map[string]interface{}{
			"componentId":        componentID,
			"result":             "NOT_FOUND",
			"registeredOnLedger": false,
		})
		return string(out), nil
	}
	var token ComponentToken
	if err := json.Unmarshal(bytes, &token); err != nil {
		return "", err
	}
	sufficientlyAttested := len(token.CoAttestingOrgs) >= minCoAttestingOrgs
	result := "SUSPECT"
	if sufficientlyAttested {
		result = "REGISTERED_WITH_SUFFICIENT_ATTESTATION"
	}
	out, _ := json.Marshal(map[string]interface{}{
		"componentId":         componentID,
		"result":              result,
		"registeredOnLedger":  true,
		"coAttestingOrgs":     token.CoAttestingOrgs,
		"status":              token.Status,
		"note":                "confirms ledger registration and declared co-attestation only; does not by itself prove the physical item being scanned is the genuine, unaltered original",
	})
	return string(out), nil
}

// TriggerRecall marks every component/product in a batch as RECALLED and
// returns the de-duplicated set of current owners to notify.
//
// This uses a batch~component composite-key index maintained by
// addToBatchIndex, rather than a CouchDB rich query (GetQueryResult). A rich
// query is a problem here specifically because this transaction both reads
// via the query AND writes (PutState) inside the same transaction: Fabric's
// execute-order-validate model only guarantees that plain GetState/PutState
// keys are protected against phantom reads (a concurrent transaction adding
// a new matching document between this transaction's execution and its
// commit); a CouchDB selector query has no equivalent protection, so a
// component registered into the batch concurrently with this recall could
// be silently missed. A partial-composite-key range query over
// batch~component does not have this gap, because the composite keys
// themselves are ordinary ledger keys subject to normal MVCC read-set
// tracking.
func (s *SmartContract) TriggerRecall(ctx contractapi.TransactionContextInterface, batchID string, reason string) (string, error) {
	callerMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", err
	}
	if callerMSP != oemOrgMSP && callerMSP != regulatorOrgMSP {
		return "", fmt.Errorf("triggerRecall rejected: caller org must be OEM or Regulator, got %s", callerMSP)
	}

	componentIDs, err := s.batchIndexMembers(ctx, batchID)
	if err != nil {
		return "", err
	}
	if len(componentIDs) == 0 {
		return "", fmt.Errorf("triggerRecall rejected: no components found for batch %s", batchID)
	}

	affected := 0
	recalledIDs := make([]string, 0, len(componentIDs))
	ownerSet := map[string]bool{}
	for _, tokenID := range componentIDs {
		token, err := s.mustGetToken(ctx, tokenID)
		if err != nil {
			return "", err
		}
		if token.Status == "RECALLED" {
			continue
		}
		token.Status = "RECALLED"
		token.Reason = reason
		if err := s.putToken(ctx, token, ""); err != nil {
			return "", err
		}
		ownerSet[token.Owner] = true
		recalledIDs = append(recalledIDs, tokenID)
		affected++
	}

	owners := make([]string, 0, len(ownerSet))
	for o := range ownerSet {
		owners = append(owners, o)
	}
	sort.Strings(owners)
	sort.Strings(recalledIDs)

	txID := ctx.GetStub().GetTxID()
	// Exactly one SetEvent call for the whole transaction: Fabric only
	// carries a single chaincode event per transaction, so calling
	// SetEvent once per token inside the loop above (as an earlier version
	// of this chaincode did) would silently discard every event except the
	// last one written. Downstream systems (e.g. a dealer-notification
	// listener) should subscribe to this one aggregated event and fan out
	// per-dealer notifications off-chain from its payload.
	eventPayload, _ := json.Marshal(map[string]interface{}{
		"batchId":        batchID,
		"affectedCount":  affected,
		"recalledTokens": recalledIDs,
		"notifiedOwners": owners,
		"txId":           txID,
	})
	if err := ctx.GetStub().SetEvent("RecallAlert", eventPayload); err != nil {
		return "", err
	}

	out, _ := json.Marshal(map[string]interface{}{
		"batchId":         batchID,
		"affectedCount":   affected,
		"notifiedOwners":  owners,
		"txId":            txID,
	})
	return string(out), nil
}

// CloseRecall moves a single component from RECALLED to a terminal
// resolution state. The original recall Reason is left untouched; the
// resolution is appended to ReasonHistory so the full timeline stays on the
// ledger instead of being overwritten.
func (s *SmartContract) CloseRecall(ctx contractapi.TransactionContextInterface, componentID string, resolution string, note string, coAttestingOrgsCSV string) (string, error) {
	token, err := s.mustGetToken(ctx, componentID)
	if err != nil {
		return "", err
	}
	if err := requireStatus(token, "RECALLED"); err != nil {
		return "", err
	}
	callerMSP, coAttestors, err := recordCoAttestation(ctx, splitCSV(coAttestingOrgsCSV))
	if err != nil {
		return "", err
	}
	if len(coAttestors) < minCoAttestingOrgs {
		return "", fmt.Errorf("closeRecall rejected: needs >=%d co-attesting orgs", minCoAttestingOrgs)
	}
	if resolution != "REPAIRED" && resolution != "REPLACED" && resolution != "RETIRED" {
		return "", fmt.Errorf("resolution must be one of REPAIRED, REPLACED, RETIRED, got %s", resolution)
	}

	txID := ctx.GetStub().GetTxID()
	token.Status = resolution
	token.SubmittingOrgMSP = callerMSP
	token.CoAttestingOrgs = coAttestors
	token.ReasonHistory = append(token.ReasonHistory, fmt.Sprintf("CLOSED(%s): %s [tx:%s]", resolution, note, txID))
	if err := s.putToken(ctx, token, "RecallClosed"); err != nil {
		return "", err
	}
	out, _ := json.Marshal(map[string]interface{}{"componentId": componentID, "newStatus": resolution, "txId": txID})
	return string(out), nil
}

// ReviseRecallReason appends an amendment to every RECALLED token in a batch
// without overwriting the original reason text. OEM or Regulator only.
func (s *SmartContract) ReviseRecallReason(ctx contractapi.TransactionContextInterface, batchID string, amendedReason string) (string, error) {
	callerMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", err
	}
	if callerMSP != oemOrgMSP && callerMSP != regulatorOrgMSP {
		return "", fmt.Errorf("reviseRecallReason rejected: caller org must be OEM or Regulator, got %s", callerMSP)
	}

	componentIDs, err := s.batchIndexMembers(ctx, batchID)
	if err != nil {
		return "", err
	}
	txID := ctx.GetStub().GetTxID()
	amended := 0
	for _, tokenID := range componentIDs {
		token, err := s.mustGetToken(ctx, tokenID)
		if err != nil {
			return "", err
		}
		if token.Status != "RECALLED" {
			continue
		}
		token.ReasonHistory = append(token.ReasonHistory, fmt.Sprintf("AMENDED by %s: %s [tx:%s]", callerMSP, amendedReason, txID))
		if err := s.putToken(ctx, token, ""); err != nil {
			return "", err
		}
		amended++
	}
	if err := ctx.GetStub().SetEvent("RecallReasonAmended", []byte(fmt.Sprintf(`{"batchId":%q,"amendedCount":%d,"txId":%q}`, batchID, amended, txID))); err != nil {
		return "", err
	}
	out, _ := json.Marshal(map[string]interface{}{"batchId": batchID, "amendedCount": amended, "txId": txID})
	return string(out), nil
}

// RevokeRecall reverts every RECALLED token in a batch back to ACTIVE. This
// is deliberately restricted to RegulatorMSP only (not the OEM), so the OEM
// cannot unilaterally cancel its own recall. The fact that a recall happened
// and was later revoked stays visible via ReasonHistory and GetHistory().
func (s *SmartContract) RevokeRecall(ctx contractapi.TransactionContextInterface, batchID string, justification string) (string, error) {
	callerMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", err
	}
	if callerMSP != regulatorOrgMSP {
		return "", fmt.Errorf("revokeRecall rejected: caller org must be RegulatorMSP, got %s", callerMSP)
	}

	componentIDs, err := s.batchIndexMembers(ctx, batchID)
	if err != nil {
		return "", err
	}
	txID := ctx.GetStub().GetTxID()
	revoked := 0
	for _, tokenID := range componentIDs {
		token, err := s.mustGetToken(ctx, tokenID)
		if err != nil {
			return "", err
		}
		if token.Status != "RECALLED" {
			continue
		}
		token.Status = "ACTIVE"
		token.ReasonHistory = append(token.ReasonHistory, fmt.Sprintf("REVOKED by %s: %s [tx:%s]", callerMSP, justification, txID))
		if err := s.putToken(ctx, token, ""); err != nil {
			return "", err
		}
		revoked++
	}
	if err := ctx.GetStub().SetEvent("RecallRevoked", []byte(fmt.Sprintf(`{"batchId":%q,"revokedCount":%d,"txId":%q}`, batchID, revoked, txID))); err != nil {
		return "", err
	}
	out, _ := json.Marshal(map[string]interface{}{"batchId": batchID, "revokedCount": revoked, "txId": txID})
	return string(out), nil
}

// GetHistory returns the full on-chain version history of a token: every
// PutState that ever touched this key, tagged with its TxID and timestamp.
func (s *SmartContract) GetHistory(ctx contractapi.TransactionContextInterface, componentID string) (string, error) {
	iterator, err := ctx.GetStub().GetHistoryForKey(componentID)
	if err != nil {
		return "", fmt.Errorf("GetHistoryForKey failed: %v", err)
	}
	defer iterator.Close()

	type historyEntry struct {
		TxID      string          `json:"txId"`
		Timestamp string          `json:"timestamp"`
		IsDelete  bool            `json:"isDelete"`
		Value     json.RawMessage `json:"value,omitempty"`
	}
	var entries []historyEntry
	for iterator.HasNext() {
		mod, err := iterator.Next()
		if err != nil {
			return "", err
		}
		entries = append(entries, historyEntry{
			TxID:      mod.TxId,
			Timestamp: time.Unix(mod.Timestamp.Seconds, int64(mod.Timestamp.Nanos)).UTC().Format(time.RFC3339),
			IsDelete:  mod.IsDelete,
			Value:     mod.Value,
		})
	}
	out, err := json.Marshal(entries)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// GetComponent is a convenience read for the CLI/SDK.
func (s *SmartContract) GetComponent(ctx contractapi.TransactionContextInterface, componentID string) (string, error) {
	token, err := s.mustGetToken(ctx, componentID)
	if err != nil {
		return "", err
	}
	out, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// --- helpers ---

func requireStatus(token *ComponentToken, expected string) error {
	if token.Status != expected {
		return fmt.Errorf("invalid state transition: token %s has status %s, expected %s", token.TokenID, token.Status, expected)
	}
	return nil
}

func requireOwner(token *ComponentToken, expectedOwner string) error {
	if expectedOwner != "" && token.Owner != expectedOwner {
		return fmt.Errorf("invalid caller: token %s is owned by %s, not %s", token.TokenID, token.Owner, expectedOwner)
	}
	return nil
}

func (s *SmartContract) mustGetToken(ctx contractapi.TransactionContextInterface, id string) (*ComponentToken, error) {
	bytes, err := ctx.GetStub().GetState(id)
	if err != nil {
		return nil, fmt.Errorf("failed to read world state: %v", err)
	}
	if bytes == nil {
		return nil, fmt.Errorf("no token found for %s (GetState returned nil)", id)
	}
	var token ComponentToken
	if err := json.Unmarshal(bytes, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *SmartContract) putToken(ctx contractapi.TransactionContextInterface, token *ComponentToken, eventName string) error {
	bytes, err := json.Marshal(token)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(token.TokenID, bytes); err != nil {
		return err
	}
	if eventName != "" {
		return ctx.GetStub().SetEvent(eventName, bytes)
	}
	return nil
}

// addToBatchIndex records a batch~component composite key so that
// TriggerRecall (and the other batch-scoped functions) can enumerate a
// batch's members via a range query instead of a CouchDB rich query. The
// composite key's value is unused; its existence is the index entry.
func (s *SmartContract) addToBatchIndex(ctx contractapi.TransactionContextInterface, batchID string, tokenID string) error {
	key, err := ctx.GetStub().CreateCompositeKey(batchComponentIndex, []string{batchID, tokenID})
	if err != nil {
		return fmt.Errorf("failed to create batch index key: %v", err)
	}
	return ctx.GetStub().PutState(key, []byte{0})
}

// batchIndexMembers returns every token ID indexed under batchID, in sorted
// order, via GetStateByPartialCompositeKey rather than GetQueryResult.
func (s *SmartContract) batchIndexMembers(ctx contractapi.TransactionContextInterface, batchID string) ([]string, error) {
	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey(batchComponentIndex, []string{batchID})
	if err != nil {
		return nil, fmt.Errorf("failed to range-query batch index: %v", err)
	}
	defer iterator.Close()

	var members []string
	for iterator.HasNext() {
		kv, err := iterator.Next()
		if err != nil {
			return nil, err
		}
		_, parts, err := ctx.GetStub().SplitCompositeKey(kv.Key)
		if err != nil {
			return nil, err
		}
		if len(parts) == 2 {
			members = append(members, parts[1])
		}
	}
	sort.Strings(members)
	return members, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	return out
}

// hashHex computes the real SHA-256 hex digest of the off-chain test
// report. An earlier version of this function only prefixed the input
// string with the literal text "sha256:" without hashing it at all; that
// was a placeholder left over from initial scaffolding and did not provide
// any tamper-evidence. This is the actual implementation.
func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func main() {
	chaincode, err := contractapi.NewChaincode(&SmartContract{})
	if err != nil {
		panic(fmt.Sprintf("Error creating component-traceability chaincode: %v", err))
	}
	if err := chaincode.Start(); err != nil {
		panic(fmt.Sprintf("Error starting component-traceability chaincode: %v", err))
	}
}
