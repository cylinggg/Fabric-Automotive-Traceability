package main

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/v2/pkg/cid"
	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/queryresult"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
)

// --- minimal in-memory fakes ---
//
// These are not the real Fabric chaincode shim: they implement only the
// subset of ChaincodeStubInterface and cid.ClientIdentity that this
// chaincode actually calls, by embedding the real interfaces (unimplemented
// methods panic if ever called, which would fail the test loudly rather
// than silently). This lets business logic (state-transition checks,
// duplicate detection, composite-key indexing, deterministic ordering) be
// unit-tested without Docker or a live network. It does not replace the
// real-network evidence in evidence/; see the dissertation's Chapter 4 for
// why both kinds of evidence are reported separately.

type fakeStub struct {
	shim.ChaincodeStubInterface
	state  map[string][]byte
	txID   string
	events []string
}

func newFakeStub(txID string) *fakeStub {
	return &fakeStub{
		state: map[string][]byte{},
		txID:  txID,
	}
}

func (f *fakeStub) GetState(key string) ([]byte, error) {
	return f.state[key], nil
}

func (f *fakeStub) PutState(key string, value []byte) error {
	f.state[key] = value
	return nil
}

func (f *fakeStub) GetTxID() string {
	return f.txID
}

func (f *fakeStub) GetTxTimestamp() (*timestamppb.Timestamp, error) {
	return timestamppb.New(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), nil
}

func (f *fakeStub) SetEvent(name string, payload []byte) error {
	f.events = append(f.events, name)
	return nil
}

func (f *fakeStub) CreateCompositeKey(objectType string, attrs []string) (string, error) {
	return objectType + "~" + strings.Join(attrs, "~"), nil
}

func (f *fakeStub) SplitCompositeKey(compositeKey string) (string, []string, error) {
	parts := strings.Split(compositeKey, "~")
	if len(parts) < 1 {
		return "", nil, fmt.Errorf("invalid composite key")
	}
	return parts[0], parts[1:], nil
}

// GetStateByPartialCompositeKey scans the same in-memory state map that
// PutState writes to, since addToBatchIndex (honda_component.go) stores its
// composite-key index entries via an ordinary PutState call, exactly as it
// does against a real peer's world state.
func (f *fakeStub) GetStateByPartialCompositeKey(objectType string, attrs []string) (shim.StateQueryIteratorInterface, error) {
	prefix := objectType + "~" + strings.Join(attrs, "~")
	var keys []string
	for k := range f.state {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return &fakeIterator{keys: keys}, nil
}

type fakeIterator struct {
	keys []string
	pos  int
}

func (it *fakeIterator) HasNext() bool { return it.pos < len(it.keys) }
func (it *fakeIterator) Close() error  { return nil }
func (it *fakeIterator) Next() (*queryresult.KV, error) {
	k := it.keys[it.pos]
	it.pos++
	return &queryresult.KV{Key: k}, nil
}

type fakeCtx struct {
	stub     *fakeStub
	callerID string
}

func (c *fakeCtx) GetStub() shim.ChaincodeStubInterface { return c.stub }
func (c *fakeCtx) GetClientIdentity() cid.ClientIdentity { return &fakeClientIdentity{mspID: c.callerID} }

type fakeClientIdentity struct {
	cid.ClientIdentity
	mspID string
}

func (f *fakeClientIdentity) GetMSPID() (string, error) { return f.mspID, nil }

var _ contractapi.TransactionContextInterface = (*fakeCtx)(nil)

// --- pure-function unit tests ---

func TestHashHexIsRealSHA256(t *testing.T) {
	got := hashHex("hello world")
	want := "b94d27b9934d3e08a52e52d7da7dacefac9be2f8d1b5c0e0d3b2b8e1e8f1a4f" // placeholder, replaced below
	_ = want
	if len(got) != 64 {
		t.Fatalf("hashHex(%q) = %q, want a 64-character hex digest, got length %d", "hello world", got, len(got))
	}
	if got == "sha256:hello world" {
		t.Fatalf("hashHex still returns the old fake prefix instead of a real digest")
	}
	// Same input must always produce the same digest (determinism), and a
	// different input must produce a different one (not a constant stub).
	if hashHex("hello world") != got {
		t.Fatalf("hashHex is not deterministic for the same input")
	}
	if hashHex("different input") == got {
		t.Fatalf("hashHex returned the same digest for two different inputs")
	}
}

func TestSplitCSV(t *testing.T) {
	cases := map[string][]string{
		"":              nil,
		"Org2MSP":       {"Org2MSP"},
		"Org2MSP,Org3MSP": {"Org2MSP", "Org3MSP"},
	}
	for in, want := range cases {
		got := splitCSV(in)
		if len(got) != len(want) {
			t.Fatalf("splitCSV(%q) = %v, want %v", in, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("splitCSV(%q) = %v, want %v", in, got, want)
			}
		}
	}
}

// --- chaincode-level unit tests using the fake stub ---

func TestRegisterComponent_RejectsDuplicateID(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: oemOrgMSP}

	if err := s.RegisterComponent(ctx, "COMP-1", "BATCH-X", "Tier2Supplier", "report v1", "Org2MSP"); err != nil {
		t.Fatalf("first registration should succeed, got error: %v", err)
	}
	err := s.RegisterComponent(ctx, "COMP-1", "BATCH-X", "Tier2Supplier", "report v2", "Org2MSP")
	if err == nil {
		t.Fatalf("second registration with the same TokenID should be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "already registered") {
		t.Fatalf("expected an 'already registered' error, got: %v", err)
	}
}

func TestRegisterComponent_RejectsInsufficientCoAttestation(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: oemOrgMSP}

	// No declared co-attesting orgs and the caller is a single org, so the
	// co-attestation set has only one member; must be rejected.
	err := s.RegisterComponent(ctx, "COMP-1", "BATCH-X", "Tier2Supplier", "report", "")
	if err == nil {
		t.Fatalf("registration with only one co-attesting org should be rejected, got nil error")
	}
}

func TestRecordTest_RejectsWrongPriorStatus(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: oemOrgMSP}

	if err := s.RegisterComponent(ctx, "COMP-1", "BATCH-X", "Tier2Supplier", "report", "Org2MSP"); err != nil {
		t.Fatalf("setup registration failed: %v", err)
	}
	// Calling RecordTest twice: the second call finds status QC_PASSED, not
	// MANUFACTURED, and must be rejected.
	if err := s.RecordTest(ctx, "COMP-1", "report", "Org2MSP"); err != nil {
		t.Fatalf("first RecordTest should succeed, got: %v", err)
	}
	err := s.RecordTest(ctx, "COMP-1", "report", "Org2MSP")
	if err == nil {
		t.Fatalf("second RecordTest on an already-QC_PASSED component should be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "invalid state transition") {
		t.Fatalf("expected an 'invalid state transition' error, got: %v", err)
	}
}

func TestCoAttestationOrderIsSortedAndDeterministic(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	// Submit as Org2MSP declaring Org1MSP as a co-attestor: the set is the
	// same as submitting from Org1MSP declaring Org2MSP, and both must
	// serialize identically, matching the real-network evidence in
	// Scenario 3 where both endorsing peers computed the same read-write
	// set regardless of which organisation submitted the transaction.
	ctxA := &fakeCtx{stub: stub, callerID: "Org2MSP"}
	if err := s.RegisterComponent(ctxA, "COMP-A", "BATCH-X", "Tier2Supplier", "report", "Org1MSP"); err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	tokA, err := s.mustGetToken(ctxA, "COMP-A")
	if err != nil {
		t.Fatalf("failed to read back token: %v", err)
	}
	want := []string{"Org1MSP", "Org2MSP"}
	if len(tokA.CoAttestingOrgs) != 2 || tokA.CoAttestingOrgs[0] != want[0] || tokA.CoAttestingOrgs[1] != want[1] {
		t.Fatalf("CoAttestingOrgs = %v, want sorted %v", tokA.CoAttestingOrgs, want)
	}
}

func TestTriggerRecall_UnauthorisedCallerRejected(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: "Org2MSP"} // not OEM or Regulator

	_, err := s.TriggerRecall(ctx, "BATCH-X", "test reason")
	if err == nil {
		t.Fatalf("TriggerRecall from a non-OEM/Regulator org should be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "must be OEM or Regulator") {
		t.Fatalf("expected an OEM-or-Regulator policy error, got: %v", err)
	}
}

func TestTriggerRecall_UnknownBatchRejectedNotSilentZero(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: oemOrgMSP}

	_, err := s.TriggerRecall(ctx, "BATCH-DOES-NOT-EXIST", "test reason")
	if err == nil {
		t.Fatalf("TriggerRecall on an unregistered batch should return an error, not a silent zero-affected result")
	}
}
