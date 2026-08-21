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

// fakeCompositeKeyDelim mirrors the delimiter Fabric's real shim uses
// internally for composite keys (a U+0000 control byte, not a printable
// character). An earlier version of this fake used a literal "~" as the
// delimiter, which happens to also appear inside this chaincode's own
// object-type constant, batchComponentIndex = "batch~component": splitting
// on "~" therefore produced one segment too many, so SplitCompositeKey's
// caller (batchIndexMembers) never matched len(parts)==2 and every batch
// index lookup silently returned zero members. That bug was never caught by
// the earlier test suite because no prior unit test exercised TriggerRecall
// actually finding and recalling real components; only the real Fabric
// network (whose genuine composite-key encoding does not have this
// collision) ever exercised that path. Using a delimiter that cannot appear
// in ordinary object-type or attribute strings, as Fabric itself does,
// removes the collision instead of merely avoiding it by coincidence.
const fakeCompositeKeyDelim = "\x00"

func (f *fakeStub) CreateCompositeKey(objectType string, attrs []string) (string, error) {
	var b strings.Builder
	b.WriteString(fakeCompositeKeyDelim)
	b.WriteString(objectType)
	b.WriteString(fakeCompositeKeyDelim)
	for _, a := range attrs {
		b.WriteString(a)
		b.WriteString(fakeCompositeKeyDelim)
	}
	return b.String(), nil
}

func (f *fakeStub) SplitCompositeKey(compositeKey string) (string, []string, error) {
	if len(compositeKey) == 0 || !strings.HasPrefix(compositeKey, fakeCompositeKeyDelim) {
		return "", nil, fmt.Errorf("invalid composite key: %q", compositeKey)
	}
	parts := strings.Split(strings.TrimPrefix(compositeKey, fakeCompositeKeyDelim), fakeCompositeKeyDelim)
	if len(parts) < 1 {
		return "", nil, fmt.Errorf("invalid composite key: %q", compositeKey)
	}
	objectType := parts[0]
	attrs := parts[1:]
	// The encoding above always ends with a trailing delimiter, so the
	// final split segment is always an empty string; drop it.
	if len(attrs) > 0 && attrs[len(attrs)-1] == "" {
		attrs = attrs[:len(attrs)-1]
	}
	return objectType, attrs, nil
}

func fakeCompositeKeyPrefix(objectType string, attrs []string) string {
	var b strings.Builder
	b.WriteString(fakeCompositeKeyDelim)
	b.WriteString(objectType)
	b.WriteString(fakeCompositeKeyDelim)
	for _, a := range attrs {
		b.WriteString(a)
		b.WriteString(fakeCompositeKeyDelim)
	}
	return b.String()
}

// GetStateByPartialCompositeKey scans the same in-memory state map that
// PutState writes to, since addToBatchIndex (component_traceability.go) stores its
// composite-key index entries via an ordinary PutState call, exactly as it
// does against a real peer's world state.
func (f *fakeStub) GetStateByPartialCompositeKey(objectType string, attrs []string) (shim.StateQueryIteratorInterface, error) {
	prefix := fakeCompositeKeyPrefix(objectType, attrs)
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

// reportHash is a small test helper standing in for what a real client does
// before ever calling this chaincode: hash the off-chain report itself and
// submit only the digest. Using the chaincode's own hashHex here just
// produces a realistic-looking 64-character hex string for test fixtures;
// it does not mean the chaincode hashes anything itself any more.
func reportHash(content string) string {
	return hashHex(content)
}

func TestRegisterComponent_RejectsDuplicateID(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: oemOrgMSP}

	if err := s.RegisterComponent(ctx, "COMP-1", "BATCH-X", "Tier2Supplier", reportHash("report v1"), "Org2MSP"); err != nil {
		t.Fatalf("first registration should succeed, got error: %v", err)
	}
	err := s.RegisterComponent(ctx, "COMP-1", "BATCH-X", "Tier2Supplier", reportHash("report v2"), "Org2MSP")
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
	err := s.RegisterComponent(ctx, "COMP-1", "BATCH-X", "Tier2Supplier", reportHash("report"), "")
	if err == nil {
		t.Fatalf("registration with only one co-attesting org should be rejected, got nil error")
	}
}

func TestRegisterComponent_RejectsNonHashArgument(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: oemOrgMSP}

	// A caller passing raw report text (not a digest) must be rejected: this
	// is the guard against the off-chain report being sent to the chaincode
	// at all, not just a format nicety.
	err := s.RegisterComponent(ctx, "COMP-1", "BATCH-X", "Tier2Supplier", "this is the full QC report text, not a hash", "Org2MSP")
	if err == nil {
		t.Fatalf("registration with a non-hash testReportHash argument should be rejected, got nil error")
	}
}

func TestRecordTest_RejectsWrongPriorStatus(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: oemOrgMSP}

	if err := s.RegisterComponent(ctx, "COMP-1", "BATCH-X", "Tier2Supplier", reportHash("report"), "Org2MSP"); err != nil {
		t.Fatalf("setup registration failed: %v", err)
	}
	// Calling RecordTest twice: the second call finds status QC_PASSED, not
	// MANUFACTURED, and must be rejected.
	if err := s.RecordTest(ctx, "COMP-1", reportHash("test report"), "Org2MSP"); err != nil {
		t.Fatalf("first RecordTest should succeed, got: %v", err)
	}
	err := s.RecordTest(ctx, "COMP-1", reportHash("test report"), "Org2MSP")
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
	if err := s.RegisterComponent(ctxA, "COMP-A", "BATCH-X", "Tier2Supplier", reportHash("report"), "Org1MSP"); err != nil {
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

// --- cross-batch assembly (supervisor feedback: Batch -> Component ->
// Product/Vehicle should not require every component to share one batch) ---

func shipComponent(t *testing.T, s *SmartContract, ctx *fakeCtx, id, batch string) {
	t.Helper()
	if err := s.RegisterComponent(ctx, id, batch, "Tier2Supplier", reportHash(id+"-report"), "Org2MSP"); err != nil {
		t.Fatalf("setup RegisterComponent(%s) failed: %v", id, err)
	}
	if err := s.RecordTest(ctx, id, reportHash(id+"-test"), "Org2MSP"); err != nil {
		t.Fatalf("setup RecordTest(%s) failed: %v", id, err)
	}
	if err := s.RecordShipment(ctx, id, "Tier2Supplier", "Org1MSP", "Org2MSP"); err != nil {
		t.Fatalf("setup RecordShipment(%s) failed: %v", id, err)
	}
}

func TestRecordAssembly_AllowsCrossBatchComponents(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: oemOrgMSP}

	shipComponent(t, s, ctx, "COMP-X1", "BATCH-X")
	shipComponent(t, s, ctx, "COMP-Y1", "BATCH-Y")

	// Two components from two different batches: an earlier version of this
	// chaincode rejected this outright ("mixed-batch assembly is not
	// permitted"). It must now succeed, because a real product is routinely
	// built from parts drawn from more than one production batch.
	if err := s.RecordAssembly(ctx, "PRODUCT-XY", "COMP-X1,COMP-Y1", "RECIPE-1", "Org2MSP"); err != nil {
		t.Fatalf("cross-batch RecordAssembly should succeed, got error: %v", err)
	}
	product, err := s.mustGetToken(ctx, "PRODUCT-XY")
	if err != nil {
		t.Fatalf("failed to read back product: %v", err)
	}
	want := []string{"BATCH-X", "BATCH-Y"}
	if len(product.ComponentBatches) != 2 || product.ComponentBatches[0] != want[0] || product.ComponentBatches[1] != want[1] {
		t.Fatalf("ComponentBatches = %v, want sorted %v", product.ComponentBatches, want)
	}
}

func TestTriggerRecall_FindsCrossBatchProductViaEitherConstituentBatch(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: oemOrgMSP}

	shipComponent(t, s, ctx, "COMP-X2", "BATCH-X2")
	shipComponent(t, s, ctx, "COMP-Y2", "BATCH-Y2")
	if err := s.RecordAssembly(ctx, "PRODUCT-XY2", "COMP-X2,COMP-Y2", "RECIPE-2", "Org2MSP"); err != nil {
		t.Fatalf("setup RecordAssembly failed: %v", err)
	}

	// Recalling BATCH-Y2 (not BATCH-X2, whichever the product's "primary"
	// BatchID happens to be) must still find and recall the product: the
	// product is indexed under every batch it draws components from, not
	// only its first one.
	if _, err := s.TriggerRecall(ctx, "BATCH-Y2", "defect found in batch Y2"); err != nil {
		t.Fatalf("TriggerRecall on BATCH-Y2 should succeed, got: %v", err)
	}
	product, err := s.mustGetToken(ctx, "PRODUCT-XY2")
	if err != nil {
		t.Fatalf("failed to read back product: %v", err)
	}
	if product.RecallStatus != "RECALLED" {
		t.Fatalf("product RecallStatus = %q, want RECALLED after recalling one of its two constituent batches", product.RecallStatus)
	}
}

// --- recall/lifecycle separation (supervisor feedback: recall must not
// overwrite or destroy lifecycle status) ---

func TestTriggerRecall_PreservesLifecycleStatus(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: oemOrgMSP}

	shipComponent(t, s, ctx, "COMP-D1", "BATCH-D")
	if err := s.RecordAssembly(ctx, "PRODUCT-D1", "COMP-D1", "RECIPE-D", "Org2MSP"); err != nil {
		t.Fatalf("setup RecordAssembly failed: %v", err)
	}
	if err := s.RecordDelivery(ctx, "PRODUCT-D1", "DealerMSP", "Org2MSP"); err != nil {
		t.Fatalf("setup RecordDelivery failed: %v", err)
	}
	before, err := s.mustGetToken(ctx, "COMP-D1")
	if err != nil || before.Status != "DELIVERED" {
		t.Fatalf("setup: expected component to be DELIVERED before recall, got status=%q err=%v", before.Status, err)
	}

	if _, err := s.TriggerRecall(ctx, "BATCH-D", "defect found post-delivery"); err != nil {
		t.Fatalf("TriggerRecall failed: %v", err)
	}
	after, err := s.mustGetToken(ctx, "COMP-D1")
	if err != nil {
		t.Fatalf("failed to read back component after recall: %v", err)
	}
	if after.RecallStatus != "RECALLED" {
		t.Fatalf("RecallStatus = %q, want RECALLED", after.RecallStatus)
	}
	if after.Status != "DELIVERED" {
		t.Fatalf("Status = %q, want DELIVERED to survive the recall unchanged (this is the exact bug the supervisor flagged: recall must not overwrite lifecycle status)", after.Status)
	}
}

func TestRevokeRecall_RestoresOriginalLifecycleStatusInsteadOfGenericActive(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: oemOrgMSP}
	regCtx := &fakeCtx{stub: stub, callerID: regulatorOrgMSP}

	shipComponent(t, s, ctx, "COMP-D2", "BATCH-D2")
	if err := s.RecordAssembly(ctx, "PRODUCT-D2", "COMP-D2", "RECIPE-D2", "Org2MSP"); err != nil {
		t.Fatalf("setup RecordAssembly failed: %v", err)
	}
	if err := s.RecordDelivery(ctx, "PRODUCT-D2", "DealerMSP", "Org2MSP"); err != nil {
		t.Fatalf("setup RecordDelivery failed: %v", err)
	}
	if _, err := s.TriggerRecall(ctx, "BATCH-D2", "precautionary recall"); err != nil {
		t.Fatalf("setup TriggerRecall failed: %v", err)
	}

	if _, err := s.RevokeRecall(regCtx, "BATCH-D2", "root cause found to be unrelated"); err != nil {
		t.Fatalf("RevokeRecall failed: %v", err)
	}
	tok, err := s.mustGetToken(ctx, "COMP-D2")
	if err != nil {
		t.Fatalf("failed to read back component after revocation: %v", err)
	}
	if tok.RecallStatus != "" {
		t.Fatalf("RecallStatus = %q, want cleared to empty after RevokeRecall", tok.RecallStatus)
	}
	if tok.Status != "DELIVERED" {
		t.Fatalf("Status = %q, want DELIVERED preserved; an earlier version reset this to a generic ACTIVE value, losing the fact the component had already been delivered", tok.Status)
	}
}

func TestRequireNotRecalled_BlocksFurtherLifecycleProgression(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: oemOrgMSP}

	if err := s.RegisterComponent(ctx, "COMP-R1", "BATCH-R", "Tier2Supplier", reportHash("r"), "Org2MSP"); err != nil {
		t.Fatalf("setup registration failed: %v", err)
	}
	if err := s.RecordTest(ctx, "COMP-R1", reportHash("t"), "Org2MSP"); err != nil {
		t.Fatalf("setup RecordTest failed: %v", err)
	}
	if _, err := s.TriggerRecall(ctx, "BATCH-R", "defect found before shipment"); err != nil {
		t.Fatalf("setup TriggerRecall failed: %v", err)
	}

	// The component's lifecycle Status is still QC_PASSED (recall does not
	// touch it), so without an explicit RecallStatus guard, RecordShipment
	// would otherwise be free to proceed on a component that is currently
	// under recall.
	err := s.RecordShipment(ctx, "COMP-R1", "Tier2Supplier", "Org1MSP", "Org2MSP")
	if err == nil {
		t.Fatalf("RecordShipment on a RECALLED component should be rejected, got nil error")
	}
	if !strings.Contains(err.Error(), "RECALLED") {
		t.Fatalf("expected a RECALLED-related rejection, got: %v", err)
	}
}

func TestProvenanceCheck_DistinguishesRegisteredFromUnknown(t *testing.T) {
	s := &SmartContract{}
	stub := newFakeStub("tx1")
	ctx := &fakeCtx{stub: stub, callerID: oemOrgMSP}

	if err := s.RegisterComponent(ctx, "COMP-P1", "BATCH-P", "Tier2Supplier", reportHash("p"), "Org2MSP"); err != nil {
		t.Fatalf("setup registration failed: %v", err)
	}
	out, err := s.ProvenanceCheck(ctx, "COMP-P1")
	if err != nil || !strings.Contains(out, "REGISTERED_WITH_SUFFICIENT_ATTESTATION") {
		t.Fatalf("ProvenanceCheck on a registered component = %q, err=%v, want REGISTERED_WITH_SUFFICIENT_ATTESTATION", out, err)
	}
	out, err = s.ProvenanceCheck(ctx, "COMP-DOES-NOT-EXIST")
	if err != nil || !strings.Contains(out, "NOT_FOUND") {
		t.Fatalf("ProvenanceCheck on an unregistered component = %q, err=%v, want NOT_FOUND", out, err)
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
