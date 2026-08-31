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
//
// Version history (chaincode package version / lifecycle sequence on the
// evaluated Fabric channel; see README.md and the dissertation's Scenario
// Analysis chapter for the real-network evidence backing each):
//
//	1.0 (sequence 1): original hardening pass. Real crypto/sha256 hashing,
//	    deterministic (sorted) co-attestation, a batch~component
//	    composite-key index instead of a CouchDB rich query inside
//	    TriggerRecall, and explicit state-transition/ownership checks.
//	2.0 (sequence 2): client-side report hashing (RegisterComponent/
//	    RecordTest take a digest, never the report text), cross-batch
//	    product assembly (RecordAssembly no longer requires shared batch
//	    membership), RecallStatus separated from lifecycle Status, and
//	    CounterfeitScan renamed to ProvenanceCheck.
//	2.1 (sequence 3, evaluated deployment): RecallBatchID added to fix a cross-batch
//	    overlap gap the 2.0 design could not represent: a product recalled
//	    under two different batches at once had no record of which
//	    batch's campaign actually owned the current recall, so revoking
//	    the wrong batch could silently clear a recall it had no authority
//	    over. TriggerRecall no longer relabels a token already recalled
//	    under a different batch (reported as skippedOverlap instead), and
//	    ReviseRecallReason/RevokeRecall now act only on tokens whose
//	    RecallBatchID matches the batch named in the call.
//	2.2 (sequence 4): append-only EvidenceReference records plus
//	    AttachEvidence/GetEvidence, preserving the v2.1 transaction
//	    signatures and legacy DataHash field. Unit-tested from the start;
//	    also exercised live on the same three-organisation network
//	    (evidence/real_fabric_run5_evidence_extension.log): a component
//	    registered, two typed evidence references attached and both
//	    retained by GetEvidence, and both negative cases (duplicate
//	    evidence ID, malformed digest) rejected as designed.
//	3.0 (sequence 5): caller authorisation hardened in response to
//	    supervisor review. RegisterComponent, RecordTest, RecordShipment,
//	    RecordAssembly, RecordDelivery, AttachEvidence, CloseRecall, and
//	    RecordUsageLog previously checked only caller-supplied business
//	    data (a declared fromOwner string, a declared supplierID,
//	    CoAttestingOrgs) and never the caller's own authenticated MSP
//	    identity, so an enrolled but unrelated participant could act on a
//	    token it did not hold. requireCallerIsOwner and requireCallerIs now
//	    compare against ctx.GetClientIdentity().GetMSPID() directly.
//	    RecordUsageLog also gained the DELIVERED status check the
//	    dissertation already claimed but the code did not enforce.
//	    ProvenanceCheck's REGISTERED_WITH_SUFFICIENT_ATTESTATION result was
//	    renamed to REGISTERED_WITH_DECLARED_PARTICIPANTS, since
//	    CoAttestingOrgs is caller-supplied and not cryptographic evidence of
//	    endorsement. Unit-tested (27 cases, including 11 new
//	    caller-authorisation negative tests) and exercised live on the same
//	    three-organisation network (evidence/real_fabric_run6_caller_authorisation.log;
//	    Scenario 9).
//	3.1 (sequence 6): proactive hardening of the same caller-authorisation
//	    layer, anticipating further review rather than waiting for it.
//	    Closes three residual gaps the v3.0 fix did not: (1) RecordShipment
//	    accepted any toOrg string as the new Owner, so a mistyped or
//	    fabricated destination could permanently orphan a token (no future
//	    caller could ever satisfy requireCallerIsOwner again) -- toOrg must
//	    now be one of the network's known MSPs; (2) RecordAssembly checked
//	    only that the caller *was* the OEM, never that the OEM actually
//	    *held* each listed component, so a component shipped laterally to
//	    Tier-1 could still be assembled by the OEM purely on role, not
//	    possession -- a per-component requireCallerIsOwner check was added;
//	    (3) declared CoAttestingOrgs names were accepted verbatim with no
//	    check that they named a real, deployed organisation, so a typo'd or
//	    fabricated org could be recorded as if it were a genuine
//	    participant -- recordCoAttestation now rejects any declared name
//	    outside the known three-organisation set. RecordDelivery also
//	    gained a plain non-empty check on dealerID. Unit-tested (31 cases,
//	    4 new) and exercised live on the same three-organisation network
//	    (evidence/real_fabric_run7_proactive_hardening.log; Scenario 10).
//	3.2 (sequence 7): intra-organisation role boundary. MSP membership
//	    alone proves the caller belongs to an authorised organisation, not
//	    that every enrolled client in it may perform a safety-critical
//	    operation. TriggerRecall, CloseRecall, ReviseRecallReason,
//	    RevokeRecall, and RecordUsageLog now additionally require an
//	    X.509 OU=admin certificate (requireCallerOU), rejecting an
//	    OU=client identity even from an otherwise-authorised MSP. Exercised
//	    live with the network's real Org1 Admin and User1 certificates
//	    (evidence/real_fabric_run8_client_role.log; Scenario 11); this is a
//	    coarse test-network role model, not a claim that production
//	    telemetry should require a full administrator.
//	3.3 (sequence 8): CustodianMSP/InstalledInProductID/DealerID field
//	    separation, prompted by supervisor review. The single Owner field
//	    held three different concepts across a token's lifetime: an MSP
//	    identity after registration, a productID after RecordAssembly, and
//	    a caller-supplied dealerID after RecordDelivery. Since
//	    requireCallerIsOwner compared the caller's MSP against that same
//	    field, no enrolled identity could ever pass the check again once
//	    either of the latter two values overwrote it -- a gap Scenario 9
//	    had already surfaced for AttachEvidence after delivery, but which
//	    also affected AttachEvidence on any assembled-but-undelivered
//	    component, not previously tested. CustodianMSP now holds only a
//	    real, deployed MSP and is never overwritten with a productID or
//	    dealerID; RecordAssembly records InstalledInProductID and
//	    RecordDelivery records DealerID as separate fields instead,
//	    renamed requireCallerIsOwner to requireCallerIsCustodian throughout
//	    (compares against CustodianMSP), and RecordUsageLog switched from a
//	    hardcoded OEM role check to the same CustodianMSP check every other
//	    function uses, since CustodianMSP now correctly survives delivery.
//	    Unit-tested (4 new cases proving CustodianMSP survives assembly and
//	    delivery, and that AttachEvidence now succeeds in both cases
//	    previously blocked) and exercised live on the same
//	    three-organisation network (evidence/real_fabric_run9_custodian_field_separation.log;
//	    Scenario 12).
//	3.4 (sequence 9): read-time compatibility for pre-v3.3 ledger records.
//	    A record written before v3.3 has no custodianMsp key at all, so
//	    CustodianMSP unmarshals to empty rather than an error -- a gap
//	    identified and stated as untested/unimplemented in the
//	    dissertation immediately after v3.3 shipped. mustGetToken now
//	    falls back to decoding the legacy "owner" key when CustodianMSP is
//	    empty, so a genuinely legacy record that was never assembled or
//	    delivered under the old design (and so still holds a real MSP in
//	    "owner") can be read and authorised against correctly. This is
//	    read-time compatibility, not a migration: nothing is written back,
//	    and a legacy record whose "owner" had already been overwritten
//	    with a productID or dealerID before v3.3 existed cannot be
//	    recovered, since that value was never a usable MSP identity to
//	    begin with. Unit-tested (2 new cases, one proving recovery and one
//	    proving the honest boundary) and exercised live on the same
//	    three-organisation network against a genuine pre-v3.3 record still
//	    on the real ledger (evidence/real_fabric_run10_legacy_compatibility.log;
//	    Scenario 13).
//	3.5 (sequence 10): RecallCampaigns replaces the scalar RecallBatchID/
//	    Reason/ReasonHistory fields with a one-to-many record, closing the
//	    overlapping-recall gap named explicitly in supervisor review and
//	    already flagged as a partial solution throughout this dissertation.
//	    Before this version, a token recalled under a second, independent
//	    batch could not have that second campaign tracked at all -- it was
//	    reported only as skippedOverlap and silently dropped otherwise. Each
//	    RecallCampaign is now its own record (BatchID, Reason,
//	    ReasonHistory, Status, OpenedAt), so a token can carry more than one
//	    simultaneously open campaign, and CloseRecall/ReviseRecallReason/
//	    RevokeRecall now take an explicit batchID identifying which campaign
//	    they act on, rather than assuming a token has only one. The derived
//	    RecallStatus field is retained (RECALLED if any campaign is open,
//	    else "") so requireNotRecalled and ProvenanceCheck's single-field
//	    read need no change. skippedOverlap is removed from TriggerRecall's
//	    response: a second batch's campaign is now genuinely opened, not
//	    skipped. mustGetToken falls back to synthesising one RecallCampaign
//	    from the legacy scalar fields when RecallCampaigns is empty but a
//	    legacy RecallBatchID is present, the same pattern introduced in
//	    v3.4 for CustodianMSP, except this one is naturally written forward
//	    on the record's next recall-mutating call rather than staying
//	    read-only, since CloseRecall/ReviseRecallReason/RevokeRecall write
//	    through RecallCampaigns directly. Unit-tested (new cases proving two
//	    independent campaigns on one token, independent closure/revocation,
//	    and the legacy-campaign fallback) and exercised live on the same
//	    three-organisation network (evidence/real_fabric_run11_recall_campaigns.log;
//	    Scenario 14).
type SmartContract struct {
	contractapi.Contract
}

// ComponentToken is the on-chain record for a single component or an
// assembled product.
//
// Three fields deserve special note because they were previously a source of
// confusion between "cryptographic proof" and "self-reported business data",
// or between two logically distinct notions of "status":
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
//     business-level annotation, not a security control. Genuine peer
//     endorsement is never derived from this field; it is enforced
//     separately, before this code ever runs, by the channel's endorsement
//     policy and Fabric's signature verification over each peer's simulated
//     response.
//   - Status is the component's lifecycle position (MANUFACTURED,
//     QC_PASSED, SHIPPED, ASSEMBLED, DELIVERED) and is never set to
//     RECALLED. RecallStatus is a separate field for exactly this reason:
//     an earlier version of this chaincode overwrote Status with RECALLED
//     and then, on revocation, reset it to a generic ACTIVE value, silently
//     destroying whatever lifecycle stage the token had actually reached
//     (was it DELIVERED? still ASSEMBLED?). Keeping the two fields apart
//     means a recall can be triggered, resolved, or revoked without ever
//     touching the lifecycle history the rest of the system depends on.
//     RecallStatus itself is now a *derived* summary (see
//     recomputeRecallStatus): RECALLED if any entry in RecallCampaigns is
//     currently open, else "". The authoritative record of who did what,
//     under which batch, is RecallCampaigns, not RecallStatus.
//   - RecallCampaigns replaces a pre-v3.5 design that stored only one
//     scalar RecallBatchID/Reason/ReasonHistory set per token, so a second,
//     independent recall campaign against the same token (a product
//     indexed under two batches, Section 3.3) had nowhere to be recorded
//     and was only ever reported as skippedOverlap. Each RecallCampaign is
//     its own record, so two campaigns against one token now coexist and
//     are independently closeable (CloseRecall), amendable
//     (ReviseRecallReason), and revocable (RevokeRecall), each identified
//     by its own BatchID rather than assumed to be the token's only one.
//   - CustodianMSP, InstalledInProductID, and DealerID were previously one
//     overloaded field (Owner), which held a real MSP identity right after
//     registration, then a productID once a component was assembled
//     (RecordAssembly), then a caller-supplied dealerID once delivered
//     (RecordDelivery). Because caller authorisation compares the caller's
//     MSP against that same field, an assembled-but-undelivered component
//     could never again pass an ownership check (a productID is not an
//     MSP), and no enrolled identity could pass one after delivery either
//     (a dealerID is not an MSP) -- identified in supervisor review.
//     CustodianMSP now holds only ever a real, deployed MSP and is never
//     overwritten with a productID or dealerID: RecordAssembly records
//     InstalledInProductID separately without touching the component's
//     CustodianMSP, and RecordDelivery records DealerID separately without
//     touching CustodianMSP either, so a caller can still be authorised
//     against a token's real custodian after assembly and after delivery.
//     This is a deliberate design choice, not an oversight: CustodianMSP
//     answers "which enrolled organisation is accountable for this token",
//     which remains the OEM once a component is installed into a product
//     it assembled, or once a product it delivered leaves the channel's
//     membership -- not "who currently has physical possession", which
//     InstalledInProductID and DealerID answer separately and which this
//     chaincode cannot authenticate cryptographically (see Limitations).
//
// Ledger registration (this struct existing at TokenID) also only proves
// that *some* authorised client wrote this record; it does not, by itself,
// prove that the physical component being scanned in the real world is the
// genuine article the record describes (see ProvenanceCheck's doc comment).
// EvidenceReference anchors one externally stored document to a token.
// Document bytes stay off-chain. ProducerMSP is declared metadata, whereas
// SubmittedByMSP comes from the authenticated Fabric proposal signer.
type EvidenceReference struct {
	EvidenceID     string    `json:"evidenceId"`
	DocumentType   string    `json:"documentType"`
	SHA256         string    `json:"sha256"`
	HashAlgorithm  string    `json:"hashAlgorithm"`
	ProducerMSP    string    `json:"producerMsp"`
	RepositoryRef  string    `json:"repositoryRef"`
	SubmittedByMSP string    `json:"submittedByMsp"`
	SubmittedAt    time.Time `json:"submittedAt"`
	SchemaVersion  string    `json:"schemaVersion"`
}

type ComponentToken struct {
	DocType          string              `json:"docType"` // "component" or "product"
	TokenID          string              `json:"tokenId"`
	BatchID          string              `json:"batchId"`                    // component: its one batch; product: its lowest-sorted constituent batch, see ComponentBatches
	ComponentBatches []string            `json:"componentBatches,omitempty"` // product tokens only: every distinct batch among the assembled components (see RecordAssembly)
	RecipeID         string              `json:"recipeId,omitempty"`
	Status           string              `json:"status"`                 // lifecycle only: MANUFACTURED, QC_PASSED, SHIPPED, ASSEMBLED, DELIVERED (never RECALLED; see RecallStatus)
	RecallStatus     string              `json:"recallStatus,omitempty"` // DERIVED: "" or RECALLED, recomputed from RecallCampaigns by recomputeRecallStatus after every campaign mutation; independent of Status
	RecallCampaigns  []RecallCampaign    `json:"recallCampaigns,omitempty"` // v3.5: one-to-many replacement for the pre-v3.5 scalar recall fields below, allowing independently-managed overlapping campaigns (see type doc comment)
	CustodianMSP         string `json:"custodianMsp"`                   // authenticated MSP currently accountable for this token; always one of this network's real, deployed organisations (see requireCallerIsCustodian). Never overwritten with a productID or dealerID -- see InstalledInProductID and DealerID below.
	InstalledInProductID string `json:"installedInProductId,omitempty"` // set once a component has been assembled into a product (RecordAssembly); the component's own CustodianMSP is left unchanged, so ownership checks on it continue to work after assembly
	DealerID             string `json:"dealerId,omitempty"`             // caller-supplied business identifier for the delivery destination (RecordDelivery); NOT an MSP and never compared against a caller's authenticated identity -- CustodianMSP is deliberately left unchanged on delivery so it remains a real, checkable identity
	DataHash         string              `json:"dataHash,omitempty"` // legacy latest digest retained for v2.1 compatibility
	Evidence         []EvidenceReference `json:"evidence,omitempty"` // typed references to separately stored off-chain documents
	SubmittingOrgMSP string              `json:"submittingOrgMspId"` // cryptographically verified by Fabric for this transaction
	CoAttestingOrgs  []string            `json:"coAttestingOrgs"`    // self-declared, not independently verified (see type doc comment)
	Timestamp        time.Time           `json:"timestamp"`          // from ctx.GetStub().GetTxTimestamp(), not time.Now()
	Components       []string            `json:"components,omitempty"` // for assembled product tokens
	UsageAvgTempC    *float64            `json:"usageAvgTempC,omitempty"`

	// Pre-v3.5 scalar recall fields, retained only so a legacy record still
	// decodes and can be recovered by mustGetToken's read-time fallback into
	// RecallCampaigns (see the v3.5 changelog entry above). New code never
	// writes these three fields.
	RecallBatchID string   `json:"recallBatchId,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	ReasonHistory []string `json:"reasonHistory,omitempty"`
}

// RecallCampaign records one independently-managed recall campaign against a
// token, identified by the batch that opened it. Introduced in v3.5 to
// replace a single scalar RecallBatchID/Reason/ReasonHistory set per token,
// which meant a second, genuinely independent campaign against the same
// token (a product indexed under two batches, Section 3.3) could not be
// tracked at all -- see the type doc comment on ComponentToken and the v3.5
// changelog entry.
type RecallCampaign struct {
	BatchID       string    `json:"batchId"`
	Reason        string    `json:"reason"`             // original reason, never overwritten; amendments go to ReasonHistory
	ReasonHistory []string  `json:"reasonHistory,omitempty"`
	Status        string    `json:"status"`   // RECALLED (open), or a terminal value: REPAIRED, REPLACED, RETIRED (via CloseRecall), or REVOKED (via RevokeRecall)
	OpenedAt      time.Time `json:"openedAt"` // ctx.GetStub().GetTxTimestamp() at TriggerRecall, not time.Now()
}

const (
	minCoAttestingOrgs  = 2
	oemOrgMSP           = "Org1MSP" // generic OEM org; map to your real MSP identifier at deployment (see README)
	tier1OrgMSP         = "Org2MSP" // generic Tier-1 supplier org; the only supplier-side org actually deployed on the evaluated test network (see README / Limitations)
	regulatorOrgMSP     = "Org3MSP" // requires a third network organisation; see Limitations
	batchComponentIndex = "batch~component"
)

// knownOrgMSPs lists every MSP actually deployed on this evaluated network.
// Used to reject nonsense or mistyped organisation names wherever a caller
// supplies one as business data (a declared co-attestor, a shipment
// destination), rather than silently accepting and recording it. This does
// not make CoAttestingOrgs cryptographic evidence of endorsement -- a
// caller can still name a real organisation that never reviewed the
// record -- it only stops a typo'd or fabricated name from being accepted
// as if it were a real one.
var knownOrgMSPs = []string{oemOrgMSP, tier1OrgMSP, regulatorOrgMSP}

func isKnownOrgMSP(msp string) bool {
	for _, o := range knownOrgMSPs {
		if msp == o {
			return true
		}
	}
	return false
}

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
		if o == "" {
			continue
		}
		if !isKnownOrgMSP(o) {
			return "", nil, fmt.Errorf("declared co-attesting org %q is not a known organisation on this network", o)
		}
		set[o] = true
	}
	out := make([]string, 0, len(set))
	for o := range set {
		out = append(out, o)
	}
	sort.Strings(out)
	return callerMSP, out, nil
}

// requireCallerIsCustodian enforces that the transaction's authenticated MSP
// identity, not any caller-supplied business string, matches the token's
// CustodianMSP before a custody-changing or custody-scoped operation
// proceeds.
//
// This exists to close a caller-authorisation gap identified in supervisor
// review: several functions previously checked only a caller-supplied claim
// against the token (e.g. RecordShipment's now-removed fromOwner check,
// which compared a single overloaded Owner field to a string the caller
// itself typed in) and never verified that the caller's own
// cryptographically authenticated identity actually matched. Under that
// design, any enrolled participant who merely knew or guessed the current
// owner value could act on a token they did not hold, because the check
// never touched ctx.GetClientIdentity() at all. Comparing against callerMSP
// here instead ties the decision to the same MSP identity Fabric itself
// authenticates for every transaction, which cannot be forged by the caller
// the way a plain string argument can.
//
// A second, later review round found that Owner itself was overloaded
// across the lifecycle -- an MSP identity, then a productID, then a
// dealerID -- which meant this check could never succeed again once either
// of the latter two overwrote it (see the ComponentToken doc comment).
// Comparing against the now-separate CustodianMSP field fixes that: a
// component's custodian survives assembly (InstalledInProductID is set
// instead) and a product's custodian survives delivery (DealerID is set
// instead), so this check keeps working at every lifecycle stage rather
// than only until the first productID/dealerID assignment.
func requireCallerIsCustodian(ctx contractapi.TransactionContextInterface, token *ComponentToken) error {
	callerMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return fmt.Errorf("failed to get caller MSP: %v", err)
	}
	if callerMSP != token.CustodianMSP {
		return fmt.Errorf("caller %s is not the current custodian of token %s (custodian is %s)", callerMSP, token.TokenID, token.CustodianMSP)
	}
	return nil
}

// requireCallerIs enforces that the transaction's authenticated MSP identity
// is one of the given allowed organisations, returning that identity on
// success. Used for functions restricted to a role rather than to a token's
// current owner (e.g. only the OEM may assemble products; only the OEM or
// Regulator may resolve a recall). Every caller of this helper passes the
// error straight back to the client without proceeding, so a rejected
// caller's identity is never silently accepted for a partial effect.
func requireCallerIs(ctx contractapi.TransactionContextInterface, allowed ...string) (string, error) {
	callerMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", fmt.Errorf("failed to get caller MSP: %v", err)
	}
	for _, a := range allowed {
		if callerMSP == a {
			return callerMSP, nil
		}
	}
	return "", fmt.Errorf("caller org %s is not authorised to call this function (allowed: %v)", callerMSP, allowed)
}

// requireCallerOU adds a client-role check within an already-authorised MSP.
// MSP membership alone proves the caller belongs to an organisation, not
// that every enrolled client in that organisation may perform a
// safety-critical operation. The evaluated Fabric CA certificates distinguish
// administrators (OU=admin) from ordinary enrolled users (OU=client).
func requireCallerOU(ctx contractapi.TransactionContextInterface, allowedOU string) error {
	cert, err := ctx.GetClientIdentity().GetX509Certificate()
	if err != nil {
		return fmt.Errorf("failed to get caller certificate: %v", err)
	}
	if cert == nil {
		return fmt.Errorf("caller certificate is unavailable")
	}
	for _, ou := range cert.Subject.OrganizationalUnit {
		if ou == allowedOU {
			return nil
		}
	}
	return fmt.Errorf("caller certificate requires OU=%s, got %v", allowedOU, cert.Subject.OrganizationalUnit)
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
//
// supplierID is accepted for interface/script compatibility and audit-trail
// readability only. It is a caller-supplied label, not independently
// verified, so it is never used to decide the token's custodian: the
// custodian is always the caller's own authenticated MSP identity (see
// requireCallerIsCustodian). Only the OEM or the (one, deployed) Tier-1
// supplier org may register a new component; the Regulator may not.
func (s *SmartContract) RegisterComponent(ctx contractapi.TransactionContextInterface,
	componentID string, batchID string, supplierID string, testReportHash string, coAttestingOrgsCSV string) error {

	if componentID == "" || batchID == "" {
		return fmt.Errorf("registerComponent rejected: componentID and batchID are required")
	}
	if _, err := requireCallerIs(ctx, oemOrgMSP, tier1OrgMSP); err != nil {
		return fmt.Errorf("registerComponent rejected: %v", err)
	}
	if err := requireHashLike(testReportHash); err != nil {
		return fmt.Errorf("registerComponent rejected: %v", err)
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
		CustodianMSP:     callerMSP, // authenticated identity, not the caller-supplied supplierID
		DataHash:         testReportHash,
		SubmittingOrgMSP: callerMSP,
		CoAttestingOrgs:  coAttestors,
		Timestamp:        ts,
	}
	if err := s.putToken(ctx, &token, "ComponentRegistered"); err != nil {
		return err
	}
	return s.addToBatchIndex(ctx, batchID, componentID)
}

// RecordTest commits the off-chain QC test report's hash on-chain. The
// caller computes the SHA-256 digest of the report itself and submits only
// the hex digest as testReportHash; the report text is never sent to, or
// seen by, this chaincode (see the on-chain/off-chain boundary discussion,
// dissertation Section 3.6). Requires the component to currently be
// MANUFACTURED, so a component cannot be tested twice or tested before it
// exists.
func (s *SmartContract) RecordTest(ctx contractapi.TransactionContextInterface, componentID string, testReportHash string, coAttestingOrgsCSV string) error {
	token, err := s.mustGetToken(ctx, componentID)
	if err != nil {
		return err
	}
	if err := requireStatus(token, "MANUFACTURED"); err != nil {
		return err
	}
	if err := requireNotRecalled(token); err != nil {
		return err
	}
	if err := requireCallerIsCustodian(ctx, token); err != nil {
		return fmt.Errorf("recordTest rejected: %v", err)
	}
	if err := requireHashLike(testReportHash); err != nil {
		return fmt.Errorf("recordTest rejected: %v", err)
	}
	callerMSP, coAttestors, err := recordCoAttestation(ctx, splitCSV(coAttestingOrgsCSV))
	if err != nil {
		return err
	}
	if len(coAttestors) < minCoAttestingOrgs {
		return fmt.Errorf("recordTest rejected: needs >=%d co-attesting orgs", minCoAttestingOrgs)
	}
	token.DataHash = testReportHash
	token.SubmittingOrgMSP = callerMSP
	token.CoAttestingOrgs = coAttestors
	token.Status = "QC_PASSED"
	return s.putToken(ctx, token, "TestRecorded")
}

// AttachEvidence appends verification metadata for an externally stored
// document. The document itself never enters the Fabric proposal.
func (s *SmartContract) AttachEvidence(ctx contractapi.TransactionContextInterface,
	tokenID string, evidenceID string, documentType string, documentSHA256 string,
	producerMSP string, repositoryRef string, coAttestingOrgsCSV string) error {
	if tokenID == "" || evidenceID == "" || documentType == "" || producerMSP == "" || repositoryRef == "" {
		return fmt.Errorf("attachEvidence rejected: tokenID, evidenceID, documentType, producerMSP, and repositoryRef are required")
	}
	if err := requireHashLike(documentSHA256); err != nil {
		return fmt.Errorf("attachEvidence rejected: %v", err)
	}
	token, err := s.mustGetToken(ctx, tokenID)
	if err != nil {
		return err
	}
	for _, evidence := range token.Evidence {
		if evidence.EvidenceID == evidenceID {
			return fmt.Errorf("attachEvidence rejected: evidence %s already exists on token %s", evidenceID, tokenID)
		}
	}
	if err := requireCallerIsCustodian(ctx, token); err != nil {
		return fmt.Errorf("attachEvidence rejected: %v", err)
	}
	callerMSP, coAttestors, err := recordCoAttestation(ctx, splitCSV(coAttestingOrgsCSV))
	if err != nil {
		return err
	}
	if len(coAttestors) < minCoAttestingOrgs {
		return fmt.Errorf("attachEvidence rejected: needs >=%d co-attesting orgs", minCoAttestingOrgs)
	}
	ts, err := txTimestamp(ctx)
	if err != nil {
		return err
	}
	token.Evidence = append(token.Evidence, EvidenceReference{
		EvidenceID: evidenceID, DocumentType: documentType,
		SHA256: documentSHA256, HashAlgorithm: "SHA-256",
		ProducerMSP: producerMSP, RepositoryRef: repositoryRef,
		SubmittedByMSP: callerMSP, SubmittedAt: ts, SchemaVersion: "1.0",
	})
	token.SubmittingOrgMSP = callerMSP
	token.CoAttestingOrgs = coAttestors
	return s.putToken(ctx, token, "EvidenceAttached")
}

// GetEvidence returns ledger metadata and digests only. Authorised clients
// retrieve the corresponding document from the external repository.
func (s *SmartContract) GetEvidence(ctx contractapi.TransactionContextInterface, tokenID string) ([]EvidenceReference, error) {
	token, err := s.mustGetToken(ctx, tokenID)
	if err != nil {
		return nil, err
	}
	return token.Evidence, nil
}

// RecordShipment transfers custody to the next organisation in the chain.
// Requires the component to currently be QC_PASSED.
//
// fromOwner is retained for interface/script compatibility and audit-trail
// readability only; it used to be compared directly against the token's
// (then single, overloaded) Owner field as the sole authorisation check,
// which meant any enrolled caller who simply knew or guessed the right
// string, not necessarily the actual custodian, could ship someone else's
// component. That check has been removed in favour of
// requireCallerIsCustodian, which instead compares the caller's own
// cryptographically authenticated MSP identity to the token's CustodianMSP.
// fromOwner is no longer used to decide anything.
//
// toOrg becomes the new CustodianMSP as a caller-supplied destination
// declaration; this authenticates the sender's authority to release
// custody, not an acceptance signature from the receiving organisation.
// Requiring the receiver to also endorse the transfer is a natural
// extension left for future work (Limitations).
func (s *SmartContract) RecordShipment(ctx contractapi.TransactionContextInterface, componentID string, fromOwner string, toOrg string, coAttestingOrgsCSV string) error {
	token, err := s.mustGetToken(ctx, componentID)
	if err != nil {
		return err
	}
	if err := requireStatus(token, "QC_PASSED"); err != nil {
		return err
	}
	if err := requireNotRecalled(token); err != nil {
		return err
	}
	if err := requireCallerIsCustodian(ctx, token); err != nil {
		return fmt.Errorf("recordShipment rejected: %v", err)
	}
	// toOrg becomes the token's new CustodianMSP, so an unvalidated or
	// mistyped value here would orphan the token: no future
	// requireCallerIsCustodian check could ever match it again. Restricting
	// it to a known, deployed organisation closes that failure mode; it
	// does not, by itself, confirm that organisation agreed to receive the
	// shipment (Section on defence in depth).
	if !isKnownOrgMSP(toOrg) {
		return fmt.Errorf("recordShipment rejected: toOrg %q is not a known organisation on this network", toOrg)
	}
	callerMSP, coAttestors, err := recordCoAttestation(ctx, splitCSV(coAttestingOrgsCSV))
	if err != nil {
		return err
	}
	if len(coAttestors) < minCoAttestingOrgs {
		return fmt.Errorf("recordShipment rejected: needs >=%d co-attesting orgs", minCoAttestingOrgs)
	}
	token.CustodianMSP = toOrg
	token.SubmittingOrgMSP = callerMSP
	token.CoAttestingOrgs = coAttestors
	token.Status = "SHIPPED"
	return s.putToken(ctx, token, "ShipmentRecorded")
}

// RecordAssembly combines component tokens into a single product token (the
// "Token Recipe" pattern). Every listed component must currently be SHIPPED
// and not already used in another assembly; the product ID must not already
// exist.
//
// Components are deliberately NOT required to share one batch: a real
// automotive product is routinely assembled from parts sourced from several
// suppliers and several production batches (Batch -> Component ->
// Product/Vehicle -> Dealer, not one Batch -> one Product). An earlier
// version of this chaincode rejected any assembly whose components spanned
// more than one batch; that made the demonstration simpler but did not
// represent a real supply chain, and would have silently hidden a recalled
// component if it happened to sit inside a multi-batch product. The product
// token instead records every distinct batch its components were drawn from
// in ComponentBatches, and is indexed under all of them, so that recalling
// ANY one of those batches (TriggerRecall) correctly finds and recalls the
// product too, not only products whose components all share one batch.
func (s *SmartContract) RecordAssembly(ctx contractapi.TransactionContextInterface, productID string, componentIDsCSV string, recipeID string, coAttestingOrgsCSV string) error {
	if productID == "" {
		return fmt.Errorf("recordAssembly rejected: productID is required")
	}
	if _, err := requireCallerIs(ctx, oemOrgMSP); err != nil {
		return fmt.Errorf("recordAssembly rejected: %v", err)
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
	batchSet := map[string]bool{}
	for _, cid := range componentIDs {
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
		if err := requireNotRecalled(tok); err != nil {
			return fmt.Errorf("recordAssembly rejected for component %s: %v", cid, err)
		}
		// requireCallerIs above only confirms the caller is *an* OEM
		// identity; it does not confirm this specific component was ever
		// shipped to that OEM. Without this check, an OEM could assemble a
		// component still owned by another organisation (e.g. shipped
		// laterally to Tier-1 rather than to the OEM) purely because it is
		// allowed to call RecordAssembly at all -- the same
		// role-check-without-possession-check gap RecordShipment and
		// RecordDelivery were fixed against.
		if err := requireCallerIsCustodian(ctx, tok); err != nil {
			return fmt.Errorf("recordAssembly rejected for component %s: %v", cid, err)
		}
		batchSet[tok.BatchID] = true
		tokens = append(tokens, tok)
	}
	componentBatches := make([]string, 0, len(batchSet))
	for b := range batchSet {
		componentBatches = append(componentBatches, b)
	}
	sort.Strings(componentBatches)

	// Only mutate world state after every precondition above has passed, so
	// a rejected assembly never leaves some components half-updated.
	// InstalledInProductID records that this component is now part of a
	// product; CustodianMSP is deliberately left unchanged (still the OEM,
	// confirmed above), so a later AttachEvidence or similar call against
	// this specific component ID can still authorise correctly -- an
	// earlier version overwrote Owner with productID here, which broke
	// exactly that check for the rest of the component's lifetime.
	for _, tok := range tokens {
		tok.Status = "ASSEMBLED"
		tok.InstalledInProductID = productID
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
		BatchID:          componentBatches[0], // primary/lowest-sorted batch, for display only; ComponentBatches is authoritative
		ComponentBatches: componentBatches,
		RecipeID:         recipeID,
		Status:           "ASSEMBLED",
		CustodianMSP:     oemOrgMSP,
		Components:       componentIDs,
		SubmittingOrgMSP: callerMSP,
		CoAttestingOrgs:  coAttestors,
		Timestamp:        ts,
	}
	if err := s.putToken(ctx, &product, "AssemblyRecorded"); err != nil {
		return err
	}
	// Index the product under every batch it draws components from, so a
	// recall of any one of those batches finds this product too.
	for _, b := range componentBatches {
		if err := s.addToBatchIndex(ctx, b, productID); err != nil {
			return err
		}
	}
	return nil
}

// RecordDelivery sets the final owner to the dealer. Requires the product to
// currently be ASSEMBLED, and cascades the same ownership/status update to
// every component the product was built from, so a query on a component
// after delivery reflects reality instead of still showing it owned by the
// assembler.
func (s *SmartContract) RecordDelivery(ctx contractapi.TransactionContextInterface, productID string, dealerID string, coAttestingOrgsCSV string) error {
	if dealerID == "" {
		return fmt.Errorf("recordDelivery rejected: dealerID is required")
	}
	token, err := s.mustGetToken(ctx, productID)
	if err != nil {
		return err
	}
	if err := requireStatus(token, "ASSEMBLED"); err != nil {
		return err
	}
	if err := requireNotRecalled(token); err != nil {
		return err
	}
	if err := requireCallerIsCustodian(ctx, token); err != nil {
		return fmt.Errorf("recordDelivery rejected: %v", err)
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

	// DealerID records the delivery destination as caller-supplied business
	// data; CustodianMSP is deliberately left unchanged (still the OEM,
	// confirmed above by requireCallerIsCustodian) rather than overwritten
	// with a non-MSP value. An earlier version overwrote Owner with
	// dealerID here, which meant no enrolled identity could ever pass an
	// ownership check on this token again (a dealerID is not an MSP);
	// CustodianMSP staying a real, checkable identity after delivery is
	// what lets AttachEvidence and RecordUsageLog keep working afterwards.
	token.DealerID = dealerID
	token.SubmittingOrgMSP = callerMSP
	token.CoAttestingOrgs = coAttestors
	token.Status = "DELIVERED"
	if err := s.putToken(ctx, token, "DeliveryRecorded"); err != nil {
		return err
	}
	for _, ctok := range componentTokens {
		ctok.DealerID = dealerID
		ctok.Status = "DELIVERED"
		if err := s.putToken(ctx, ctok, ""); err != nil {
			return err
		}
	}
	return nil
}

// RecordUsageLog stores field telemetry used by the warranty-dispute
// scenario. Requires the component to have been delivered (there is no
// meaningful "usage" before a customer has the product); an earlier version
// of this function checked only requireNotRecalled and silently accepted
// usage data for a component still sitting at MANUFACTURED/QC_PASSED/
// SHIPPED/ASSEMBLED, contradicting the dissertation's own stated design.
// That gap is fixed below by requiring Status == DELIVERED explicitly.
//
// Caller authorisation now checks CustodianMSP like every other lifecycle
// function, rather than hardcoding the OEM as a special case. The real
// post-delivery custodian of the physical product is a dealer or service
// centre, but this evaluated network deploys only three organisations
// (OEM, Tier-1 supplier, Regulator; see README / Limitations) and has no
// separate dealer MSP to authenticate against. Because RecordDelivery
// records the delivery destination in the separate DealerID field and
// deliberately leaves CustodianMSP unchanged, CustodianMSP still correctly
// names the OEM after delivery, so requireCallerIsCustodian works here
// exactly as it does everywhere else -- no special-casing required. (An
// earlier version reached the same OEM-only outcome by hardcoding
// requireCallerIs(ctx, oemOrgMSP) instead, precisely because the
// then-single Owner field had already been overwritten with a dealerID by
// this point and could no longer be compared meaningfully.) A production
// design would still add a real dealer/service organisation so telemetry
// is authenticated from the party that actually reports it, instead of
// relayed through the OEM.
func (s *SmartContract) RecordUsageLog(ctx contractapi.TransactionContextInterface, componentID string, avgTempC float64, coAttestingOrgsCSV string) error {
	token, err := s.mustGetToken(ctx, componentID)
	if err != nil {
		return err
	}
	if err := requireStatus(token, "DELIVERED"); err != nil {
		return fmt.Errorf("recordUsageLog rejected: %v", err)
	}
	if err := requireNotRecalled(token); err != nil {
		return err
	}
	if err := requireCallerIsCustodian(ctx, token); err != nil {
		return fmt.Errorf("recordUsageLog rejected: %v", err)
	}
	if err := requireCallerOU(ctx, "admin"); err != nil {
		return fmt.Errorf("recordUsageLog rejected: %v", err)
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

// ProvenanceCheck checks whether a token exists and was registered with the
// required number of co-attesting organisations. Read-only.
//
// Named ProvenanceCheck rather than the earlier CounterfeitScan, because the
// original name implied a stronger guarantee than the function actually
// provides. Important scope limitation, stated explicitly rather than only
// in prose elsewhere: this function verifies ledger presence and declared
// co-attestation count, not physical authenticity. A counterfeit
// manufacturer could copy a genuine componentID onto a fake part; scanning
// that copied ID would still return "registered" here, because this
// chaincode has no way to bind a digital record to the specific physical
// object in front of the scanner. The JSON fields are named accordingly.
func (s *SmartContract) ProvenanceCheck(ctx contractapi.TransactionContextInterface, componentID string) (string, error) {
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
	hasDeclaredParticipants := len(token.CoAttestingOrgs) >= minCoAttestingOrgs
	result := "SUSPECT"
	if hasDeclaredParticipants {
		result = "REGISTERED_WITH_DECLARED_PARTICIPANTS"
	}
	out, _ := json.Marshal(map[string]interface{}{
		"componentId":        componentID,
		"result":             result,
		"registeredOnLedger": true,
		"coAttestingOrgs":    token.CoAttestingOrgs,
		"lifecycleStatus":    token.Status,
		"recallStatus":       token.RecallStatus,
		"note":               "confirms ledger registration and a caller-declared co-attestation list only; CoAttestingOrgs is business data supplied by the submitting client, not cryptographic proof that those organisations endorsed anything, and this result does not by itself prove the physical item being scanned is the genuine, unaltered original",
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
//
// Overlapping campaigns: a product can be indexed under more than one batch
// (Section 3.3 / RecordAssembly). Before v3.5, a token already RECALLED
// under a different batch's still-open campaign could not have a second
// campaign tracked at all; this call only reported it as skippedOverlap and
// otherwise ignored it. As of v3.5, a genuinely different batchID opens its
// own independent RecallCampaign on the token, coexisting with any other
// open campaign, each later closeable/revocable/amendable on its own via
// its own batchID (CloseRecall/ReviseRecallReason/RevokeRecall). The only
// remaining no-op case is re-triggering the *same* batchID while its
// campaign is already open, which stays idempotent (openCampaignFor finds
// it and this call skips it without duplicating the campaign or resetting
// its OpenedAt/Reason).
func (s *SmartContract) TriggerRecall(ctx contractapi.TransactionContextInterface, batchID string, reason string) (string, error) {
	callerMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", err
	}
	if callerMSP != oemOrgMSP && callerMSP != regulatorOrgMSP {
		return "", fmt.Errorf("triggerRecall rejected: caller org must be OEM or Regulator, got %s", callerMSP)
	}
	if err := requireCallerOU(ctx, "admin"); err != nil {
		return "", fmt.Errorf("triggerRecall rejected: %v", err)
	}

	componentIDs, err := s.batchIndexMembers(ctx, batchID)
	if err != nil {
		return "", err
	}
	if len(componentIDs) == 0 {
		return "", fmt.Errorf("triggerRecall rejected: no components found for batch %s", batchID)
	}

	txID := ctx.GetStub().GetTxID()
	openedAt, err := txTimestamp(ctx)
	if err != nil {
		return "", err
	}

	affected := 0
	recalledIDs := make([]string, 0, len(componentIDs))
	ownerSet := map[string]bool{}
	for _, tokenID := range componentIDs {
		token, err := s.mustGetToken(ctx, tokenID)
		if err != nil {
			return "", err
		}
		if openCampaignFor(token, batchID) != nil {
			// This exact batch already has an open campaign on this token:
			// idempotent no-op, matching the pre-v3.5 repeated-recall
			// behaviour (Table 6's "Repeated recall / idempotency" case).
			continue
		}
		token.RecallCampaigns = append(token.RecallCampaigns, RecallCampaign{
			BatchID:  batchID,
			Reason:   reason,
			Status:   "RECALLED",
			OpenedAt: openedAt,
		})
		recomputeRecallStatus(token)
		if err := s.putToken(ctx, token, ""); err != nil {
			return "", err
		}
		// Notify whoever currently has the token: the dealer if it has
		// been delivered, otherwise the on-chain custodian organisation.
		// DealerID is caller-supplied business data, not an authenticated
		// identity, but it is the more useful notification target once a
		// product has left the channel's membership -- the JSON field name
		// (notifiedOwners) is unchanged for evidence-log compatibility.
		notifyTarget := token.CustodianMSP
		if token.DealerID != "" {
			notifyTarget = token.DealerID
		}
		ownerSet[notifyTarget] = true
		recalledIDs = append(recalledIDs, tokenID)
		affected++
	}

	owners := make([]string, 0, len(ownerSet))
	for o := range ownerSet {
		owners = append(owners, o)
	}
	sort.Strings(owners)
	sort.Strings(recalledIDs)

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
		"batchId":        batchID,
		"affectedCount":  affected,
		"notifiedOwners": owners,
		"txId":           txID,
	})
	return string(out), nil
}

// openCampaignFor returns the currently open (Status == RECALLED) campaign
// for batchID on this token, if any. An earlier, already-closed or revoked
// campaign for the same batchID (from a prior TriggerRecall/CloseRecall/
// RevokeRecall cycle) is left in RecallCampaigns as history and is not
// returned, so a fresh TriggerRecall for that batchID opens a new campaign
// entry rather than resurrecting the old one.
func openCampaignFor(token *ComponentToken, batchID string) *RecallCampaign {
	for i := range token.RecallCampaigns {
		if token.RecallCampaigns[i].BatchID == batchID && token.RecallCampaigns[i].Status == "RECALLED" {
			return &token.RecallCampaigns[i]
		}
	}
	return nil
}

// recomputeRecallStatus keeps the derived ComponentToken.RecallStatus field
// in sync with RecallCampaigns: RECALLED if any campaign is currently open,
// else "". Must be called after any function that mutates RecallCampaigns,
// so requireNotRecalled and ProvenanceCheck's single-field read stay
// correct without themselves inspecting the campaigns array.
func recomputeRecallStatus(token *ComponentToken) {
	for _, c := range token.RecallCampaigns {
		if c.Status == "RECALLED" {
			token.RecallStatus = "RECALLED"
			return
		}
	}
	token.RecallStatus = ""
}

// CloseRecall moves one token's campaign for batchID from RECALLED to a
// terminal resolution state (REPAIRED, REPLACED, or RETIRED). This
// resolution is recorded on that campaign, not on Status: the component's
// lifecycle status (e.g. DELIVERED) is left exactly as it was, since a
// recall and its resolution are events layered on top of the lifecycle, not
// replacements for it. The campaign's original Reason is left untouched;
// the resolution is appended to that campaign's own ReasonHistory. Since
// v3.5, batchID identifies which of a token's possibly several open
// campaigns this call resolves; a token with two independent open campaigns
// requires two separate CloseRecall calls, one per batchID.
//
// Restricted to OEM or Regulator, matching ReviseRecallReason and
// RevokeRecall: an earlier version had no caller-role check at all, so any
// enrolled participant, including one with no relationship to the recalled
// token, could resolve a safety recall.
func (s *SmartContract) CloseRecall(ctx contractapi.TransactionContextInterface, componentID string, batchID string, resolution string, note string, coAttestingOrgsCSV string) (string, error) {
	token, err := s.mustGetToken(ctx, componentID)
	if err != nil {
		return "", err
	}
	campaign := openCampaignFor(token, batchID)
	if campaign == nil {
		return "", fmt.Errorf("closeRecall rejected: token %s has no open recall campaign for batch %s", componentID, batchID)
	}
	if _, err := requireCallerIs(ctx, oemOrgMSP, regulatorOrgMSP); err != nil {
		return "", fmt.Errorf("closeRecall rejected: %v", err)
	}
	if err := requireCallerOU(ctx, "admin"); err != nil {
		return "", fmt.Errorf("closeRecall rejected: %v", err)
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
	campaign.Status = resolution
	campaign.ReasonHistory = append(campaign.ReasonHistory, fmt.Sprintf("CLOSED(%s): %s [tx:%s]", resolution, note, txID))
	recomputeRecallStatus(token)
	token.SubmittingOrgMSP = callerMSP
	token.CoAttestingOrgs = coAttestors
	if err := s.putToken(ctx, token, "RecallClosed"); err != nil {
		return "", err
	}
	out, _ := json.Marshal(map[string]interface{}{"componentId": componentID, "batchId": batchID, "lifecycleStatus": token.Status, "recallStatus": token.RecallStatus, "campaignStatus": resolution, "txId": txID})
	return string(out), nil
}

// ReviseRecallReason appends an amendment to a batch's open campaign on
// every token in it, without overwriting the original reason text. OEM or
// Regulator only. Since v3.5 this targets each token's campaign object
// (openCampaignFor), leaving any other, independent open campaign on the
// same token (a different batchID) untouched.
func (s *SmartContract) ReviseRecallReason(ctx contractapi.TransactionContextInterface, batchID string, amendedReason string) (string, error) {
	callerMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", err
	}
	if callerMSP != oemOrgMSP && callerMSP != regulatorOrgMSP {
		return "", fmt.Errorf("reviseRecallReason rejected: caller org must be OEM or Regulator, got %s", callerMSP)
	}
	if err := requireCallerOU(ctx, "admin"); err != nil {
		return "", fmt.Errorf("reviseRecallReason rejected: %v", err)
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
		campaign := openCampaignFor(token, batchID)
		if campaign == nil {
			// No open campaign for this exact batchID on this token: either
			// never recalled under it, or that campaign already closed/
			// revoked. Any other, independent open campaign on the same
			// token (a different batchID) is left untouched either way.
			continue
		}
		campaign.ReasonHistory = append(campaign.ReasonHistory, fmt.Sprintf("AMENDED by %s: %s [tx:%s]", callerMSP, amendedReason, txID))
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

// RevokeRecall marks REVOKED the campaign matching batchID on every token
// reachable from batchID's index entries, restoring visibility of whatever
// lifecycle status (Status) the token actually had, since that field was
// never touched by TriggerRecall in the first place. An earlier version of
// this chaincode instead overwrote Status with a generic ACTIVE value on
// revocation, silently destroying the information that the token had, for
// example, already been DELIVERED before the recall; this version cannot
// lose that information because recall and lifecycle are tracked in
// separate fields.
//
// The batchID match matters independently of that fix: a product can be
// indexed under more than one batch (Section 3.3), and since v3.5 may carry
// more than one simultaneously open campaign. Revoking batchID must not
// affect a different, independent campaign on the same token; openCampaignFor
// scopes the revocation to the one campaign whose BatchID matches. Unlike
// pre-v3.5, which cleared RecallBatchID and so lost the record of which
// batch had been revoked, the campaign object itself is kept (marked
// REVOKED, not deleted), so its BatchID, Reason, and full ReasonHistory
// remain on the ledger rather than only in a free-text ReasonHistory entry.
//
// This function is deliberately restricted to RegulatorMSP only (not the
// OEM), so the OEM cannot unilaterally cancel its own recall. The fact that
// a recall happened and was later revoked stays visible via the campaign's
// own ReasonHistory, RecallCampaigns, and GetHistory().
func (s *SmartContract) RevokeRecall(ctx contractapi.TransactionContextInterface, batchID string, justification string) (string, error) {
	callerMSP, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", err
	}
	if callerMSP != regulatorOrgMSP {
		return "", fmt.Errorf("revokeRecall rejected: caller org must be RegulatorMSP, got %s", callerMSP)
	}
	if err := requireCallerOU(ctx, "admin"); err != nil {
		return "", fmt.Errorf("revokeRecall rejected: %v", err)
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
		campaign := openCampaignFor(token, batchID)
		if campaign == nil {
			// No open campaign for this exact batchID: never recalled under
			// it, already resolved/revoked, or only recalled under a
			// different, independent campaign that this call has no
			// authority over (see the doc comment above).
			continue
		}
		campaign.Status = "REVOKED"
		campaign.ReasonHistory = append(campaign.ReasonHistory, fmt.Sprintf("REVOKED by %s: %s [tx:%s] (lifecycle status %s untouched)", callerMSP, justification, txID, token.Status))
		recomputeRecallStatus(token)
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

// requireNotRecalled blocks ordinary lifecycle-mutating functions
// (RecordTest, RecordShipment, RecordAssembly, RecordDelivery,
// RecordUsageLog) from operating on a token whose RecallStatus is
// currently RECALLED. This check exists precisely because RecallStatus and
// Status are now separate fields (see the ComponentToken doc comment): once
// a recall no longer overwrites Status, nothing else would otherwise stop a
// recalled component continuing to move through its ordinary lifecycle.
func requireNotRecalled(token *ComponentToken) error {
	if token.RecallStatus == "RECALLED" {
		return fmt.Errorf("invalid state transition: token %s is currently RECALLED (lifecycle status %s); resolve (CloseRecall) or revoke (RevokeRecall) the recall before recording further lifecycle events", token.TokenID, token.Status)
	}
	return nil
}

// requireHashLike performs a light sanity check that a client-supplied
// digest looks like a SHA-256 hex string (64 lowercase hex characters). It
// intentionally cannot verify the digest was actually computed from any
// particular document, since this chaincode never receives the document
// itself: the caller is expected to hash the off-chain report client-side
// and submit only the resulting digest (see RegisterComponent, RecordTest,
// and the on-chain/off-chain boundary discussion in the dissertation).
func requireHashLike(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("expected a 64-character SHA-256 hex digest, got length %d", len(s))
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return fmt.Errorf("expected lowercase hex characters only in the digest")
		}
	}
	return nil
}

// legacyOwnerToken decodes only the single field ("owner") that a
// pre-v3.3 ledger record used before CustodianMSP/InstalledInProductID/
// DealerID existed. It is consulted only as a read-time fallback (see
// mustGetToken); it never writes anything back to the ledger.
type legacyOwnerToken struct {
	Owner string `json:"owner"`
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
	if token.CustodianMSP == "" {
		// A record written before v3.3 has no "custodianMsp" key at all,
		// so json.Unmarshal leaves CustodianMSP at its zero value here
		// rather than an error -- Go does not rename json fields across
		// versions on its own. Fall back to decoding the legacy "owner"
		// key so the token can still be read and its custodian
		// identified, instead of silently treating it as ownerless. This
		// is read-time compatibility only, not a migration: the ledger
		// record itself is unchanged until the next write to this key,
		// at which point CustodianMSP is populated normally and this
		// fallback is no longer needed for it.
		//
		// This recovers the custodian correctly only for a legacy record
		// that was never assembled or delivered under the old design: if
		// "owner" had already been overwritten with a productID or
		// dealerID (the exact bug version 3.3 fixes), that overwritten
		// value is what gets read back here too, and it was already not
		// a usable MSP identity at the time it was written -- no
		// read-time fallback can recover information the old design had
		// already discarded.
		var legacy legacyOwnerToken
		if err := json.Unmarshal(bytes, &legacy); err == nil && legacy.Owner != "" {
			token.CustodianMSP = legacy.Owner
		}
	}
	if len(token.RecallCampaigns) == 0 && token.RecallBatchID != "" {
		// A record written before v3.5 has no "recallCampaigns" key at all,
		// so a legacy record still carrying a scalar RecallBatchID (i.e.
		// currently RECALLED or resolved-but-not-revoked -- a revoked
		// legacy record already had RecallBatchID cleared by the old
		// RevokeRecall) would otherwise appear to have no campaign history
		// at all. Synthesise one RecallCampaign from the legacy scalar
		// fields (Reason, ReasonHistory, RecallBatchID, RecallStatus)
		// instead. Unlike the CustodianMSP fallback above, this is not
		// purely read-time: CloseRecall/ReviseRecallReason/RevokeRecall all
		// write RecallCampaigns back through putToken, so the very next
		// recall-mutating call against this token naturally carries the
		// synthesised campaign forward onto the ledger.
		token.RecallCampaigns = []RecallCampaign{{
			BatchID:       token.RecallBatchID,
			Reason:        token.Reason,
			ReasonHistory: token.ReasonHistory,
			Status:        token.RecallStatus,
		}}
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
