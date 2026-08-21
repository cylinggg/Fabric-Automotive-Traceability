# Automotive Component Traceability on Hyperledger Fabric

Go chaincode, deployment scripts, and real-network evidence logs for an
MSc dissertation on permissioned-blockchain traceability for automotive
component supply chains (manufacture → test → shipment → assembly →
delivery → recall).

This code accompanies the dissertation *"A Permissioned Blockchain
Framework for Automotive Component Traceability: Chaincode Design and
Evaluation on a Local Hyperledger Fabric Test Network."* It is a research
prototype evaluated on a local, Docker-based Fabric test network, not a
production system. Organisation names are generic (`OEM`, `Tier1Supplier`,
`Tier2Supplier`, `Regulator`, `Dealer`) rather than tied to any named
manufacturer.

## What is actually in this repo

- `chaincode/component_traceability.go` — the full Go chaincode (Fabric
  Contract API v2). This is the hardened version described in the
  dissertation's Scenario Analysis and Methodology chapters:
  - Client-side hashing: `RegisterComponent`/`RecordTest` take a
    caller-computed SHA-256 hex digest (`testReportHash`), never the
    report text itself, so the report cannot leak through a transaction
    proposal (an earlier version hashed the full report text inside the
    chaincode).
  - Cross-batch product assembly: `RecordAssembly` no longer requires
    every component to share one batch. A product records every distinct
    batch its components were drawn from in `componentBatches` and is
    indexed under all of them, so a recall of *any* one of those batches
    still finds it (an earlier version rejected any assembly whose
    components spanned more than one batch, which does not represent a
    real automotive product built from multiple suppliers/batches).
  - Separate recall and lifecycle status: `status` is the lifecycle
    position only (MANUFACTURED…DELIVERED) and is never overwritten by a
    recall. `recallStatus` is a distinct field for RECALLED and its
    resolutions (REPAIRED/REPLACED/RETIRED); `RevokeRecall` clears
    `recallStatus` without ever touching `status` (an earlier version
    overwrote `status` with RECALLED and then reset it to a generic
    ACTIVE value on revocation, destroying whatever lifecycle stage —
    e.g. DELIVERED — the token had actually reached).
  - `ProvenanceCheck` (renamed from `CounterfeitScan`): the original name
    implied a stronger guarantee — physical authenticity — than the
    function actually verifies (ledger presence and declared
    co-attestation only).
  - Real `crypto/sha256` hashing, deterministic (sorted) co-attestation
    lists, a `batch~component` composite-key index instead of a CouchDB
    rich query inside `TriggerRecall`, a single aggregated event per
    transaction, and explicit state-transition / ownership checks on
    every lifecycle function, including a `requireNotRecalled` guard so a
    token under recall cannot continue moving through its ordinary
    lifecycle.
- `scripts/scenario_1_timing_lesson.sh` — the first real test run against
  a live 2-org Fabric test-network. Several steps in this run fail
  because `peer chaincode invoke` returns as soon as a transaction is
  submitted to the ordering service, not once it actually commits; the
  next dependent call in this script ran before the previous block had
  been cut. Kept deliberately as evidence of a genuine, undocumented
  operational lesson from testing against a real network rather than a
  simulator (see `evidence/real_fabric_run1_timing_lesson.log`).
- `scripts/scenario_2_full_lifecycle.sh` — the corrected run, with an
  explicit wait after every invoke, exercising the full lifecycle
  (register → test → ship → assemble → deliver), the ownership-cascade
  fix on delivery, batch recall, `CloseRecall`, and `ReviseRecallReason`.
  All transactions in this script are real, endorsed, committed Fabric
  transactions (see `evidence/real_fabric_run2_full_scenario.log`).
- `evidence/` — unedited console output of four separate runs, captured
  directly from `peer chaincode invoke`/`query` against a running
  network, not from any simulator: `real_fabric_run1_timing_lesson.log`
  and `real_fabric_run2_full_scenario.log` (the two-organisation
  lifecycle/recall runs above), `real_fabric_rename_verification.log` (a
  `RegisterComponent`/`GetComponent` pair confirming the chaincode still
  works after being repackaged and redeployed under this generic name),
  and `real_fabric_org3_regulator_scenario.log` (a third organisation,
  `Org3MSP`, added to the same network via `fabric-samples`' `addOrg3`,
  then a real regulator-triggered `TriggerRecall` and a real
  `RevokeRecall` invoked by `Org3MSP`, alongside the corresponding
  rejections when `Org2MSP`/`Org1MSP` attempt those same calls without
  authority).
- `chaincode/component_traceability_test.go` — Go unit tests (`go test
  ./...`, no Docker or live network required) covering the business logic
  that does not need a real peer to verify: real-SHA-256 hashing,
  duplicate-ID rejection, insufficient-co-attestation rejection, invalid
  state-transition rejection, deterministic sorted co-attestation
  ordering, unauthorised-caller rejection, unknown-batch rejection,
  cross-batch product assembly, a recall reaching a product via any one of
  its constituent batches, recall preserving lifecycle status, revoke
  restoring the original lifecycle status (not a generic placeholder), a
  recalled token being blocked from further lifecycle progression, and
  `ProvenanceCheck` distinguishing a registered token from an unknown one.
  These are unit tests against a hand-rolled in-memory fake of the
  `ChaincodeStubInterface`/`ClientIdentity` methods this chaincode
  actually calls; they check the same logic the real-network evidence in
  `evidence/` also exercises, but faster and without infrastructure. They
  do **not** replace that real-network evidence — a unit test cannot
  observe real multi-peer endorsement, MVCC conflicts, or the
  asynchronous-commit behaviour documented in `evidence/`.

  **A genuine gap was found and fixed while adding these tests, worth
  recording rather than quietly correcting**: the fake stub's composite-key
  emulation joined and split keys on a literal `~`, which collides with the
  `~` already inside this chaincode's own object-type constant
  (`batch~component`). Every existing test that exercised `TriggerRecall`
  only checked *rejection* paths, so this defect silently meant no unit
  test had ever exercised `TriggerRecall` actually finding and recalling a
  real token — only the genuine Fabric network (whose real composite-key
  encoding has no such collision) had ever exercised that path. The fake
  now uses a delimiter that cannot appear in ordinary object-type or
  attribute strings, matching Fabric's own approach, and the tests above
  now exercise the previously-blind path directly.
- `simulator/traceability-simulator.html` — the self-contained,
  browser-based JavaScript behavioural simulator referenced in the
  dissertation's Methodology chapter as historical/development-phase
  evidence (open the file directly in a browser; no build step or server
  required). Its results are superseded wherever both exist by the real
  Fabric evidence in `evidence/`.
- `simulator/simulator-demo-screenshot.pdf` — a screenshot of the
  simulator running in-browser: 12 `registerComponent` calls succeeding
  and one `triggerRecall` attempt from `Tier1SupplierMSP` being correctly
  rejected by the `OEM_MSP`/`RegulatorMSP`-only endorsement check.
- `network-config/README.md` — which parts of the deployment are the
  unmodified `fabric-samples/test-network`, the exact `peer lifecycle
  chaincode commit` invocation used, and an explicit note that this
  project relied on Fabric's default majority endorsement policy for a
  2-org channel rather than a hand-authored policy string (a plainly
  stated limitation, not glossed over).
- `couchdb-indexes/index-batchId-status.json` — the CouchDB index
  definition for ad hoc, read-only audit queries over `batchId`/`status`
  (in the standard `META-INF/statedb/couchdb/indexes/` chaincode-package
  location). `TriggerRecall` itself no longer depends on a CouchDB rich
  query (see the composite-key index discussion in the dissertation), but
  CouchDB remains the peer state database and this index keeps ad hoc
  dashboard-style queries efficient.

## What this repo does *not* include

- A packaged Fabric network (crypto material, `docker-compose` files,
  channel genesis artifacts). It was deployed against the standard 2-org
  `test-network` from
  [`hyperledger/fabric-samples`](https://github.com/hyperledger/fabric-samples),
  unmodified, started with `./network.sh up createChannel -s couchdb`;
  crypto material is generated fresh per deployment and is not something
  that should ever be committed to a repository.
- A packaged, ready-to-commit `RegulatorMSP` deployment bundle. The
  reference `test-network` starts with only two peer organisations
  (`Org1MSP`, `Org2MSP`); `Org3MSP` (the regulator role) was added
  afterwards using `fabric-samples`' standard `addOrg3` channel-update
  script, then installed and approved for the already-committed
  chaincode definition. That step is not automated in this repo, but the
  resulting real transactions, `Org3MSP` triggering a recall and
  invoking the `Org3MSP`-only `RevokeRecall`, are recorded in
  `evidence/real_fabric_org3_regulator_scenario.log`; see the
  dissertation's Scenario 5 for the walkthrough.

## Reproducing the evidence logs

```bash
# 1. Clone hyperledger/fabric-samples and start the 2-org test-network with CouchDB
cd fabric-samples/test-network
./network.sh up createChannel -c mychannel -s couchdb

# 2. Package, install, approve, and commit this chaincode (see the dissertation's
#    System Design chapter for the exact peer lifecycle chaincode commands used,
#    or adapt network.sh deployCC to point -ccp at chaincode/).

# 3. Run the scenario scripts, editing the paths at the top of each script to
#    match your local fabric-samples checkout.
./scripts/scenario_2_full_lifecycle.sh
```

## Chaincode functions

| Function | Endorsement | Purpose |
|---|---|---|
| `RegisterComponent` | ≥2 distinct orgs | Mint a new component token; rejects duplicate IDs; takes a client-computed SHA-256 hash of the report, not the report text |
| `RecordTest` | ≥2 distinct orgs; requires status `MANUFACTURED`; rejects if currently RECALLED | Commit client-hashed QC test-report digest; status → `QC_PASSED` |
| `RecordShipment` | ≥2 distinct orgs; requires status `QC_PASSED`, matching current owner, and not currently RECALLED | Transfer custody; status → `SHIPPED` |
| `RecordAssembly` | ≥2 distinct orgs; every listed component must be `SHIPPED` and not currently RECALLED (components may span multiple batches) | Combine components into a product token, recording every distinct constituent batch in `componentBatches`; status → `ASSEMBLED` |
| `RecordDelivery` | ≥2 distinct orgs; requires status `ASSEMBLED` and not currently RECALLED; cascades to every component | Final transfer to dealer; status → `DELIVERED` |
| `RecordUsageLog` | ≥2 distinct orgs; rejects if currently RECALLED | Attach field telemetry to a token |
| `WarrantyCheck` | Read-only | Apply a threshold rule to usage data |
| `ProvenanceCheck` (formerly `CounterfeitScan`) | Read-only | Verify ledger registration + declared co-attestation count (not physical authenticity) |
| `TriggerRecall` | Caller must be OEM or Regulator org | Batch-level recall via composite-key index; sets `recallStatus` (never touches lifecycle `status`); single aggregated event; a product is found via *any* of its constituent batches |
| `CloseRecall` | ≥2 distinct orgs; requires `recallStatus` = `RECALLED` | Resolve a recalled token's `recallStatus` to `REPAIRED`/`REPLACED`/`RETIRED`; lifecycle `status` is left untouched |
| `ReviseRecallReason` | Caller must be OEM or Regulator org | Append an amendment to a batch's recall reason without overwriting it |
| `RevokeRecall` | Caller must be Regulator org only | Clear a batch's `recallStatus` back to empty, restoring visibility of whatever lifecycle `status` the token actually had (not a generic placeholder) |
| `GetHistory` | Read-only | Full on-chain version history of a token (`GetHistoryForKey`) |

Every write function above that operates on an existing token also rejects
the call outright if that token's `recallStatus` is currently `RECALLED`
(`requireNotRecalled`), so a component under recall cannot continue moving
through its ordinary lifecycle while the recall is open.

## Licence

Code released for academic/educational reuse alongside the dissertation.
