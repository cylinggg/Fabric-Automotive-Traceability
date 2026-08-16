# Automotive Component Traceability on Hyperledger Fabric

Go chaincode, deployment scripts, and real-network evidence logs for an
MSc dissertation on permissioned-blockchain traceability for automotive
component supply chains (manufacture → test → shipment → assembly →
delivery → recall).

This code accompanies the dissertation *"A Permissioned Blockchain
Framework for Automotive Component Traceability: Chaincode Design and
Evaluation Using Hyperledger Fabric."* It is a research prototype, not a
production system. Organisation names are generic (`OEM`, `Tier1Supplier`,
`Tier2Supplier`, `Regulator`, `Dealer`) rather than tied to any named
manufacturer.

## What is actually in this repo

- `chaincode/component_traceability.go` — the full Go chaincode (Fabric
  Contract API v2). This is the fixed version described in the
  dissertation's Scenario Analysis: real `crypto/sha256` hashing,
  deterministic (sorted) co-attestation lists, a `batch~component`
  composite-key index instead of a CouchDB rich query inside
  `TriggerRecall`, a single aggregated event per transaction, and
  explicit state-transition / ownership checks on every lifecycle
  function.
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
- `evidence/` — unedited console output of both runs above, captured
  directly from `peer chaincode invoke`/`query` against a running
  network (org peers, orderer, and two CouchDB instances), not from any
  simulator.
- `chaincode/component_traceability_test.go` — Go unit tests (`go test
  ./...`, no Docker or live network required) covering the business logic
  that does not need a real peer to verify: real-SHA-256 hashing,
  duplicate-ID rejection, insufficient-co-attestation rejection, invalid
  state-transition rejection, deterministic sorted co-attestation
  ordering, unauthorised-caller rejection, and unknown-batch rejection.
  These are unit tests against a hand-rolled in-memory fake of the
  `ChaincodeStubInterface`/`ClientIdentity` methods this chaincode
  actually calls; they check the same logic the real-network evidence in
  `evidence/` also exercises, but faster and without infrastructure. They
  do **not** replace that real-network evidence — a unit test cannot
  observe real multi-peer endorsement, MVCC conflicts, or the
  asynchronous-commit behaviour documented in `evidence/`.
- `simulator/traceability-simulator.html` — the self-contained,
  browser-based JavaScript behavioural simulator referenced in the
  dissertation's Methodology chapter as historical/development-phase
  evidence (open the file directly in a browser; no build step or server
  required). Its results are superseded wherever both exist by the real
  Fabric evidence in `evidence/`.
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
- A `RegulatorMSP` organisation. The reference `test-network` only
  provisions two peer organisations (`Org1MSP`, `Org2MSP`); the chaincode
  assigns `Org1MSP` the OEM role and reserves `Org3MSP` for a regulator
  role that was never deployed. Functions gated to `Org3MSP` only
  (`RevokeRecall`) are implemented and unit-tested but were not
  exercised against a live network in this evidence set — see the
  dissertation's Scenario Analysis and Limitations for the honest
  real/not-yet-tested split.

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
| `RegisterComponent` | ≥2 distinct orgs | Mint a new component token; rejects duplicate IDs |
| `RecordTest` | ≥2 distinct orgs; requires status `MANUFACTURED` | Commit QC test-report hash; status → `QC_PASSED` |
| `RecordShipment` | ≥2 distinct orgs; requires status `QC_PASSED` and matching current owner | Transfer custody; status → `SHIPPED` |
| `RecordAssembly` | ≥2 distinct orgs; every listed component must be `SHIPPED` and share one batch | Combine components into a product token; status → `ASSEMBLED` |
| `RecordDelivery` | ≥2 distinct orgs; requires status `ASSEMBLED`; cascades to every component | Final transfer to dealer; status → `DELIVERED` |
| `RecordUsageLog` | ≥2 distinct orgs | Attach field telemetry to a token |
| `WarrantyCheck` | Read-only | Apply a threshold rule to usage data |
| `CounterfeitScan` | Read-only | Verify ledger registration + co-attestation count (not physical authenticity) |
| `TriggerRecall` | Caller must be OEM or Regulator org | Batch-level recall via composite-key index; single aggregated event |
| `CloseRecall` | ≥2 distinct orgs; requires status `RECALLED` | Resolve a recalled token to `REPAIRED`/`REPLACED`/`RETIRED` |
| `ReviseRecallReason` | Caller must be OEM or Regulator org | Append an amendment to a batch's recall reason without overwriting it |
| `RevokeRecall` | Caller must be Regulator org only | Revert a batch's `RECALLED` tokens to `ACTIVE` |
| `GetHistory` | Read-only | Full on-chain version history of a token (`GetHistoryForKey`) |

## Licence

Code released for academic/educational reuse alongside the dissertation.
