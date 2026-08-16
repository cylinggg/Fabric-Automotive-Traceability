# Network and Endorsement-Policy Configuration

This project deploys against the **unmodified** `test-network` from
[`hyperledger/fabric-samples`](https://github.com/hyperledger/fabric-samples)
(2 peer organisations, `Org1MSP` and `Org2MSP`, one Raft orderer node), so
the channel-genesis, MSP, and crypto-material configuration is not
reproduced here; it is exactly the standard `fabric-samples/test-network`
output of:

```bash
cd fabric-samples/test-network
./network.sh up createChannel -c mychannel -s couchdb
```

The `-s couchdb` flag is required: without it the peers run LevelDB and
`GetStateByPartialCompositeKey` still works (composite keys don't need
CouchDB), but the read-only audit queries this project's CouchDB index
(`../couchdb-indexes/index-batchId-status.json`) supports would not.

## Chaincode-level endorsement policy actually used

The commit in this project's evidence log did **not** pass an explicit
`--signature-policy` or `--channel-config-policy` flag to
`peer lifecycle chaincode commit`:

```bash
peer lifecycle chaincode commit -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA" \
  --channelID mychannel --name component-traceability --version 1.0 --sequence 1 \
  --peerAddresses localhost:7051 --tlsRootCertFiles <org1-tls-ca> \
  --peerAddresses localhost:9051 --tlsRootCertFiles <org2-tls-ca>
```

Omitting `--signature-policy` means Fabric falls back to its **implicit
majority policy** for the chaincode's currently-approved organisations,
confirmed by `peer lifecycle chaincode querycommitted`:

```
Committed chaincode definition for chaincode 'component-traceability' on channel 'mychannel':
Version: 1.0, Sequence: 1, Endorsement Plugin: escc, Validation Plugin: vscc,
Approvals: [Org1MSP: true, Org2MSP: true]
```

The chaincode was originally committed under an internal working name
(`honda`, version 2.0, sequence 5) before generic naming was adopted for
the public dissertation and repository; it was formally redeployed under
this generic name (a genuine new install/approve/commit cycle on the same
live network, not a text relabelling) on 16 August 2026, verified by a
real `RegisterComponent`/`GetComponent` invoke-and-query pair recorded in
`evidence/real_fabric_rename_verification.log`.

With two organisations, majority means both must endorse, which is
consistent with this dissertation's stated design requirement of
"endorsement from at least two distinct organisations" for ordinary
writes (Section III-E / III-F), but it is worth being explicit that this
was Fabric's default behaviour for a 2-org channel, not a hand-authored
policy string. A production deployment implementing the dissertation's
distinct rule for `TriggerRecall` (OEM or Regulator only, rather than
"majority of all channel members") would need an explicit **state-based
endorsement policy** set via `SetStateValidationParameter` on the
relevant keys, or a separate chaincode-level policy applied only to that
function's key namespace; this project's `TriggerRecall` caller check is
enforced only in application code (`GetClientIdentity().GetMSPID()`
inside the chaincode), not at the channel-policy level, exactly as
documented as a limitation in the dissertation (Section VI-C).

## What is not included

- Crypto material (MSP certificates, TLS certificates) — generated fresh
  per-deployment by `fabric-samples/test-network`'s `cryptogen`/Fabric CA
  scripts, not committed to any repository for obvious security reasons.
- A third `Org3MSP` (Regulator) network definition — never deployed in
  this evaluation; see the dissertation's Limitations section.
