#!/usr/bin/env bash
# Scenario 13 (FABRIC TEST-NETWORK): live-network test of two items
# identified as untested/unimplemented immediately after v3.3 shipped.
#   PART A: read-time compatibility for pre-v3.3 legacy records (v3.4,
#     sequence 9), verified against a GENUINE legacy record still on this
#     network's real ledger (AUTH-NEG-TEST, registered under v3.0 in
#     Scenario 9, long before CustodianMSP existed) -- not a synthetic one.
#   PART B: insufficient peer endorsement, submitting a transaction with
#     only one organisation's peer address when the committed policy
#     requires more, confirming Fabric rejects it before this chaincode
#     ever runs.
set -uo pipefail
cd "/Users/chenyuling/Desktop/論文/fabric-samples/test-network"
export PATH=${PWD}/../bin:/opt/homebrew/bin:$PATH
export FABRIC_CFG_PATH=${PWD}/../config
export CORE_PEER_TLS_ENABLED=true
export ORDERER_CA=${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
P1=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
P2=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
P3=${PWD}/organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt

as_admin() {
  ORG=$1; PORT=$2
  export CORE_PEER_LOCALMSPID="Org${ORG}MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org${ORG}.example.com/peers/peer0.org${ORG}.example.com/tls/ca.crt
  export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org${ORG}.example.com/users/Admin@org${ORG}.example.com/msp
  export CORE_PEER_ADDRESS=localhost:${PORT}
}

inv() {
  peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA" \
    -C mychannel -n component-traceability --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 \
    --waitForEvent -c "$1" 2>&1
}
qry() {
  peer chaincode query -C mychannel -n component-traceability -c "$1" 2>&1
}
h() { printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; }

# --- 1-5. One-time deployment (idempotent) ---
as_admin 1 7051
ALREADY=$(peer lifecycle chaincode querycommitted -C mychannel -n component-traceability 2>&1 | grep -c "Version: 3.4, Sequence: 9")
if [ "$ALREADY" -ge 1 ]; then
  echo "=== 1-5. v3.4/sequence 9 already committed on this network; skipping package/install/approve/commit ==="
  peer lifecycle chaincode querycommitted -C mychannel -n component-traceability
else
  echo "=== 1. Package current chaincode source (legacy compatibility) as v3.4 ==="
  mkdir -p /tmp/cc_package
  peer lifecycle chaincode package /tmp/cc_package/component-traceability_3.4.tar.gz \
    --path /Users/chenyuling/Desktop/論文/automotive-component-traceability-fabric/chaincode \
    --lang golang --label component-traceability_3.4
  PKGID=$(peer lifecycle chaincode calculatepackageid /tmp/cc_package/component-traceability_3.4.tar.gz)
  echo "Package ID: $PKGID"

  echo "=== 2. Install on Org1, Org2, Org3 ==="
  as_admin 1 7051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.4.tar.gz
  as_admin 2 9051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.4.tar.gz
  as_admin 3 11051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.4.tar.gz

  echo "=== 3. Approve v3.4 sequence 9 for Org1, Org2, Org3 ==="
  as_admin 1 7051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.4 --package-id "$PKGID" --sequence 9
  as_admin 2 9051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.4 --package-id "$PKGID" --sequence 9
  as_admin 3 11051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.4 --package-id "$PKGID" --sequence 9

  echo "=== 4. checkcommitreadiness ==="
  as_admin 1 7051
  peer lifecycle chaincode checkcommitreadiness -C mychannel -n component-traceability -v 3.4 --sequence 9 --tls --cafile "$ORDERER_CA" --output json

  echo "=== 5. Commit v3.4 sequence 9 ==="
  peer lifecycle chaincode commit -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability \
    --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 --peerAddresses localhost:11051 --tlsRootCertFiles $P3 \
    -v 3.4 --sequence 9
  echo "=== querycommitted ==="
  peer lifecycle chaincode querycommitted -C mychannel -n component-traceability
fi

as_admin 1 7051

echo ""
echo "############################################################"
echo "### PART A: legacy-record read compatibility, against a GENUINE pre-v3.3 record ###"
echo "############################################################"
echo "--- GetComponent AUTH-NEG-TEST: a real component registered under v3.0 in Scenario 9, ---"
echo "--- long before CustodianMSP existed, never assembled or delivered since. ---"
qry '{"function":"GetComponent","Args":["AUTH-NEG-TEST"]}'
echo "--- AttachEvidence on AUTH-NEG-TEST as its real original registrant (Org1MSP) -- should now succeed via legacy fallback ---"
inv "{\"function\":\"AttachEvidence\",\"Args\":[\"AUTH-NEG-TEST\",\"EV-LEGACY-REAL\",\"QUALITY_TEST_REPORT\",\"$(h "legacy real evidence")\",\"Org1MSP\",\"repo://legacy-real\",\"Org2MSP\"]}"
echo "--- GetComponent AUTH-NEG-TEST again: confirm custodianMsp now recovered and evidence attached ---"
qry '{"function":"GetComponent","Args":["AUTH-NEG-TEST"]}'

echo ""
echo "############################################################"
echo "### PART B: insufficient peer endorsement ###"
echo "############################################################"
echo "--- Register a fresh component with only ONE organisation's peer address (policy requires more) ---"
peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA" \
  -C mychannel -n component-traceability --peerAddresses localhost:7051 --tlsRootCertFiles $P1 \
  --waitForEvent -c "{\"function\":\"RegisterComponent\",\"Args\":[\"INSUFFICIENT-ENDORSE-1\",\"BATCH-INSUFFICIENT\",\"Tier2Supplier\",\"$(h "insufficient endorse report")\",\"Org2MSP\"]}" 2>&1 || true
echo "--- Confirm the component was NOT created (query should fail: no state committed) ---"
qry '{"function":"GetComponent","Args":["INSUFFICIENT-ENDORSE-1"]}' || true

echo ""
echo "=== DONE: Scenario 13 complete ==="
