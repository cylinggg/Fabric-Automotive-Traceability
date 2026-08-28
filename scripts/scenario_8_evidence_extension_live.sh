#!/usr/bin/env bash
# Scenario 8 (FABRIC TEST-NETWORK): first live-network test of the
# EvidenceReference / AttachEvidence / GetEvidence extension. This
# chaincode was previously deployed only as v2.1 (sequence 3), which
# predates AttachEvidence in the source; the extension had been unit-tested
# only. This script repackages the *current* chaincode source (which
# includes AttachEvidence/GetEvidence) as v2.2, sequence 4, installs it on
# all three organisations, approves and commits it, then runs a real
# multi-evidence-reference attach/query sequence plus the two negative
# cases (duplicate evidence ID, malformed digest) against the live network.
set -uo pipefail
cd "/Users/chenyuling/Desktop/論文/fabric-samples/test-network"
export PATH=${PWD}/../bin:/opt/homebrew/bin:$PATH
export FABRIC_CFG_PATH=${PWD}/../config
export CORE_PEER_TLS_ENABLED=true
export ORDERER_CA=${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
P1=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
P2=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
P3=${PWD}/organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt

as_org() {
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
inv_noassert() {
  peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA" \
    -C mychannel -n component-traceability --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 \
    -c "$1" 2>&1
}
qry() {
  peer chaincode query -C mychannel -n component-traceability -c "$1" 2>&1
}
h() { printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; }

# Steps 1-5 are one-time deployment steps. They are made idempotent below
# (skipped if this peer set is already committed at v2.2/sequence 4) so a
# reader re-running this script after the first successful run sees a clean
# skip rather than confusing "already installed"/"already committed" errors.
as_org 1 7051
ALREADY=$(peer lifecycle chaincode querycommitted -C mychannel -n component-traceability 2>&1 | grep -c "Version: 2.2, Sequence: 4")
if [ "$ALREADY" -ge 1 ]; then
  echo "=== 1-5. v2.2/sequence 4 already committed on this network; skipping package/install/approve/commit ==="
  peer lifecycle chaincode querycommitted -C mychannel -n component-traceability
else
  echo "=== 1. Package current chaincode source (includes AttachEvidence/GetEvidence) as v2.2 ==="
  mkdir -p /tmp/cc_package
  peer lifecycle chaincode package /tmp/cc_package/component-traceability_2.2.tar.gz \
    --path /Users/chenyuling/Desktop/論文/automotive-component-traceability-fabric/chaincode \
    --lang golang --label component-traceability_2.2
  PKGID=$(peer lifecycle chaincode calculatepackageid /tmp/cc_package/component-traceability_2.2.tar.gz)
  echo "Package ID: $PKGID"

  echo "=== 2. Install on Org1, Org2, Org3 ==="
  as_org 1 7051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_2.2.tar.gz
  as_org 2 9051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_2.2.tar.gz
  as_org 3 11051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_2.2.tar.gz

  echo "=== 3. Approve v2.2 sequence 4 for Org1, Org2, Org3 ==="
  as_org 1 7051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 2.2 --package-id "$PKGID" --sequence 4
  as_org 2 9051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 2.2 --package-id "$PKGID" --sequence 4
  as_org 3 11051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 2.2 --package-id "$PKGID" --sequence 4

  echo "=== 4. checkcommitreadiness ==="
  as_org 1 7051
  peer lifecycle chaincode checkcommitreadiness -C mychannel -n component-traceability -v 2.2 --sequence 4 --tls --cafile "$ORDERER_CA" --output json

  echo "=== 5. Commit v2.2 sequence 4 ==="
  peer lifecycle chaincode commit -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability \
    --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 --peerAddresses localhost:11051 --tlsRootCertFiles $P3 \
    -v 2.2 --sequence 4
  echo "=== querycommitted ==="
  peer lifecycle chaincode querycommitted -C mychannel -n component-traceability
fi

echo ""
echo "=== 6. RegisterComponent EVID-TEST-002 (fresh token for this test) ==="
as_org 1 7051
TESTHASH=$(h "EVID-TEST-002 initial QC placeholder")
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"EVID-TEST-002\",\"BATCH-EVID-TEST\",\"Tier1Supplier\",\"$TESTHASH\",\"Org1MSP,Org2MSP\"]}"

echo ""
echo "=== 7. AttachEvidence #1: QC test report ==="
HASH1=$(h "QC test report for EVID-TEST-002, batch BATCH-EVID-TEST")
inv "{\"function\":\"AttachEvidence\",\"Args\":[\"EVID-TEST-002\",\"EV-QC-1\",\"QC_TEST_REPORT\",\"$HASH1\",\"Tier1SupplierMSP\",\"repo://tier1-docs/qc-reports/EVID-TEST-002.pdf\",\"Org1MSP,Org2MSP\"]}"

echo ""
echo "=== 8. AttachEvidence #2: shipping manifest (different evidence ID, same token) ==="
HASH2=$(h "Shipping manifest for EVID-TEST-002, dispatched to Dealer-Manchester")
inv "{\"function\":\"AttachEvidence\",\"Args\":[\"EVID-TEST-002\",\"EV-SHIP-1\",\"SHIPPING_MANIFEST\",\"$HASH2\",\"Tier1SupplierMSP\",\"repo://tier1-docs/manifests/EVID-TEST-002.pdf\",\"Org1MSP,Org2MSP\"]}"

echo ""
echo "=== 9. Negative case: duplicate evidence ID EV-QC-1 (expect rejection) ==="
DUPHASH=$(h "irrelevant duplicate attempt")
inv_noassert "{\"function\":\"AttachEvidence\",\"Args\":[\"EVID-TEST-002\",\"EV-QC-1\",\"QC_TEST_REPORT\",\"$DUPHASH\",\"Tier1SupplierMSP\",\"repo://x\",\"Org1MSP,Org2MSP\"]}"

echo ""
echo "=== 10. Negative case: malformed digest (expect rejection) ==="
inv_noassert "{\"function\":\"AttachEvidence\",\"Args\":[\"EVID-TEST-002\",\"EV-BAD-1\",\"QC_TEST_REPORT\",\"not-a-real-hash\",\"Tier1SupplierMSP\",\"repo://x\",\"Org1MSP,Org2MSP\"]}"

echo ""
echo "=== 11. GetEvidence (query): confirm both references retained ==="
qry '{"function":"GetEvidence","Args":["EVID-TEST-002"]}'
