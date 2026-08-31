#!/usr/bin/env bash
# Scenario 12 (FABRIC TEST-NETWORK): live-network test of the
# CustodianMSP/InstalledInProductID/DealerID field separation (v3.3,
# sequence 8), prompted by supervisor review of the single, overloaded
# Owner field. Deploys the current chaincode source as v3.3, sequence 8,
# then proves the two failure modes that field separation fixes:
#   (a) AttachEvidence on an assembled-but-undelivered component
#   (b) AttachEvidence after RecordDelivery (a documented limitation as of
#       Scenario 9/v3.0)
# both of which previously failed for every possible caller because the
# single Owner field had been overwritten with a non-MSP value.
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
ALREADY=$(peer lifecycle chaincode querycommitted -C mychannel -n component-traceability 2>&1 | grep -c "Version: 3.3, Sequence: 8")
if [ "$ALREADY" -ge 1 ]; then
  echo "=== 1-5. v3.3/sequence 8 already committed on this network; skipping package/install/approve/commit ==="
  peer lifecycle chaincode querycommitted -C mychannel -n component-traceability
else
  echo "=== 1. Package current chaincode source (custodian field separation) as v3.3 ==="
  mkdir -p /tmp/cc_package
  peer lifecycle chaincode package /tmp/cc_package/component-traceability_3.3.tar.gz \
    --path /Users/chenyuling/Desktop/論文/automotive-component-traceability-fabric/chaincode \
    --lang golang --label component-traceability_3.3
  PKGID=$(peer lifecycle chaincode calculatepackageid /tmp/cc_package/component-traceability_3.3.tar.gz)
  echo "Package ID: $PKGID"

  echo "=== 2. Install on Org1, Org2, Org3 ==="
  as_admin 1 7051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.3.tar.gz
  as_admin 2 9051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.3.tar.gz
  as_admin 3 11051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.3.tar.gz

  echo "=== 3. Approve v3.3 sequence 8 for Org1, Org2, Org3 ==="
  as_admin 1 7051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.3 --package-id "$PKGID" --sequence 8
  as_admin 2 9051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.3 --package-id "$PKGID" --sequence 8
  as_admin 3 11051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.3 --package-id "$PKGID" --sequence 8

  echo "=== 4. checkcommitreadiness ==="
  as_admin 1 7051
  peer lifecycle chaincode checkcommitreadiness -C mychannel -n component-traceability -v 3.3 --sequence 8 --tls --cafile "$ORDERER_CA" --output json

  echo "=== 5. Commit v3.3 sequence 8 ==="
  peer lifecycle chaincode commit -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability \
    --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 --peerAddresses localhost:11051 --tlsRootCertFiles $P3 \
    -v 3.3 --sequence 8
  echo "=== querycommitted ==="
  peer lifecycle chaincode querycommitted -C mychannel -n component-traceability
fi

as_admin 1 7051

echo ""
echo "############################################################"
echo "### PART A: AttachEvidence on an assembled-but-undelivered component ###"
echo "############################################################"
echo "--- RegisterComponent, RecordTest, RecordShipment, RecordAssembly CUST-1 ---"
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"CUST-1\",\"BATCH-CUST\",\"Tier2Supplier\",\"$(h "cust1 report")\",\"Org2MSP\"]}"
inv "{\"function\":\"RecordTest\",\"Args\":[\"CUST-1\",\"$(h "cust1 qc")\",\"Org2MSP\"]}"
inv '{"function":"RecordShipment","Args":["CUST-1","Org1MSP","Org1MSP","Org2MSP"]}'
inv '{"function":"RecordAssembly","Args":["CUST-PRODUCT-1","CUST-1","RECIPE-CUST-1","Org2MSP"]}'
echo "--- GetComponent CUST-1: confirm custodianMsp unchanged, installedInProductId set ---"
qry '{"function":"GetComponent","Args":["CUST-1"]}'
echo "--- AttachEvidence on CUST-1 (assembled, not yet delivered) -- should now SUCCEED ---"
inv "{\"function\":\"AttachEvidence\",\"Args\":[\"CUST-1\",\"EV-CUST-1\",\"QUALITY_TEST_REPORT\",\"$(h "cust1 evidence")\",\"Org1MSP\",\"repo://cust1\",\"Org2MSP\"]}"

echo ""
echo "############################################################"
echo "### PART B: AttachEvidence after RecordDelivery (previously a documented limitation) ###"
echo "############################################################"
echo "--- Complete delivery of CUST-PRODUCT-1 ---"
inv '{"function":"RecordDelivery","Args":["CUST-PRODUCT-1","Dealer1","Org2MSP"]}'
echo "--- GetComponent CUST-1: confirm custodianMsp STILL unchanged, dealerId now set ---"
qry '{"function":"GetComponent","Args":["CUST-1"]}'
echo "--- AttachEvidence on CUST-1 (delivered) -- should now SUCCEED (was blocked in Scenario 9) ---"
inv "{\"function\":\"AttachEvidence\",\"Args\":[\"CUST-1\",\"EV-CUST-1-POSTDELIVERY\",\"USAGE_REPORT\",\"$(h "cust1 post-delivery evidence")\",\"Org1MSP\",\"repo://cust1-post\",\"Org2MSP\"]}"
echo "--- RecordUsageLog on CUST-1 (delivered; CustodianMSP-based check, no longer a hardcoded role) ---"
inv '{"function":"RecordUsageLog","Args":["CUST-1","91.0","Org2MSP"]}'
echo "--- GetEvidence CUST-1: confirm both evidence references retained ---"
qry '{"function":"GetEvidence","Args":["CUST-1"]}'

echo ""
echo "=== DONE: Scenario 12 complete ==="
