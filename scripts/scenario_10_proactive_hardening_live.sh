#!/usr/bin/env bash
# Scenario 10 (FABRIC TEST-NETWORK): live-network test of the proactive
# caller-authorisation hardening added in v3.1, ahead of any further
# supervisor feedback. Deploys the current chaincode source as v3.1,
# sequence 6, then runs one genuine negative case per new check:
#   (a) RecordShipment to an unknown destination org
#   (b) RecordAssembly on a component the OEM does not actually hold
#   (c) RecordDelivery with an empty dealerID
#   (d) RegisterComponent declaring a fabricated co-attesting org
# plus a full authorised path proving nothing legitimate was broken.
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

# --- 1-5. One-time deployment (idempotent) ---
as_org 1 7051
ALREADY=$(peer lifecycle chaincode querycommitted -C mychannel -n component-traceability 2>&1 | grep -c "Version: 3.1, Sequence: 6")
if [ "$ALREADY" -ge 1 ]; then
  echo "=== 1-5. v3.1/sequence 6 already committed on this network; skipping package/install/approve/commit ==="
  peer lifecycle chaincode querycommitted -C mychannel -n component-traceability
else
  echo "=== 1. Package current chaincode source (proactive hardening) as v3.1 ==="
  mkdir -p /tmp/cc_package
  peer lifecycle chaincode package /tmp/cc_package/component-traceability_3.1.tar.gz \
    --path /Users/chenyuling/Desktop/論文/automotive-component-traceability-fabric/chaincode \
    --lang golang --label component-traceability_3.1
  PKGID=$(peer lifecycle chaincode calculatepackageid /tmp/cc_package/component-traceability_3.1.tar.gz)
  echo "Package ID: $PKGID"

  echo "=== 2. Install on Org1, Org2, Org3 ==="
  as_org 1 7051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.1.tar.gz
  as_org 2 9051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.1.tar.gz
  as_org 3 11051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.1.tar.gz

  echo "=== 3. Approve v3.1 sequence 6 for Org1, Org2, Org3 ==="
  as_org 1 7051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.1 --package-id "$PKGID" --sequence 6
  as_org 2 9051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.1 --package-id "$PKGID" --sequence 6
  as_org 3 11051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.1 --package-id "$PKGID" --sequence 6

  echo "=== 4. checkcommitreadiness ==="
  as_org 1 7051
  peer lifecycle chaincode checkcommitreadiness -C mychannel -n component-traceability -v 3.1 --sequence 6 --tls --cafile "$ORDERER_CA" --output json

  echo "=== 5. Commit v3.1 sequence 6 ==="
  peer lifecycle chaincode commit -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability \
    --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 --peerAddresses localhost:11051 --tlsRootCertFiles $P3 \
    -v 3.1 --sequence 6
  echo "=== querycommitted ==="
  peer lifecycle chaincode querycommitted -C mychannel -n component-traceability
fi

echo ""
echo "############################################################"
echo "### PART A: authorised happy path unaffected by the new checks ###"
echo "############################################################"
as_org 1 7051
echo "--- RegisterComponent AUTH2-HAPPY-1 (known co-attestor) ---"
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH2-HAPPY-1\",\"BATCH-AUTH2-HAPPY\",\"Tier2Supplier\",\"$(h "happy report")\",\"Org2MSP\"]}"
echo "--- RecordTest ---"
inv "{\"function\":\"RecordTest\",\"Args\":[\"AUTH2-HAPPY-1\",\"$(h "happy qc")\",\"Org2MSP\"]}"
echo "--- RecordShipment to a known org (Org1MSP) ---"
inv '{"function":"RecordShipment","Args":["AUTH2-HAPPY-1","Org1MSP","Org1MSP","Org2MSP"]}'
echo "--- AttachEvidence before delivery ---"
inv "{\"function\":\"AttachEvidence\",\"Args\":[\"AUTH2-HAPPY-1\",\"EV-AUTH2-HAPPY-1\",\"USAGE_REPORT\",\"$(h "happy evidence")\",\"Org1MSP\",\"repo://auth2-happy/1\",\"Org2MSP\"]}"
echo "--- RecordAssembly (OEM genuinely owns the component) ---"
inv '{"function":"RecordAssembly","Args":["AUTH2-HAPPY-PRODUCT-1","AUTH2-HAPPY-1","RECIPE-AUTH2","Org2MSP"]}'
echo "--- RecordDelivery with a real dealerID ---"
inv '{"function":"RecordDelivery","Args":["AUTH2-HAPPY-PRODUCT-1","Dealer1","Org2MSP"]}'
echo "--- RecordUsageLog (OEM, now DELIVERED) ---"
inv '{"function":"RecordUsageLog","Args":["AUTH2-HAPPY-1","90.0","Org2MSP"]}'

echo ""
echo "############################################################"
echo "### PART B: negative cases for the new proactive checks ###"
echo "############################################################"

echo "--- B1. RecordShipment to an unknown destination org -- expect rejection ---"
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH2-NEG-SHIP\",\"BATCH-AUTH2-NEG\",\"Tier2Supplier\",\"$(h "neg ship report")\",\"Org2MSP\"]}"
inv "{\"function\":\"RecordTest\",\"Args\":[\"AUTH2-NEG-SHIP\",\"$(h "neg ship qc")\",\"Org2MSP\"]}"
inv_noassert '{"function":"RecordShipment","Args":["AUTH2-NEG-SHIP","Org1MSP","NotARealOrg","Org2MSP"]}'

echo "--- B2. RecordAssembly on a component shipped laterally to Tier-1, not the OEM -- expect rejection ---"
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH2-NEG-ASM\",\"BATCH-AUTH2-NEG\",\"Tier2Supplier\",\"$(h "neg asm report")\",\"Org2MSP\"]}"
inv "{\"function\":\"RecordTest\",\"Args\":[\"AUTH2-NEG-ASM\",\"$(h "neg asm qc")\",\"Org2MSP\"]}"
inv '{"function":"RecordShipment","Args":["AUTH2-NEG-ASM","Org1MSP","Org2MSP","Org2MSP"]}'
inv_noassert '{"function":"RecordAssembly","Args":["AUTH2-NEG-ASM-PRODUCT","AUTH2-NEG-ASM","RECIPE-AUTH2-NEG","Org2MSP"]}'

echo "--- B3. RecordDelivery with an empty dealerID -- expect rejection ---"
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH2-NEG-DEL\",\"BATCH-AUTH2-NEG\",\"Tier2Supplier\",\"$(h "neg del report")\",\"Org2MSP\"]}"
inv "{\"function\":\"RecordTest\",\"Args\":[\"AUTH2-NEG-DEL\",\"$(h "neg del qc")\",\"Org2MSP\"]}"
inv '{"function":"RecordShipment","Args":["AUTH2-NEG-DEL","Org1MSP","Org1MSP","Org2MSP"]}'
inv '{"function":"RecordAssembly","Args":["AUTH2-NEG-DEL-PRODUCT","AUTH2-NEG-DEL","RECIPE-AUTH2-NEG","Org2MSP"]}'
inv_noassert '{"function":"RecordDelivery","Args":["AUTH2-NEG-DEL-PRODUCT","","Org2MSP"]}'

echo "--- B4. RegisterComponent declaring a fabricated co-attesting org -- expect rejection ---"
inv_noassert "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH2-NEG-COATT\",\"BATCH-AUTH2-NEG\",\"Tier2Supplier\",\"$(h "neg coatt report")\",\"FakeOrgXYZ\"]}"

echo ""
echo "=== DONE: Scenario 10 complete ==="
