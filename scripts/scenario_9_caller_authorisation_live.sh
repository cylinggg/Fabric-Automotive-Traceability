#!/usr/bin/env bash
# Scenario 9 (FABRIC TEST-NETWORK): live-network test of the caller-
# authorisation hardening requested in supervisor review. Deploys the
# current chaincode source as v3.0, sequence 5, then runs:
#   (a) a full authorised happy path across every affected function, and
#   (b) one genuine negative case per affected function, each submitted by
#       an enrolled organisation that is NOT authorised for that call, and
#       each expected to be rejected by requireCallerIsOwner/requireCallerIs
#       -- not by a caller-supplied business string, which is exactly the
#       gap this version fixes.
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
ALREADY=$(peer lifecycle chaincode querycommitted -C mychannel -n component-traceability 2>&1 | grep -c "Version: 3.0, Sequence: 5")
if [ "$ALREADY" -ge 1 ]; then
  echo "=== 1-5. v3.0/sequence 5 already committed on this network; skipping package/install/approve/commit ==="
  peer lifecycle chaincode querycommitted -C mychannel -n component-traceability
else
  echo "=== 1. Package current chaincode source (caller-authorisation hardening) as v3.0 ==="
  mkdir -p /tmp/cc_package
  peer lifecycle chaincode package /tmp/cc_package/component-traceability_3.0.tar.gz \
    --path /Users/chenyuling/Desktop/論文/automotive-component-traceability-fabric/chaincode \
    --lang golang --label component-traceability_3.0
  PKGID=$(peer lifecycle chaincode calculatepackageid /tmp/cc_package/component-traceability_3.0.tar.gz)
  echo "Package ID: $PKGID"

  echo "=== 2. Install on Org1, Org2, Org3 ==="
  as_org 1 7051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.0.tar.gz
  as_org 2 9051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.0.tar.gz
  as_org 3 11051; peer lifecycle chaincode install /tmp/cc_package/component-traceability_3.0.tar.gz

  echo "=== 3. Approve v3.0 sequence 5 for Org1, Org2, Org3 ==="
  as_org 1 7051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.0 --package-id "$PKGID" --sequence 5
  as_org 2 9051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.0 --package-id "$PKGID" --sequence 5
  as_org 3 11051
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.0 --package-id "$PKGID" --sequence 5

  echo "=== 4. checkcommitreadiness ==="
  as_org 1 7051
  peer lifecycle chaincode checkcommitreadiness -C mychannel -n component-traceability -v 3.0 --sequence 5 --tls --cafile "$ORDERER_CA" --output json

  echo "=== 5. Commit v3.0 sequence 5 ==="
  peer lifecycle chaincode commit -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability \
    --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 --peerAddresses localhost:11051 --tlsRootCertFiles $P3 \
    -v 3.0 --sequence 5
  echo "=== querycommitted ==="
  peer lifecycle chaincode querycommitted -C mychannel -n component-traceability
fi

echo ""
echo "############################################################"
echo "### PART A: authorised happy path (all calls as Org1MSP/OEM) ###"
echo "############################################################"
as_org 1 7051

echo "--- RegisterComponent AUTH-HAPPY-1 (as OEM) ---"
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH-HAPPY-1\",\"BATCH-AUTH-HAPPY\",\"Tier2Supplier\",\"$(h "happy report")\",\"Org2MSP\"]}"

echo "--- RecordTest AUTH-HAPPY-1 (as OEM, the current owner) ---"
inv "{\"function\":\"RecordTest\",\"Args\":[\"AUTH-HAPPY-1\",\"$(h "happy qc pass")\",\"Org2MSP\"]}"

echo "--- RecordShipment AUTH-HAPPY-1 (as OEM, the current owner) ---"
inv '{"function":"RecordShipment","Args":["AUTH-HAPPY-1","Org1MSP","Org1MSP","Org2MSP"]}'

echo "--- AttachEvidence on AUTH-HAPPY-1 (as OEM, the current owner; must run before RecordDelivery -- see note below) ---"
inv "{\"function\":\"AttachEvidence\",\"Args\":[\"AUTH-HAPPY-1\",\"EV-AUTH-HAPPY-1\",\"USAGE_REPORT\",\"$(h "happy evidence")\",\"Org1MSP\",\"repo://auth-happy/1\",\"Org2MSP\"]}"

echo "--- RecordAssembly AUTH-HAPPY-PRODUCT-1 (as OEM) ---"
inv '{"function":"RecordAssembly","Args":["AUTH-HAPPY-PRODUCT-1","AUTH-HAPPY-1","RECIPE-AUTH","Org2MSP"]}'

echo "--- RecordDelivery AUTH-HAPPY-PRODUCT-1 (as OEM, the current owner) ---"
inv '{"function":"RecordDelivery","Args":["AUTH-HAPPY-PRODUCT-1","Dealer1","Org2MSP"]}'

# NOTE ON ORDERING: AttachEvidence must run before RecordDelivery under this
# version's caller-authorisation design. requireCallerIsOwner compares the
# caller's MSP identity to token.Owner, and RecordDelivery sets Owner to a
# caller-supplied dealer label (e.g. "Dealer1") that is not a real MSP on
# this three-organisation network -- so no enrolled identity can ever equal
# it. Calling AttachEvidence after delivery is therefore rejected for every
# caller, not only unauthorised ones. This was discovered by first running
# this script with AttachEvidence placed after RecordDelivery (see
# evidence/real_fabric_run6_caller_authorisation.log) and is recorded as a
# limitation rather than silently worked around (Ch.7 Limitations).

echo "--- RecordUsageLog AUTH-HAPPY-1 (as OEM, now DELIVERED) ---"
inv '{"function":"RecordUsageLog","Args":["AUTH-HAPPY-1","91.5","Org2MSP"]}'

echo "--- WarrantyCheck AUTH-HAPPY-1 (query) ---"
qry '{"function":"WarrantyCheck","Args":["AUTH-HAPPY-1","85.0"]}'

echo "--- TriggerRecall BATCH-AUTH-HAPPY then CloseRecall AUTH-HAPPY-1 (both as OEM) ---"
inv '{"function":"TriggerRecall","Args":["BATCH-AUTH-HAPPY","precautionary check"]}'
inv '{"function":"CloseRecall","Args":["AUTH-HAPPY-1","REPAIRED","confirmed sound","Org2MSP"]}'

echo "--- ProvenanceCheck AUTH-HAPPY-1 (query): confirm new REGISTERED_WITH_DECLARED_PARTICIPANTS wording live ---"
qry '{"function":"ProvenanceCheck","Args":["AUTH-HAPPY-1"]}'

echo ""
echo "############################################################"
echo "### PART B: negative cases -- an enrolled but unauthorised org attempts each call ###"
echo "############################################################"

echo "--- B1. RegisterComponent as Regulator (Org3) -- expect rejection ---"
as_org 3 11051
inv_noassert "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH-NEG-REGISTER\",\"BATCH-AUTH-NEG\",\"Tier2Supplier\",\"$(h "neg report")\",\"Org1MSP\"]}"

echo "--- B2. RecordTest as Tier-1 (Org2) on a component owned by the OEM -- expect rejection ---"
as_org 1 7051
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH-NEG-TEST\",\"BATCH-AUTH-NEG\",\"Tier2Supplier\",\"$(h "neg test report")\",\"Org2MSP\"]}"
as_org 2 9051
inv_noassert "{\"function\":\"RecordTest\",\"Args\":[\"AUTH-NEG-TEST\",\"$(h "neg test qc")\",\"Org1MSP\"]}"

echo "--- B3. RecordShipment as Regulator (Org3) on a component owned by the OEM -- expect rejection ---"
as_org 1 7051
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH-NEG-SHIP\",\"BATCH-AUTH-NEG\",\"Tier2Supplier\",\"$(h "neg ship report")\",\"Org2MSP\"]}"
inv "{\"function\":\"RecordTest\",\"Args\":[\"AUTH-NEG-SHIP\",\"$(h "neg ship qc")\",\"Org2MSP\"]}"
as_org 3 11051
inv_noassert '{"function":"RecordShipment","Args":["AUTH-NEG-SHIP","Org1MSP","Org3MSP","Org2MSP"]}'

echo "--- B4. RecordAssembly as Tier-1 (Org2) -- expect rejection (OEM-only) ---"
as_org 1 7051
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH-NEG-ASM\",\"BATCH-AUTH-NEG\",\"Tier2Supplier\",\"$(h "neg asm report")\",\"Org2MSP\"]}"
inv "{\"function\":\"RecordTest\",\"Args\":[\"AUTH-NEG-ASM\",\"$(h "neg asm qc")\",\"Org2MSP\"]}"
inv '{"function":"RecordShipment","Args":["AUTH-NEG-ASM","Org1MSP","Org1MSP","Org2MSP"]}'
as_org 2 9051
inv_noassert '{"function":"RecordAssembly","Args":["AUTH-NEG-ASM-PRODUCT","AUTH-NEG-ASM","RECIPE-AUTH-NEG","Org1MSP"]}'

echo "--- B5. RecordDelivery as Tier-1 (Org2) on a product owned by the OEM -- expect rejection ---"
as_org 1 7051
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH-NEG-DEL\",\"BATCH-AUTH-NEG\",\"Tier2Supplier\",\"$(h "neg del report")\",\"Org2MSP\"]}"
inv "{\"function\":\"RecordTest\",\"Args\":[\"AUTH-NEG-DEL\",\"$(h "neg del qc")\",\"Org2MSP\"]}"
inv '{"function":"RecordShipment","Args":["AUTH-NEG-DEL","Org1MSP","Org1MSP","Org2MSP"]}'
inv '{"function":"RecordAssembly","Args":["AUTH-NEG-DEL-PRODUCT","AUTH-NEG-DEL","RECIPE-AUTH-NEG","Org2MSP"]}'
as_org 2 9051
inv_noassert '{"function":"RecordDelivery","Args":["AUTH-NEG-DEL-PRODUCT","Dealer1","Org1MSP"]}'

echo "--- B6. AttachEvidence as Regulator (Org3) on a component owned by the OEM -- expect rejection ---"
as_org 1 7051
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH-NEG-EVID\",\"BATCH-AUTH-NEG\",\"Tier2Supplier\",\"$(h "neg evid report")\",\"Org2MSP\"]}"
as_org 3 11051
inv_noassert "{\"function\":\"AttachEvidence\",\"Args\":[\"AUTH-NEG-EVID\",\"EV-AUTH-NEG\",\"QUALITY_TEST_REPORT\",\"$(h "neg evid doc")\",\"Org3MSP\",\"repo://x\",\"Org1MSP\"]}"

echo "--- B7. CloseRecall as Tier-1 (Org2) -- expect rejection (OEM/Regulator only) ---"
as_org 1 7051
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH-NEG-CLOSE\",\"BATCH-AUTH-NEG-CLOSE\",\"Tier2Supplier\",\"$(h "neg close report")\",\"Org2MSP\"]}"
inv '{"function":"TriggerRecall","Args":["BATCH-AUTH-NEG-CLOSE","test defect"]}'
as_org 2 9051
inv_noassert '{"function":"CloseRecall","Args":["AUTH-NEG-CLOSE","REPAIRED","attempted by wrong org","Org1MSP"]}'

echo "--- B8. RecordUsageLog as Tier-1 (Org2) on a DELIVERED component owned by the OEM -- expect rejection (wrong org) ---"
as_org 1 7051
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH-NEG-USAGE-ORG\",\"BATCH-AUTH-NEG\",\"Tier2Supplier\",\"$(h "neg usage org report")\",\"Org2MSP\"]}"
inv "{\"function\":\"RecordTest\",\"Args\":[\"AUTH-NEG-USAGE-ORG\",\"$(h "neg usage org qc")\",\"Org2MSP\"]}"
inv '{"function":"RecordShipment","Args":["AUTH-NEG-USAGE-ORG","Org1MSP","Org1MSP","Org2MSP"]}'
inv '{"function":"RecordAssembly","Args":["AUTH-NEG-USAGE-ORG-PRODUCT","AUTH-NEG-USAGE-ORG","RECIPE-AUTH-NEG","Org2MSP"]}'
inv '{"function":"RecordDelivery","Args":["AUTH-NEG-USAGE-ORG-PRODUCT","Dealer1","Org2MSP"]}'
as_org 2 9051
inv_noassert '{"function":"RecordUsageLog","Args":["AUTH-NEG-USAGE-ORG","90.0","Org1MSP"]}'

echo "--- B9. RecordUsageLog as OEM, but the component is not yet DELIVERED -- expect rejection (wrong status) ---"
as_org 1 7051
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"AUTH-NEG-USAGE-STATUS\",\"BATCH-AUTH-NEG\",\"Tier2Supplier\",\"$(h "neg usage status report")\",\"Org2MSP\"]}"
inv "{\"function\":\"RecordTest\",\"Args\":[\"AUTH-NEG-USAGE-STATUS\",\"$(h "neg usage status qc")\",\"Org2MSP\"]}"
inv_noassert '{"function":"RecordUsageLog","Args":["AUTH-NEG-USAGE-STATUS","90.0","Org2MSP"]}'

echo ""
echo "=== DONE: Scenario 9 complete ==="
