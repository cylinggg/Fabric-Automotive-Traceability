#!/usr/bin/env bash
# Scenario 11: v3.2 client-role hardening. MSP membership is necessary but
# no longer sufficient for safety-critical calls: OU=admin is required.
set -uo pipefail
cd "/Users/chenyuling/Desktop/論文/fabric-samples/test-network"
export PATH=${PWD}/../bin:/opt/homebrew/bin:$PATH
export FABRIC_CFG_PATH=${PWD}/../config
export CORE_PEER_TLS_ENABLED=true
ORDERER_CA=${PWD}/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem
P1=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
P2=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
P3=${PWD}/organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt

as_admin() {
  local org=$1 port=$2
  export CORE_PEER_LOCALMSPID="Org${org}MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org${org}.example.com/peers/peer0.org${org}.example.com/tls/ca.crt
  export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org${org}.example.com/users/Admin@org${org}.example.com/msp
  export CORE_PEER_ADDRESS=localhost:${port}
}
as_org1_user() {
  export CORE_PEER_LOCALMSPID=Org1MSP
  export CORE_PEER_TLS_ROOTCERT_FILE=$P1
  export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp
  export CORE_PEER_ADDRESS=localhost:7051
}
as_org3_user() {
  export CORE_PEER_LOCALMSPID=Org3MSP
  export CORE_PEER_TLS_ROOTCERT_FILE=$P3
  export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org3.example.com/users/User1@org3.example.com/msp
  export CORE_PEER_ADDRESS=localhost:11051
}
invoke() {
  peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA" \
    -C mychannel -n component-traceability --peerAddresses localhost:7051 --tlsRootCertFiles "$P1" \
    --peerAddresses localhost:9051 --tlsRootCertFiles "$P2" --waitForEvent -c "$1" 2>&1
}
h() { printf '%s' "$1" | shasum -a 256 | awk '{print $1}'; }

as_admin 1 7051
echo "=== Package/install/approve/commit v3.2 sequence 7 ==="
mkdir -p /tmp/cc_package
PACKAGE=/tmp/cc_package/component-traceability_3.2.tar.gz
if [ ! -f "$PACKAGE" ]; then
  peer lifecycle chaincode package "$PACKAGE" \
    --path /Users/chenyuling/Desktop/論文/automotive-component-traceability-fabric/chaincode \
    --lang golang --label component-traceability_3.2
fi
PKGID=$(peer lifecycle chaincode calculatepackageid "$PACKAGE")
for spec in "1 7051" "2 9051" "3 11051"; do
  set -- $spec; as_admin "$1" "$2"
  peer lifecycle chaincode install "$PACKAGE" || true
  peer lifecycle chaincode approveformyorg -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
    --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability -v 3.2 --package-id "$PKGID" --sequence 7
done
as_admin 1 7051
peer lifecycle chaincode commit -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com \
  --tls --cafile "$ORDERER_CA" -C mychannel -n component-traceability \
  --peerAddresses localhost:7051 --tlsRootCertFiles "$P1" --peerAddresses localhost:9051 --tlsRootCertFiles "$P2" \
  --peerAddresses localhost:11051 --tlsRootCertFiles "$P3" -v 3.2 --sequence 7
peer lifecycle chaincode querycommitted -C mychannel -n component-traceability

echo "=== Recall role test: same MSP, ordinary client rejected ==="
invoke "{\"function\":\"RegisterComponent\",\"Args\":[\"ROLE-LIVE-1\",\"BATCH-ROLE-LIVE\",\"OEM\",\"$(h report)\",\"Org2MSP\"]}"
as_org1_user
invoke '{"function":"TriggerRecall","Args":["BATCH-ROLE-LIVE","ordinary client"]}' || true
as_admin 1 7051
invoke '{"function":"TriggerRecall","Args":["BATCH-ROLE-LIVE","admin recall"]}'
as_org1_user
invoke '{"function":"CloseRecall","Args":["ROLE-LIVE-1","REPAIRED","ordinary client","Org2MSP"]}' || true
invoke '{"function":"ReviseRecallReason","Args":["BATCH-ROLE-LIVE","ordinary client"]}' || true
as_org3_user
invoke '{"function":"RevokeRecall","Args":["BATCH-ROLE-LIVE","ordinary client"]}' || true
as_admin 1 7051
invoke '{"function":"CloseRecall","Args":["ROLE-LIVE-1","REPAIRED","admin close","Org2MSP"]}'

echo "=== Usage role test: delivered token, same MSP client rejected ==="
invoke "{\"function\":\"RegisterComponent\",\"Args\":[\"ROLE-LIVE-2\",\"BATCH-ROLE-LIVE-2\",\"OEM\",\"$(h report2)\",\"Org2MSP\"]}"
invoke "{\"function\":\"RecordTest\",\"Args\":[\"ROLE-LIVE-2\",\"$(h qc2)\",\"Org2MSP\"]}"
invoke '{"function":"RecordShipment","Args":["ROLE-LIVE-2","Org1MSP","Org1MSP","Org2MSP"]}'
invoke '{"function":"RecordAssembly","Args":["ROLE-LIVE-P2","ROLE-LIVE-2","ROLE-RECIPE-2","Org2MSP"]}'
invoke '{"function":"RecordDelivery","Args":["ROLE-LIVE-P2","Dealer1","Org2MSP"]}'
as_org1_user
invoke '{"function":"RecordUsageLog","Args":["ROLE-LIVE-2","88.0","Org2MSP"]}' || true
as_admin 1 7051
invoke '{"function":"RecordUsageLog","Args":["ROLE-LIVE-2","88.0","Org2MSP"]}'
echo "=== Scenario 11 complete ==="
