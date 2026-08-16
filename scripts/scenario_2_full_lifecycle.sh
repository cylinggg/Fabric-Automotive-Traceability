#!/usr/bin/env bash
set -uo pipefail
cd "/Users/chenyuling/Desktop/論文/fabric-samples/test-network"
export PATH=${PWD}/../bin:/opt/homebrew/bin:$PATH
export FABRIC_CFG_PATH=${PWD}/../config
export CORE_PEER_TLS_ENABLED=true
export ORDERER_CA=${PWD}/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem
P1=organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
P2=organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt

as_org1() {
  export CORE_PEER_LOCALMSPID="Org1MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt
  export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp
  export CORE_PEER_ADDRESS=localhost:7051
}

inv() {
  peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA" \
    -C mychannel -n component-traceability --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 \
    -c "$1" 2>&1
  sleep 3
}
qry() {
  peer chaincode query -C mychannel -n component-traceability -c "$1" 2>&1
}

as_org1

echo "### RUN2 STEP A: Register + fully cycle COMP-B1..COMP-B3 to SHIPPED (with proper commit wait) ###"
for i in 1 2 3; do
  echo "-- RegisterComponent COMP-B$i --"
  inv "{\"function\":\"RegisterComponent\",\"Args\":[\"COMP-B$i\",\"BATCH-B\",\"Tier2Supplier\",\"QC report B$i\",\"Org2MSP\"]}"
  echo "-- RecordTest COMP-B$i --"
  inv "{\"function\":\"RecordTest\",\"Args\":[\"COMP-B$i\",\"full QC pass B$i\",\"Org2MSP\"]}"
  echo "-- RecordShipment COMP-B$i --"
  inv "{\"function\":\"RecordShipment\",\"Args\":[\"COMP-B$i\",\"Tier2Supplier\",\"Tier1Supplier\",\"Org2MSP\"]}"
done

echo "### RUN2 STEP B: RecordAssembly PRODUCT-B (3 components, same batch) ###"
inv '{"function":"RecordAssembly","Args":["PRODUCT-B","COMP-B1,COMP-B2,COMP-B3","RECIPE-STD","Org2MSP"]}'

echo "-- QUERY PRODUCT-B --"
qry '{"function":"GetComponent","Args":["PRODUCT-B"]}'

echo "### RUN2 STEP C: RecordDelivery PRODUCT-B to DealerB (should cascade to all 3 components) ###"
inv '{"function":"RecordDelivery","Args":["PRODUCT-B","DealerB","Org2MSP"]}'

echo "-- QUERY COMP-B1 after delivery (expect owner=DealerB, status=DELIVERED) --"
qry '{"function":"GetComponent","Args":["COMP-B1"]}'
echo "-- QUERY COMP-B2 after delivery --"
qry '{"function":"GetComponent","Args":["COMP-B2"]}'
echo "-- QUERY COMP-B3 after delivery --"
qry '{"function":"GetComponent","Args":["COMP-B3"]}'

echo "### RUN2 STEP D: Negative - duplicate assembly (PRODUCT-B already exists) ###"
inv '{"function":"RecordAssembly","Args":["PRODUCT-B","COMP-B1,COMP-B2,COMP-B3","RECIPE-STD","Org2MSP"]}'

echo "### RUN2 STEP E: CloseRecall path - first recall BATCH-B, then close COMP-B1 ###"
inv '{"function":"TriggerRecall","Args":["BATCH-B","seatbelt tensioner fault"]}'
qry '{"function":"GetComponent","Args":["COMP-B1"]}'
inv '{"function":"CloseRecall","Args":["COMP-B1","REPAIRED","dealer repaired tensioner","Org2MSP"]}'
qry '{"function":"GetComponent","Args":["COMP-B1"]}'

echo "### RUN2 STEP F: ReviseRecallReason on BATCH-B (amend, not overwrite) ###"
inv '{"function":"ReviseRecallReason","Args":["BATCH-B","root cause confirmed as torque spec, not tensioner"]}'
qry '{"function":"GetComponent","Args":["COMP-B2"]}'

echo "### DONE RUN2 ###"
