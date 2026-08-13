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
as_org2() {
  export CORE_PEER_LOCALMSPID="Org2MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt
  export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org2.example.com/users/Admin@org2.example.com/msp
  export CORE_PEER_ADDRESS=localhost:9051
}

inv() {
  peer chaincode invoke -o localhost:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORDERER_CA" \
    -C mychannel -n honda --peerAddresses localhost:7051 --tlsRootCertFiles $P1 --peerAddresses localhost:9051 --tlsRootCertFiles $P2 \
    -c "$1" 2>&1
  sleep 0.6
}
qry() {
  peer chaincode query -C mychannel -n honda -c "$1" 2>&1
}

as_org1

echo "### STEP 1: Register target batch BATCH-T (5 components) ###"
for i in 1 2 3 4 5; do
  echo "-- RegisterComponent COMP-T$i --"
  inv "{\"function\":\"RegisterComponent\",\"Args\":[\"COMP-T$i\",\"BATCH-T\",\"Tier2Supplier\",\"QC report T$i\",\"Org2MSP\"]}"
done

echo "### STEP 2: Register control batch BATCH-C (3 components, should NOT be recalled) ###"
for i in 1 2 3; do
  echo "-- RegisterComponent COMP-C$i --"
  inv "{\"function\":\"RegisterComponent\",\"Args\":[\"COMP-C$i\",\"BATCH-C\",\"Tier2Supplier\",\"QC report C$i\",\"Org2MSP\"]}"
done

echo "### STEP 3: Full lifecycle for COMP-T1 -> RecordTest -> RecordShipment -> assemble -> deliver ###"
inv '{"function":"RecordTest","Args":["COMP-T1","full QC pass report","Org2MSP"]}'
inv '{"function":"RecordShipment","Args":["COMP-T1","Tier2Supplier","Tier1Supplier","Org2MSP"]}'

echo "-- RecordAssembly should REJECT (component still SHIPPED not the issue; but only 1 comp, status SHIPPED expected pass) --"
inv '{"function":"RecordAssembly","Args":["PRODUCT-V1","COMP-T1","RECIPE-STD","Org2MSP"]}'

echo "-- RecordDelivery PRODUCT-V1 to DealerA (should cascade to COMP-T1) --"
inv '{"function":"RecordDelivery","Args":["PRODUCT-V1","DealerA","Org2MSP"]}'

echo "-- QUERY COMP-T1 after delivery (owner/status should now be DealerA/DELIVERED, proving cascade fix) --"
qry '{"function":"GetComponent","Args":["COMP-T1"]}'

echo "### STEP 4: Negative case - RecordAssembly on a component that is NOT SHIPPED (COMP-T2 is still MANUFACTURED) ###"
inv '{"function":"RecordAssembly","Args":["PRODUCT-BAD","COMP-T2","RECIPE-STD","Org2MSP"]}'

echo "### STEP 5: Negative case - RecordShipment with wrong fromOwner ###"
inv '{"function":"RecordTest","Args":["COMP-T3","QC pass","Org2MSP"]}'
inv '{"function":"RecordShipment","Args":["COMP-T3","WrongOwner","Tier1Supplier","Org2MSP"]}'

echo "### STEP 6: Warranty scenario - usage log + check (two cases) ###"
inv '{"function":"RecordTest","Args":["COMP-T4","QC pass","Org2MSP"]}'
inv '{"function":"RecordUsageLog","Args":["COMP-T4","92.0","Org2MSP"]}'
qry '{"function":"WarrantyCheck","Args":["COMP-T4","85.0"]}'
inv '{"function":"RecordUsageLog","Args":["COMP-T5","78.0","Org2MSP"]}'
echo "-- expect fail: COMP-T5 never RegisterComponent'd test/usage before check consistency n/a --"
qry '{"function":"WarrantyCheck","Args":["COMP-T5","85.0"]}'

echo "### STEP 7: CounterfeitScan - genuine vs fabricated ID ###"
qry '{"function":"CounterfeitScan","Args":["COMP-T1"]}'
qry '{"function":"CounterfeitScan","Args":["COMP-FAKE-9999"]}'

echo "### STEP 8: Negative case - unauthorized TriggerRecall caller (Org2 = Tier1Supplier, not OEM/Regulator) ###"
as_org2
inv '{"function":"TriggerRecall","Args":["BATCH-T","unauthorized attempt"]}'

echo "### STEP 9: Authorized TriggerRecall by Org1 (OEM) on BATCH-T only ###"
as_org1
inv '{"function":"TriggerRecall","Args":["BATCH-T","engine mount torque spec deviation"]}'

echo "### STEP 10: Verify control batch BATCH-C untouched ###"
for i in 1 2 3; do
  qry "{\"function\":\"GetComponent\",\"Args\":[\"COMP-C$i\"]}"
done

echo "### STEP 11: Verify all BATCH-T components now RECALLED ###"
for i in 1 2 3 4 5; do
  qry "{\"function\":\"GetComponent\",\"Args\":[\"COMP-T$i\"]}"
done

echo "### STEP 12: Negative case - TriggerRecall on unknown batch ###"
inv '{"function":"TriggerRecall","Args":["BATCH-DOES-NOT-EXIST","test"]}'

echo "### STEP 13: CloseRecall on one recalled component ###"
inv '{"function":"CloseRecall","Args":["COMP-T1","REPAIRED","dealer replaced faulty mount","Org2MSP"]}'

echo "### STEP 14: GetHistory for COMP-T1 (full audit trail) ###"
qry '{"function":"GetHistory","Args":["COMP-T1"]}'

echo "### DONE ###"
