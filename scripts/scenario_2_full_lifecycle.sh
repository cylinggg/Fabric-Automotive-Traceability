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
as_org3_regulator() {
  export CORE_PEER_LOCALMSPID="Org3MSP"
  export CORE_PEER_TLS_ROOTCERT_FILE=${PWD}/organizations/peerOrganizations/org3.example.com/peers/peer0.org3.example.com/tls/ca.crt
  export CORE_PEER_MSPCONFIGPATH=${PWD}/organizations/peerOrganizations/org3.example.com/users/Admin@org3.example.com/msp
  export CORE_PEER_ADDRESS=localhost:11051
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
# Reports are hashed client-side and only the digest is ever submitted to the
# chaincode; the report text itself never appears in a transaction proposal.
# See dissertation Section 3.6 (on-chain/off-chain boundary).
h() {
  printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
}

as_org1

echo "### RUN2 STEP A: Register + fully cycle COMP-B1,COMP-B2 (BATCH-B) and COMP-B3 (BATCH-B2) to SHIPPED ###"
echo "-- deliberately spanning two batches: a real product routinely combines parts from more than one batch --"
for i in 1 2; do
  echo "-- RegisterComponent COMP-B$i (BATCH-B) --"
  inv "{\"function\":\"RegisterComponent\",\"Args\":[\"COMP-B$i\",\"BATCH-B\",\"Tier2Supplier\",\"$(h "QC report B$i")\",\"Org2MSP\"]}"
  echo "-- RecordTest COMP-B$i --"
  inv "{\"function\":\"RecordTest\",\"Args\":[\"COMP-B$i\",\"$(h "full QC pass B$i")\",\"Org2MSP\"]}"
  echo "-- RecordShipment COMP-B$i --"
  inv "{\"function\":\"RecordShipment\",\"Args\":[\"COMP-B$i\",\"Tier2Supplier\",\"Tier1Supplier\",\"Org2MSP\"]}"
done
echo "-- RegisterComponent COMP-B3 (BATCH-B2, a different batch from COMP-B1/COMP-B2) --"
inv "{\"function\":\"RegisterComponent\",\"Args\":[\"COMP-B3\",\"BATCH-B2\",\"Tier2Supplier\",\"$(h "QC report B3")\",\"Org2MSP\"]}"
inv "{\"function\":\"RecordTest\",\"Args\":[\"COMP-B3\",\"$(h "full QC pass B3")\",\"Org2MSP\"]}"
inv '{"function":"RecordShipment","Args":["COMP-B3","Tier2Supplier","Tier1Supplier","Org2MSP"]}'

echo "### RUN2 STEP B: RecordAssembly PRODUCT-B (3 components spanning BATCH-B and BATCH-B2) ###"
inv '{"function":"RecordAssembly","Args":["PRODUCT-B","COMP-B1,COMP-B2,COMP-B3","RECIPE-STD","Org2MSP"]}'
echo "-- QUERY PRODUCT-B for componentBatches (expect [\"BATCH-B\",\"BATCH-B2\"]) --"
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

echo "### RUN2 STEP E: TriggerRecall on BATCH-B2 only (recalling the SECOND constituent batch of PRODUCT-B, not its primary BatchID) ###"
echo "-- this must still find PRODUCT-B, because it is indexed under every batch its components were drawn from --"
inv '{"function":"TriggerRecall","Args":["BATCH-B2","seatbelt tensioner fault"]}'
echo "-- QUERY PRODUCT-B and COMP-B1 (expect recallStatus=RECALLED, status STILL DELIVERED, not overwritten) --"
qry '{"function":"GetComponent","Args":["PRODUCT-B"]}'
qry '{"function":"GetComponent","Args":["COMP-B1"]}'

echo "### RUN2 STEP F: CloseRecall on COMP-B3 (resolution goes to recallStatus, lifecycle status untouched) ###"
echo "-- COMP-B3, not COMP-B1: BATCH-B2 (recalled in Step E) contains COMP-B3 and PRODUCT-B, not COMP-B1/COMP-B2 (those are BATCH-B only) --"
inv '{"function":"CloseRecall","Args":["COMP-B3","REPAIRED","dealer repaired tensioner","Org2MSP"]}'
echo "-- QUERY COMP-B3 (expect recallStatus=REPAIRED, status STILL DELIVERED) --"
qry '{"function":"GetComponent","Args":["COMP-B3"]}'

echo "### RUN2 STEP G: ReviseRecallReason on BATCH-B2 (amend, not overwrite; COMP-B3 already closed so excluded) ###"
inv '{"function":"ReviseRecallReason","Args":["BATCH-B2","root cause confirmed as torque spec, not tensioner"]}'
echo "-- QUERY PRODUCT-B (still RECALLED, expect amendment appended) and COMP-B3 (already REPAIRED, expect NOT amended) --"
qry '{"function":"GetComponent","Args":["PRODUCT-B"]}'
qry '{"function":"GetComponent","Args":["COMP-B3"]}'

echo "### RUN2 STEP H: Negative - OEM (Org1) attempts the Regulator-only RevokeRecall, expect rejection ###"
inv '{"function":"RevokeRecall","Args":["BATCH-B2","OEM attempting to self-revoke"]}'

echo "### RUN2 STEP I: RevokeRecall by Org3 (Regulator) on BATCH-B2 ###"
echo "-- COMP-B3 was already resolved via CloseRecall (recallStatus=REPAIRED, not RECALLED), so this only revokes PRODUCT-B --"
echo "-- expect PRODUCT-B recallStatus cleared to empty AND status still DELIVERED, not reset to a generic ACTIVE value --"
as_org3_regulator
inv '{"function":"RevokeRecall","Args":["BATCH-B2","root cause traced to a different supplier batch"]}'
as_org1
qry '{"function":"GetComponent","Args":["PRODUCT-B"]}'
echo "-- QUERY COMP-B3 again (expect recallStatus still REPAIRED, untouched by the revoke) --"
qry '{"function":"GetComponent","Args":["COMP-B3"]}'

echo "### RUN2 STEP J: ProvenanceCheck (formerly CounterfeitScan) on genuine vs fabricated ID ###"
qry '{"function":"ProvenanceCheck","Args":["COMP-B1"]}'
qry '{"function":"ProvenanceCheck","Args":["COMP-FAKE-9999"]}'

echo "### DONE RUN2 ###"
