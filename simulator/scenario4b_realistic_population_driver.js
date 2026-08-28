// ---------- Scenario 4b driver: heterogeneous multi-supplier, multi-batch population ----------
// Real execution against the extracted simulator core (no numbers below are
// invented; every count is read back from the engine's own return values
// or its final state after running).

const results = { errors: [] };

// Three Tier-2 suppliers, five production batches of varying size, not a
// clean target/control split. Batch sizes are deliberately uneven.
const SUPPLIERS = ['Tier2Supplier-Sheffield', 'Tier2Supplier-Coventry', 'Tier2Supplier-Bradford'];
const BATCHES = [
  { id: 'BATCH-2025-CAL-201', supplier: SUPPLIERS[0], size: 8 },
  { id: 'BATCH-2025-CAL-202', supplier: SUPPLIERS[0], size: 5 },
  { id: 'BATCH-2025-CAL-310', supplier: SUPPLIERS[1], size: 11 },  // <- this one gets recalled
  { id: 'BATCH-2025-CAL-311', supplier: SUPPLIERS[1], size: 4 },
  { id: 'BATCH-2025-CAL-450', supplier: SUPPLIERS[2], size: 9 },
];
const DEALERS = ['Dealer-Manchester', 'Dealer-Bristol', 'Dealer-Leeds', 'Dealer-Glasgow', 'Dealer-Newcastle'];
const RECALL_BATCH = 'BATCH-2025-CAL-310';

let dealerCycle = 0;
let registered = [];

// --- Register the full heterogeneous population ---
for (const batch of BATCHES) {
  for (let i = 1; i <= batch.size; i++) {
    const id = `${batch.id}-C${String(i).padStart(3, '0')}`;
    registerComponent(id, batch.id, batch.supplier, [ORGS.TIER2, ORGS.OEM]);
    registered.push({ id, batch: batch.id, supplier: batch.supplier });
  }
}
results.totalRegistered = registered.length;
results.batchSizes = Object.fromEntries(BATCHES.map(b => [b.id, b.size]));

// --- Negative case: duplicate registration attempt ---
try {
  registerComponent(registered[0].id, registered[0].batch, registered[0].supplier, [ORGS.TIER2, ORGS.OEM]);
  results.duplicateRejected = false;
} catch (e) {
  results.duplicateRejected = true;
  results.duplicateError = e.message;
}

// --- Ship most components to dealers; deliberately leave some MANUFACTURED
//     (different lifecycle state) to reflect a realistic in-progress population ---
let shippedCount = 0, unshippedCount = 0;
for (const r of registered) {
  // Leave the last component of every batch unshipped (still MANUFACTURED).
  const batchMembers = registered.filter(x => x.batch === r.batch);
  const isLast = batchMembers[batchMembers.length - 1].id === r.id;
  if (isLast) { unshippedCount++; continue; }
  const dealer = DEALERS[dealerCycle % DEALERS.length]; dealerCycle++;
  recordShipment(r.id, dealer, [ORGS.TIER1, ORGS.OEM]);
  shippedCount++;
}
results.shippedCount = shippedCount;
results.unshippedCount = unshippedCount;

// --- Usage logs on a subset of shipped components, mixed over/under threshold ---
const shipped = registered.filter(r => state.get(r.id).status === 'SHIPPED');
let warrantyVoid = 0, warrantyHonoured = 0;
shipped.slice(0, 6).forEach((r, i) => {
  const temp = i % 2 === 0 ? 92 : 70; // alternate over/under the 85C threshold
  recordUsageLog(r.id, temp, [ORGS.TIER1, ORGS.OEM]);
  const wc = warrantyCheck(r.id, 85);
  if (wc.result === 'WARRANTY_VOID') warrantyVoid++; else warrantyHonoured++;
});
results.warrantyChecks = { warrantyVoid, warrantyHonoured };

// --- Negative case: unauthorised recall attempt (Tier-2 supplier, not OEM/Regulator) ---
try {
  triggerRecall(RECALL_BATCH, 'unauthorised probe', ORGS.TIER2);
  results.unauthorisedRecallRejected = false;
} catch (e) {
  results.unauthorisedRecallRejected = true;
  results.unauthorisedRecallError = e.message;
}

// --- Real recall: only the named batch, among five, should be affected ---
const recallResult = triggerRecall(RECALL_BATCH, 'brake caliper torque-spec non-conformance', ORGS.OEM);
results.recallAffectedCount = recallResult.affected_count;
results.recallExpectedCount = BATCHES.find(b => b.id === RECALL_BATCH).size;
results.recallNotifiedDealers = recallResult.notified;

// --- Confirm every OTHER batch's tokens are untouched by the recall ---
let unaffectedOutsideTarget = 0, wronglyAffected = 0;
for (const r of registered) {
  const tok = state.get(r.id);
  if (r.batch === RECALL_BATCH) continue;
  if (tok.recall_status === 'RECALLED') wronglyAffected++; else unaffectedOutsideTarget++;
}
results.unaffectedOutsideTarget = unaffectedOutsideTarget;
results.wronglyAffected = wronglyAffected;
results.totalOutsideTarget = registered.length - BATCHES.find(b => b.id === RECALL_BATCH).size;

// --- provenanceCheck: one genuine registered component, one fabricated ID ---
results.provenanceGenuine = provenanceCheck(registered[0].id).result;
results.provenanceFabricated = provenanceCheck('FAKE-ID-DOES-NOT-EXIST').result;

// --- closeRecall + reviseRecallReason + revokeRecall on the recalled batch ---
const recalledIDs = registered.filter(r => r.batch === RECALL_BATCH).map(r => r.id);
closeRecall(recalledIDs[0], 'REPLACED', 'caliper swapped under recall', [ORGS.TIER1, ORGS.OEM]);
const revised = reviseRecallReason(RECALL_BATCH, 'root cause confirmed: torque spec revision C', ORGS.OEM);
results.reviseAmendedCount = revised.amended_count; // should be size-1 (the closed one excluded)
const revoked = revokeRecall(RECALL_BATCH, 'remaining stock re-certified after inspection', ORGS.REGULATOR);
results.revokeCount = revoked.revoked_count; // should be size-2 (closed + already revised != recalled anymore is same set)

// --- Final ledger consistency check: total blocks, total events ---
results.finalBlockCount = blocks.length - 1; // minus genesis
results.finalEventCount = events.length;

console.log(JSON.stringify(results, null, 2));
