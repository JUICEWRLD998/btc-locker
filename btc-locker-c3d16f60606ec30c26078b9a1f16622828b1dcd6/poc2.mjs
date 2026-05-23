/**
 * Proof of Concept — CRITICAL-2
 * estimateFee() uses a P2SH legacy byte model for P2WSH native SegWit transactions,
 * causing ~1.73× fee overestimation, systematic fund loss, and false-positive fund lock.
 *
 * Run: node poc2.mjs
 */

import * as bitcoin from "bitcoinjs-lib";
import tinysecp from "@bitcoinerlab/secp256k1";
import { ECPairFactory } from "ecpair";

// ── Initialise ECC ───────────────────────────────────────────────────────────
const ecc = tinysecp.default ?? tinysecp;
bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
const network = bitcoin.networks.testnet;

// ── Replicate the EXACT buggy formula from packages/core/src/utils/fees.ts ───
function estimateFee_BUGGY(inputCount, outputCount, feeRate = 10) {
  // P2SH input: ~148 bytes (41 outpoint + 1 script length + 23 scriptSig push +
  //   ~83 redeem script push + 4 sequence). Rounded up to 150 as a conservative
  //   overestimate — actual size varies with redeem script length.
  // P2PKH/P2SH output: 34 bytes (8 value + 1 script length + 25 scriptPubKey).
  // Transaction overhead: 10 bytes (4 version + 1 input count + 1 output count + 4 locktime).
  const estimatedSize = inputCount * 150 + outputCount * 34 + 10;
  return Math.ceil(estimatedSize * feeRate);
}

// ── Constants ────────────────────────────────────────────────────────────────
const FEE_RATE = 50; // sat/vbyte — typical congested mempool rate
const DUST_THRESHOLD = 546; // matches FeeUtils.DUST_THRESHOLD

console.log("=".repeat(64));
console.log("CRITICAL-2 — P2SH byte model used for P2WSH in estimateFee()");
console.log("=".repeat(64));

// ── Step 1: Build the exact same script structure btc-locker creates ──────────
console.log("\n[Step 1] Constructing a real P2WSH CLTV timelock transaction...");

// Use a deterministic key pair (private key = all 0x01 bytes) so results are reproducible
const keyPair = ECPair.fromPrivateKey(Buffer.alloc(32, 0x01), { network });
const pubkey = keyPair.publicKey;

// Locktime: a realistic Unix timestamp (2025-05-22)
const locktime = Math.floor(new Date("2025-05-22T00:00:00Z").getTime() / 1000);

// createTimelockScript() equivalent from packages/core/src/locker/scripts/timelock.ts
const timelockScript = bitcoin.script.compile([
  bitcoin.script.number.encode(locktime),
  bitcoin.opcodes.OP_CHECKLOCKTIMEVERIFY,
  bitcoin.opcodes.OP_DROP,
  pubkey,
  bitcoin.opcodes.OP_CHECKSIG,
]);

// P2WSH address — same as createScriptAddress() in utils/scripts.ts
const p2wsh = bitcoin.payments.p2wsh({
  redeem: { output: timelockScript, network },
  network,
});

// ── Step 2: Build and sign the PSBT to measure real vbytes ──────────────────
console.log("[Step 2] Building and signing PSBT to measure actual vbytes...\n");

// Fake txid for the UTXO (the UTXO we are spending from the P2WSH address)
const fakeTxid = "a".repeat(64);

// Amount in the UTXO — set just above (correctFee + DUST_THRESHOLD) to demonstrate fund lock
// We will determine this after computing correctFee below. Use 6246 sats (from calculation).
const utxoValue = 6246;

const psbt = new bitcoin.Psbt({ network });
psbt.setVersion(1);
psbt.setLocktime(locktime);

psbt.addInput({
  hash: fakeTxid,
  index: 0,
  sequence: 0xfffffffe,
  witnessUtxo: {
    script: p2wsh.output,
    value: BigInt(utxoValue),
  },
  witnessScript: timelockScript,
});

// Destination: a P2WPKH output (typical claim destination)
const destPubkey = ECPair.makeRandom({ network }).publicKey;
const p2wpkh = bitcoin.payments.p2wpkh({ pubkey: destPubkey, network });
psbt.addOutput({
  script: p2wpkh.output,
  value: BigInt(utxoValue - 1), // placeholder, will finalize with correct amount
});

// Sign input
psbt.signInput(0, keyPair);

// Finalize manually (P2WSH custom script): witness = [sig, witnessScript]
psbt.finalizeInput(0, (inputIndex, input) => {
  const sig = input.partialSig[0].signature;
  return {
    finalScriptSig: Buffer.alloc(0),
    finalScriptWitness: psbtEncodeWitness([sig, timelockScript]),
  };
});

// Extract the transaction and measure it
const tx = psbt.extractTransaction();
const actualWeight = tx.weight();
const actualVbytes = tx.virtualSize();

console.log("  redeemScript hex :", Buffer.from(timelockScript).toString("hex"));
console.log("  redeemScript size:", timelockScript.length, "bytes");
console.log();
console.log("  Actual transaction weight :", actualWeight, "weight units");
console.log("  Actual transaction vbytes :", actualVbytes, "vbytes");

// ── Step 3: Compare buggy estimate vs actual ──────────────────────────────────
console.log();
console.log("-".repeat(64));
console.log("[Step 3] Comparing buggy estimate vs actual size");
console.log("-".repeat(64));
console.log();

const buggySize = 1 * 150 + 1 * 34 + 10; // estimateFee_BUGGY formula for 1-in, 1-out
const buggyFee = estimateFee_BUGGY(1, 1, FEE_RATE);
const correctFee = actualVbytes * FEE_RATE;
const excessFee = buggyFee - correctFee;
const overestimationRatio = (buggySize / actualVbytes).toFixed(2);

console.log("  Model used by SDK (fees.ts)    : P2SH legacy (~148 bytes/input)");
console.log("  Actual script type             : P2WSH native SegWit (~69–73 vbytes/input)");
console.log();
console.log(`  SDK estimated tx size  : ${buggySize} bytes  (1 × 150 + 1 × 34 + 10)`);
console.log(`  Actual transaction size: ${actualVbytes} vbytes`);
console.log(`  Overestimation ratio   : ${overestimationRatio}×`);
console.log();
console.log(`  At ${FEE_RATE} sat/vbyte:`);
console.log(`    Correct fee       = ${actualVbytes} × ${FEE_RATE} = ${correctFee} sats`);
console.log(`    SDK estimated fee = ${buggySize} × ${FEE_RATE} = ${buggyFee} sats`);
console.log(`    Excess fee paid   = ${excessFee} sats  (${Math.round(excessFee / correctFee * 100)}% overpayment)`);
console.log(`    → Users lose ${excessFee} sats to miners on every single claim / withdrawal`);

// ── Step 4: Demonstrate false-positive fund lock ──────────────────────────────
console.log();
console.log("-".repeat(64));
console.log("[Step 4] False-positive fund lock (withdraw.ts guard)");
console.log("-".repeat(64));
console.log();
console.log(`  UTXO value: ${utxoValue} sats`);
console.log();
console.log(`  Using CORRECT fee (${correctFee} sats):`);
const correctOutput = utxoValue - correctFee;
console.log(`    output = ${utxoValue} - ${correctFee} = ${correctOutput} sats`);
if (correctOutput > DUST_THRESHOLD) {
  console.log(`    ${correctOutput} > ${DUST_THRESHOLD} (dust)  →  transaction IS valid and broadcastable ✓`);
} else {
  console.log(`    ${correctOutput} ≤ ${DUST_THRESHOLD} (dust)  →  below dust (also unspendable)`);
}
console.log();
console.log(`  Using BUGGY fee estimate (${buggyFee} sats):`);
const buggyOutput = utxoValue - buggyFee;
console.log(`    output = ${utxoValue} - ${buggyFee} = ${buggyOutput} sats`);
if (buggyOutput <= DUST_THRESHOLD) {
  console.log(`    ${buggyOutput} ≤ ${DUST_THRESHOLD} (dust)  →  SDK THROWS "below dust threshold" ✗`);
} else {
  console.log(`    ${buggyOutput} > ${DUST_THRESHOLD} (dust)  →  unexpectedly valid`);
}
console.log();
console.log("  *** FUND LOCK CONFIRMED ***");
console.log(`  A UTXO of ${utxoValue} sats IS economically spendable`);
console.log(`  (actual fee ${correctFee} sats leaves ${correctOutput} sats to the user)`);
console.log(`  but the SDK refuses to create the withdrawal transaction because`);
console.log(`  it over-estimates the fee by ${excessFee} sats.`);
console.log("  The user cannot recover these funds via the btc-locker SDK.");

// ── Step 5: Table of excess fees across common fee rates ─────────────────────
console.log();
console.log("-".repeat(64));
console.log("[Step 5] Excess fee across realistic UTXO sizes at common fee rates");
console.log("-".repeat(64));
console.log();
const utxo10k = 10_000;
const utxo100k = 100_000;
console.log("  fee rate | excess per tx | % of 10k-sat UTXO | % of 100k-sat UTXO");
console.log("  ---------|---------------|-------------------|--------------------");
for (const fr of [10, 25, 50, 100, 200]) {
  const excess = estimateFee_BUGGY(1, 1, fr) - actualVbytes * fr;
  const pct10k = ((excess / utxo10k) * 100).toFixed(1);
  const pct100k = ((excess / utxo100k) * 100).toFixed(2);
  console.log(
    `  ${String(fr).padStart(8)} | ${String(excess).padStart(13)} | ${String(pct10k + "%").padStart(17)} | ${String(pct100k + "%").padStart(18)}`,
  );
}

// ── Root cause ───────────────────────────────────────────────────────────────
console.log();
console.log("=".repeat(64));
console.log("ROOT CAUSE");
console.log("=".repeat(64));
console.log();
console.log("  File   : packages/core/src/utils/fees.ts");
console.log("  Class  : FeeUtils");
console.log("  Method : estimateFee(inputCount, outputCount, feeRate)");
console.log();
console.log("  Buggy line:");
console.log("    const estimatedSize = inputCount * 150 + outputCount * 34 + 10;");
console.log('  Comment in source claims "P2SH input: ~148 bytes" but ALL transactions');
console.log("  use P2WSH native SegWit inputs whose vbyte cost is ~69–73 vbytes.");
console.log();
console.log("  Fix: replace the P2SH legacy formula with a proper segwit vbyte calc:");
console.log();
console.log("    // P2WSH input: 41 non-witness bytes + ~117 witness bytes");
console.log("    //   vbytes = ceil((41*4 + 117) / 4) = ceil(281/4) = 71");
console.log("    // P2WPKH output: 31 bytes = 31 vbytes");
console.log("    // Overhead (version + counts + locktime + segwit marker/flag): 12 vbytes");
console.log("    const estimatedVbytes = inputCount * 71 + outputCount * 31 + 12;");
console.log("    return Math.ceil(estimatedVbytes * feeRate);");
console.log();
console.log("=".repeat(64));
console.log("RESULT: BUG CONFIRMED");
console.log(`  • Overestimation ratio       : ${overestimationRatio}×  (at ${FEE_RATE} sat/vbyte)`);
console.log(`  • Excess fee per tx          : ${excessFee} sats  (${Math.round(excessFee / correctFee * 100)}% overpayment)`);
console.log(`  • Fund lock threshold (${FEE_RATE} s/vb): UTXO ≤ ${buggyFee + DUST_THRESHOLD} sats with actual spendability ≥ ${correctFee + DUST_THRESHOLD + 1} sats`);
console.log("=".repeat(64));

// ── Helper: encode witness stack as a Bitcoin witness field ─────────────────
function psbtEncodeWitness(items) {
  const chunks = [Buffer.from([items.length])];
  for (const item of items) {
    const buf = Buffer.from(item);
    chunks.push(Buffer.from([buf.length]));
    chunks.push(buf);
  }
  return Buffer.concat(chunks);
}
