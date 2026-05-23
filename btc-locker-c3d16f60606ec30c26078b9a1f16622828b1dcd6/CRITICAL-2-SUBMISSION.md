# Bug Bounty Submission — CRITICAL-2

**Title:** `estimateFee()` uses a P2SH legacy byte model for P2WSH native SegWit transactions, causing ~1.73× fee overestimation, systematic fund loss, and false-positive fund lock

**Severity:** Critical  
**Component:** `packages/core/src/utils/fees.ts` — `FeeUtils.estimateFee()`  
**Impact:** Direct fund loss on every transaction + permanent fund lock for UTXOs in a specific satoshi range

---

## Summary

`FeeUtils.estimateFee()` estimates transaction sizes using the P2SH legacy byte model (150 bytes per input, as documented in its own code comment). However, **every single transaction** produced by btc-locker uses P2WSH native SegWit — a completely different wire format that benefits from SegWit's witness discount.

The actual virtual size of a 1-input 1-output P2WSH CLTV transaction is **112 vbytes**. The SDK estimates it as **194 bytes** — an overestimation of **1.73×**.

This has two direct, user-impacting consequences:

1. **Fund loss:** Every claim/withdrawal transaction overpays miners by 73% (~4,100 sats at 50 sat/vbyte).
2. **Fund lock:** The `createWithdrawalTransaction` guard (`destinationValue ≤ DUST_THRESHOLD`) fires for UTXOs that are *economically spendable*, permanently preventing the user from recovering funds via the SDK.

---

## Root Cause

**File:** `packages/core/src/utils/fees.ts`  
**Class:** `FeeUtils`  
**Method:** `estimateFee(inputCount, outputCount, feeRate)`

```typescript
static estimateFee(
  inputCount: number,
  outputCount: number,
  feeRate: number = 10,
): number {
  // P2SH input: ~148 bytes (41 outpoint + 1 script length + 23 scriptSig push +
  //   ~83 redeem script push + 4 sequence). Rounded up to 150 as a conservative
  //   overestimate — actual size varies with redeem script length.
  // P2PKH/P2SH output: 34 bytes (8 value + 1 script length + 25 scriptPubKey).
  // Transaction overhead: 10 bytes (4 version + 1 input count + 1 output count + 4 locktime).
  const estimatedSize = inputCount * 150 + outputCount * 34 + 10;  // ← BUG
  return Math.ceil(estimatedSize * feeRate);
}
```

The comment explicitly says "P2SH input: ~148 bytes" — a P2SH **legacy** formula. However, all btc-locker transactions use **P2WSH native SegWit**. In native SegWit, the script is moved to the witness field, which is discounted to 1/4 weight under BIP141. The correct vbyte cost per P2WSH input is ~71 vbytes, not 150 bytes.

### Correct P2WSH calculation

```
Non-witness bytes per input : 41  (32 txid + 4 vout + 4 sequence + 1 scriptSig length, empty)
Witness bytes per input     : ~117 (var_int + sig ~73 + var_int + witnessScript ~42)
Weight per input            : 41 × 4 + 117 = 281 weight units
vbytes per input            : ceil(281 / 4) = 71 vbytes

P2WSH output                : 31 vbytes (8 value + 1 scriptPubKey length + 22 P2WSH scriptPubKey)
Overhead                    : 12 vbytes (version + segwit marker/flag + input count + output count + locktime)

Total (1-in, 1-out)         : 71 + 31 + 12 = 114 vbytes  (PoC measured: 112 vbytes)
SDK estimate (1-in, 1-out)  : 150 + 34 + 10 = 194 bytes
```

---

## Impact

### Impact A — Systematic Fund Loss on Every Transaction

Every claim, withdrawal, and distribution transaction overpays miners.

| Fee rate (sat/vbyte) | Correct fee | SDK fee | Excess per tx | Excess as % of 10,000-sat UTXO |
|---|---|---|---|---|
| 10 | 1,120 | 1,940 | **820 sats** | 8.2% |
| 25 | 2,800 | 4,850 | **2,050 sats** | 20.5% |
| 50 | 5,600 | 9,700 | **4,100 sats** | 41.0% |
| 100 | 11,200 | 19,400 | **8,200 sats** | 82.0% |
| 200 | 22,400 | 38,800 | **16,400 sats** | 164.0% |

At a typical fee rate of 50 sat/vbyte, **41% of the UTXO value in a 10,000-sat deposit is silently donated to miners** rather than returned to the user.

### Impact B — False-Positive Fund Lock

`createWithdrawalTransaction` computes:

```typescript
const feeAmount = FeeUtils.estimateFee(
  escrowInputs.length + timelockInputs.length,
  1 + (protocolFeeAmount ? 1 : 0),
  feeRate,
);
const totalFees = feeAmount + (protocolFeeAmount || 0);
const destinationValue = totalInputValue - totalFees;
if (destinationValue <= FeeUtils.DUST_THRESHOLD) {          // 546 sats
  throw new Error("Destination output amount would be below dust threshold after fees");
}
```

With the overestimated fee, this guard fires even for UTXOs that are entirely spendable.

**Concrete example (at 50 sat/vbyte):**

- UTXO value: **6,246 sats**
- Correct fee: **5,600 sats** → output = 646 sats → **valid and broadcastable ✓**
- SDK estimated fee: **9,700 sats** → output = −3,454 sats → **SDK throws "below dust threshold" ✗**

The user's funds are **locked in a P2WSH address** they control the key for, but the SDK refuses to generate a valid spending transaction. Since the only supported spending path is through the btc-locker SDK (which created the timelock script), the user cannot recover these funds.

The fund lock window at 50 sat/vbyte affects **any UTXO between ~6,147 and ~10,246 sats** that would otherwise be spendable.

---

## Proof of Concept

**File:** `poc2.mjs` (repository root)

Run:

```bash
node poc2.mjs
```

The PoC:
1. Constructs a real P2WSH CLTV timelock transaction using `bitcoinjs-lib` (matching btc-locker's own construction logic).
2. Builds, signs, and finalizes the PSBT to obtain the real serialized transaction.
3. Measures actual virtual size using `tx.virtualSize()`.
4. Compares against `estimateFee_BUGGY()` (the formula copied verbatim from `fees.ts`).
5. Demonstrates the false-positive fund lock scenario.

**Verified output:**

```
================================================================
CRITICAL-2 — P2SH byte model used for P2WSH in estimateFee()
================================================================

  redeemScript size: 42 bytes

  Actual transaction weight : 446 weight units
  Actual transaction vbytes : 112 vbytes

----------------------------------------------------------------
  SDK estimated tx size  : 194 bytes  (1 × 150 + 1 × 34 + 10)
  Actual transaction size: 112 vbytes
  Overestimation ratio   : 1.73×

  At 50 sat/vbyte:
    Correct fee       = 112 × 50 = 5600 sats
    SDK estimated fee = 194 × 50 = 9700 sats
    Excess fee paid   = 4100 sats  (73% overpayment)
    → Users lose 4100 sats to miners on every single claim / withdrawal

----------------------------------------------------------------
  UTXO value: 6246 sats

  Using CORRECT fee (5600 sats):
    output = 6246 - 5600 = 646 sats
    646 > 546 (dust)  →  transaction IS valid and broadcastable ✓

  Using BUGGY fee estimate (9700 sats):
    output = 6246 - 9700 = -3454 sats
    -3454 ≤ 546 (dust)  →  SDK THROWS "below dust threshold" ✗

  *** FUND LOCK CONFIRMED ***
```

---

## All Affected Functions

Every transaction creation function calls `FeeUtils.estimateFee()`:

| Function | File | Effect |
|---|---|---|
| `createClaimTransaction` | `transactions/claim.ts` | Overpays fee; may silently create below-dust output (guard uses `<= 0`, not `<= DUST_THRESHOLD`) |
| `createWithdrawalTransaction` | `transactions/withdraw.ts` | Overpays fee **and** locks funds via false-positive dust check |
| `createDepositTransaction` | `transactions/deposit/deposit.ts` | Overpays fee |
| `createDistributeTransaction` | `transactions/distribute.ts` | Overpays fee |

---

## Recommended Fix

Replace the P2SH legacy formula with a correct P2WSH vbyte calculation:

```typescript
static estimateFee(inputCount: number, outputCount: number, feeRate = 10): number {
  // P2WSH input vbytes:
  //   non-witness: 41 bytes (outpoint 36 + scriptSig length 1 + sequence 4)
  //   witness:    ~117 bytes (var_int + sig ~73 + var_int + witnessScript ~42)
  //   weight: 41 × 4 + 117 = 281 → vbytes: ceil(281 / 4) = 71
  // P2WSH output: 8 (value) + 1 (scriptPubKey length) + 34 (P2WSH scriptPubKey) = 43 bytes
  // Overhead: 4 (version) + 2 (segwit marker+flag) + 1+1 (in/out counts) + 4 (locktime) = 12
  const estimatedVbytes = inputCount * 71 + outputCount * 43 + 12;
  return Math.ceil(estimatedVbytes * feeRate);
}
```

> **Note:** `witnessScript` size varies by script type (timelock ~42 bytes, escrow ~78 bytes). For precision, callers should pass the actual witness script byte length. A conservative per-script-type constant is acceptable as long as it uses the SegWit weight formula.

---

## Severity Justification

This meets the **Critical** threshold because:

- **Direct fund loss** occurs on *every* transaction the SDK creates — no user action can prevent it.
- **Permanent fund lock** occurs for UTXOs in a predictable satoshi range. Users with small UTXOs (e.g., test deposits, dust-aggregation scenarios, or high-fee-rate environments) permanently lose access to funds they control the keys for, with no workaround via the SDK.
- The bug is **deterministic** and **100% reproducible** — it affects every user, every transaction, every fee rate.

---

*Submitted by independent security researcher. PoC tested against btc-locker commit `c3d16f60606ec30c26078b9a1f16622828b1dcd6`.*
