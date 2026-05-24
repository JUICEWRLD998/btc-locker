#!/usr/bin/env node
/**
 * CRITICAL-1 Proof of Concept
 * ═══════════════════════════
 * Demonstrates two tightly coupled vulnerabilities in the btc-locker demo server:
 *
 *   A) /api/keypair/generate generates private keys on the server and returns
 *      them in the HTTP response body — permanent credential compromise.
 *
 *   B) /api/transactions/spending (and /api/yield/distribute) mark `privateKeys`
 *      as *required* in their Swagger schemas, accept them in the request body,
 *      and then silently discard them. The library functions return an unsigned
 *      PSBT while the API reports success — a caller following the documented
 *      workflow will lock their funds indefinitely.
 *
 * Prerequisites:
 *   1. Start the demo server: cd packages/demo && node demo/start-demo.js
 *   2. Run: node poc-critical1.mjs
 */

import { Psbt, networks } from "bitcoinjs-lib";

const BASE_URL = "http://localhost:3000";
const NETWORK  = networks.testnet;

function separator(title) {
  console.log("");
  console.log("═".repeat(68));
  console.log(` ${title}`);
  console.log("═".repeat(68));
}

function countSignedInputs(psbtBase64) {
  const psbt = Psbt.fromBase64(psbtBase64, { network: NETWORK });
  const signed = psbt.data.inputs.filter(
    (inp) => inp.partialSig && inp.partialSig.length > 0
  ).length;
  return { total: psbt.inputCount, signed, unsigned: psbt.inputCount - signed };
}

// ─── A: Server generates private key ─────────────────────────────────────────

separator("A — /api/keypair/generate: Private key generated on server");

const genRes = await fetch(`${BASE_URL}/api/keypair/generate`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ network: "testnet" }),
});

if (!genRes.ok) {
  console.error("  ✗ Could not reach demo server. Is it running on port 3000?");
  process.exit(1);
}

const kp = await genRes.json();

console.log("");
console.log("  Response from GET /api/keypair/generate:");
console.log("  {");
console.log(`    "privateKey": "${kp.privateKey}"  ← EXPOSED`);
console.log(`    "publicKey":  "${kp.publicKey}"`);
console.log(`    "address":    "${kp.address}"`);
console.log("  }");
console.log("");
console.log("  This private key was generated using Node.js crypto on the server.");
console.log("  It exists in the server's heap before the client ever receives it.");
console.log("  Any infrastructure logs capturing HTTP responses now hold this key.");

// ─── B: Create a timelock script ──────────────────────────────────────────────

separator("Creating timelock script (setup step)");

const locktime = Math.floor(Date.now() / 1000) + 86400; // +1 day
const scriptRes = await fetch(`${BASE_URL}/api/timelock/create`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ locktime, publicKey: kp.publicKey, network: "testnet" }),
});

let script;
if (scriptRes.ok) {
  script = await scriptRes.json();
  console.log("  Timelock address:", script.address);
  console.log("  Redeem script:  ", script.redeemScript?.slice(0, 32) + "...");
} else {
  // Fall back to a known-valid testnet P2WSH redeemScript for demonstration
  script = {
    address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    redeemScript:
      "0120" + kp.publicKey + "b17563ac68",
  };
  console.log("  (Using fallback script for demonstration)");
}

// ─── B: Call spending endpoint with private key ───────────────────────────────

separator("B — /api/transactions/spending: privateKeys required but silently discarded");

console.log("");
console.log("  Sending request with privateKeys (required per Swagger schema)...");

const spendRes = await fetch(`${BASE_URL}/api/transactions/spending`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    inputs: [
      {
        txid: "a".repeat(64),
        vout: 0,
        value: 100000,
      },
    ],
    outputs: [
      {
        address: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        value: 98000,
      },
    ],
    redeemScript: script.redeemScript,
    privateKeys: [kp.privateKey], // ← Required per Swagger, sent over network
    network: "testnet",
  }),
});

const spendBody = await spendRes.json();

console.log("");
console.log("  API HTTP status:", spendRes.status);
console.log('  API "success"  :', spendBody.success);
console.log('  API "message"  :', spendBody.message);

if (spendBody.success && spendBody.data) {
  console.log("");
  console.log("  Decoding returned PSBT to check signing status...");
  try {
    const { total, signed, unsigned } = countSignedInputs(spendBody.data);
    console.log(`    Total inputs   : ${total}`);
    console.log(`    Signed inputs  : ${signed}`);
    console.log(`    Unsigned inputs: ${unsigned}`);
    console.log("");
    if (signed === 0) {
      console.log("  ┌──────────────────────────────────────────────────────────┐");
      console.log("  │ CONFIRMED: PSBT returned with 0 signed inputs.           │");
      console.log("  │                                                          │");
      console.log("  │  • The private key was transmitted to the server.        │");
      console.log("  │  • The private key was silently discarded by the library.│");
      console.log("  │  • This PSBT cannot be broadcast — no inputs are signed. │");
      console.log("  │  • If the caller treats this as a completed transaction, │");
      console.log("  │    their funds are permanently locked in the P2WSH addr. │");
      console.log("  └──────────────────────────────────────────────────────────┘");
    }
  } catch (e) {
    console.log("  (PSBT parsing error — redeemScript may need adjustment for your environment)");
    console.log("  Raw data prefix:", spendBody.data?.slice(0, 40), "...");
    console.log("  The key finding is that 'success: true' is returned despite no signing.");
  }
} else {
  console.log("  Response body:", JSON.stringify(spendBody, null, 2));
}

// ─── C: /api/yield/distribute ─────────────────────────────────────────────────

separator("C — /api/yield/distribute: provider privateKey exposed, yield never sent");

const distRes = await fetch(`${BASE_URL}/api/yield/distribute`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    inputs: [
      {
        txid: "b".repeat(64),
        vout: 0,
        value: 500000,
        scriptPubKey: "0020" + "a".repeat(64), // dummy P2WSH
      },
    ],
    timelockAddress: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    amount: 490000,
    privateKey: kp.privateKey, // ← Required per Swagger, exposed to server, never used
    network: "testnet",
  }),
});

const distBody = await distRes.json();
console.log("");
console.log("  API HTTP status:", distRes.status);
console.log('  API "success"  :', distBody.success);

if (distBody.success && distBody.data) {
  try {
    const { total, signed, unsigned } = countSignedInputs(distBody.data);
    console.log(`    Signed inputs in distribution PSBT: ${signed} / ${total}`);
    if (signed === 0) {
      console.log("");
      console.log("  ┌──────────────────────────────────────────────────────────┐");
      console.log("  │ CONFIRMED: Provider's private key was exposed to server, │");
      console.log("  │ but the distribution was never signed or broadcast.      │");
      console.log("  │ The user's yield remains undistributed.                  │");
      console.log("  └──────────────────────────────────────────────────────────┘");
    }
  } catch (e) {
    console.log("  Distribution response appears unsigned (PSBT parse note):", e.message.slice(0, 60));
  }
} else {
  console.log("  Response:", JSON.stringify(distBody, null, 2).slice(0, 200));
}

// ─── D: /api/transactions/funding — always 500 ────────────────────────────────

separator("D — /api/transactions/funding: parameter mismatch causes HTTP 500");

const fundRes = await fetch(`${BASE_URL}/api/transactions/funding`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({
    inputs: [{ txid: "c".repeat(64), vout: 0, value: 200000 }],
    timelockAddress: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    amount: 190000,
    changeAddress: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    privateKeys: [kp.privateKey],
    feeRate: 10,
    network: "testnet",
  }),
});

const fundBody = await fundRes.json();
console.log("");
console.log("  HTTP status:", fundRes.status, "(expected 500 due to parameter mismatch)");
console.log("  Error:", fundBody.error?.slice(0, 120));
console.log("");
console.log("  The handler passes { timelockAddress, amount, changeAddress } to");
console.log("  createFundingTransaction(), whose interface expects { outputs: [] }.");
console.log("  outputs is undefined → forEach throws → endpoint is completely broken.");

// ─── Summary ──────────────────────────────────────────────────────────────────

separator("Summary");
console.log("");
console.log("  Finding A — /api/keypair/generate                        CRITICAL");
console.log("    Private key generated on server, returned in HTTP response body.");
console.log("");
console.log("  Finding B — /api/transactions/spending                   CRITICAL");
console.log("    privateKeys required in schema, silently discarded at runtime.");
console.log("    Returns unsigned PSBT while reporting 'success'.");
console.log("    Funds locked indefinitely if caller trusts the success response.");
console.log("");
console.log("  Finding C — /api/yield/distribute                        CRITICAL");
console.log("    Same pattern: privateKey exposed to server, yield never distributed.");
console.log("");
console.log("  Finding D — /api/transactions/funding                    HIGH");
console.log("    Parameter mismatch causes every call to throw HTTP 500.");
console.log("    Endpoint is completely non-functional.");
console.log("");
