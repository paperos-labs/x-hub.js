"use strict";

//let XHub = require("x-hub");
let XHub = require("../x-hub-signature.js");

async function main() {
  let secret = "It's a secret to everybody!";
  let xhub = XHub.create({ secret });
  let hash = "sha256";
  let hashType = "SHA-256";

  let encoder = new TextEncoder();

  let payload = JSON.stringify({ foo: "bar" });
  let payloadBytes = encoder.encode(payload);
  let sigBytes = await xhub.signBytes(payloadBytes, hashType);

  let sigHex = XHub._bytesToHex(sigBytes);
  let header = `${hash}=${sigHex}`;

  console.info(`X-Hub-Signature-256: ${header}`);
}

main().catch(function (e) {
  console.error(e.message);
});
