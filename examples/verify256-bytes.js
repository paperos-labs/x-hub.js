"use strict";

//let XHub = require("x-hub");
let XHub = require("../x-hub-signature.js");

async function main() {
  let secret = "It's a secret to everybody!";
  let xhub = XHub.create({ secret });

  let header =
    "sha256=2d9425c2ae617d90196c5d22f48370822036174914268970cc864a7095b065dd";
  let keyValue = header.split("=");
  let sigHex = keyValue[1];
  let sigBytes = XHub._hexToBytes(sigHex);

  let encoder = new TextEncoder();

  let payload = JSON.stringify({ foo: "bar" });
  let payloadBytes = encoder.encode(payload);

  let hashType = "SHA-256";
  let equal = await xhub.verifyBytes(sigBytes, payloadBytes, hashType);
  console.info(`Verified: ${equal}`);
}
main().catch(function (e) {
  console.error(e.message);
});
