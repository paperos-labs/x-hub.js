"use strict";

//let XHub = require("x-hub");
let XHub = require("../x-hub-signature.js");

async function main() {
  let secret = "It's a secret to everybody!";
  let xhub = XHub.create({ secret });

  let payload = JSON.stringify({ foo: "bar" });
  let hash = "sha256";
  let header = await xhub.sign(payload, hash);

  console.info(`X-Hub-Signature-256: ${header}`);
}

main().catch(function (e) {
  console.error(e.message);
});
