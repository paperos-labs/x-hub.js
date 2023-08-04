"use strict";

//let XHub = require("x-hub");
let XHub = require("../x-hub-signature.js");

async function main() {
  let secret = "It's a secret to everybody!";
  let xhub = XHub.create({ secret });

  let header =
    "sha256=2d9425c2ae617d90196c5d22f48370822036174914268970cc864a7095b065dd";
  let payload = JSON.stringify({ foo: "bar" });

  let equal = await xhub.verify(header, payload);
  console.info(`Verified: ${equal}`);
}

main().catch(function (e) {
  console.error(e.message);
});
