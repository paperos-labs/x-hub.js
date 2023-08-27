"use strict";

let XHub = module.exports;

let Crypto = require("crypto");
let encoder = new TextEncoder();

/**
 * @typedef XHub
 * @prop {Object.<String, String>} _algosMap
 * @prop {Array<String>} _algos
 * @prop {XHubBytesToHex} _bytesToHex
 * @prop {XHubCreate} create
 * @prop {XHubHexToBytes} _hexToBytes
 */

/**
 * @typedef XHubSignature
 * @prop {String} _defaultHash
 * @prop {XHubSign} sign
 * @prop {XHubSignBytes} signBytes
 * @prop {XHubVerify} verify
 * @prop {XHubVerifyBytes} verifyBytes
 */

XHub._algosMap = {
  sha1: "SHA-1",
  sha256: "SHA-256",
};
XHub._algos = Object.keys(XHub._algosMap);

/** @type XHubCreate */
XHub.create = function ({ secret, hashes }) {
  if (!secret) {
    throw new Error(`'secret' must not be empty`);
  }

  if (!hashes) {
    hashes = ["sha256"];
  }

  let algHash = "SHA-256";
  let defaultHash = hashes[0];
  if (defaultHash === "sha1") {
    algHash = "SHA-1";
  }

  let keyBytes = encoder.encode(secret);

  let xhub = {};

  xhub._defaultHash = defaultHash;

  /** @type XHubSignBytes */
  xhub.signBytes = async function (payloadBytes, algo = algHash) {
    let algorithm = { name: "HMAC", hash: { name: algo } };
    let extractable = false;
    let key = await Crypto.subtle.importKey(
      "raw",
      keyBytes,
      algorithm,
      extractable,
      ["sign", "verify"],
    );

    let sigAb = await Crypto.subtle.sign(algorithm.name, key, payloadBytes);
    let sigBytes = new Uint8Array(sigAb);

    return sigBytes;
  };

  /** @type XHubSign */
  xhub.sign = async function (payload, alg = "sha256") {
    let algo = XHub._algosMap[alg];
    if (!algo) {
      throw new Error(`'alg' must be one of '${XHub._algos}', not '${alg}'`);
    }

    let payloadBytes = encoder.encode(payload);
    let sigBytes = await xhub.signBytes(payloadBytes, algo);
    let sigHex = XHub._bytesToHex(sigBytes);
    let headerValue = alg + "=" + sigHex;

    return headerValue;
  };

  /** @type XHubVerifyBytes */
  xhub.verifyBytes = async function (sigBytes, payloadBytes, algo) {
    let algorithm = { name: "HMAC", hash: { name: algo } };

    let extractable = false;
    let key = await Crypto.subtle.importKey(
      "raw",
      keyBytes,
      algorithm,
      extractable,
      ["sign", "verify"],
    );

    let equal = await Crypto.subtle.verify(
      algorithm.name,
      key,
      sigBytes,
      payloadBytes,
    );
    return equal;
  };

  /** @type XHubVerify */
  xhub.verify = async function (header, payload, alg) {
    let parts = header.split("=");
    let _alg = parts[0];
    let algo = XHub._algosMap[_alg];
    let sigHex = parts[1];

    if (parts.length !== 2) {
      throw new Error(`'header' must be in the format 'algorthim=signature'`);
    }

    if (alg) {
      if (alg !== _alg) {
        throw new Error(`header 'alg' must be '${alg}', not '${_alg}'`);
      }
    } else {
      let allowed = hashes?.includes(_alg);
      if (!allowed) {
        throw new Error(
          `header 'alg' must be one of '${hashes}', not '${_alg}'`,
        );
      }
    }

    if (!algo) {
      throw new Error(
        `header 'alg' must be one of '${XHub._algos}', not '${_alg}'`,
      );
    }

    let sigBytes = XHub._hexToBytes(sigHex);
    let payloadBytes = encoder.encode(payload);

    let equal = await xhub.verifyBytes(sigBytes, payloadBytes, algo);
    return equal;
  };

  return xhub;
};

/** @type {XHubBytesToHex} */
XHub._bytesToHex = function (bytes) {
  /** @type {Array<String>} */
  let hex = [];

  bytes.forEach(function (b) {
    let h = b.toString(16);
    h = h.padStart(2, "0");
    hex.push(h);
  });

  return hex.join("");
};

/** @type {XHubHexToBytes} */
XHub._hexToBytes = function (hex) {
  let len = hex.length / 2;
  let bytes = new Uint8Array(len);

  let index = 0;
  for (let i = 0; i < hex.length; i += 2) {
    let c = hex.slice(i, i + 2);
    let b = parseInt(c, 16);
    bytes[index] = b;
    index += 1;
  }

  return bytes;
};

// Objects

/**
 * @typedef {"sha1"|"sha256"} XHubHeaderAlgo
 */

/**
 * @typedef {"SHA-1"|"SHA-256"} XHubAlgoName
 */

/**
 * @typedef XHubOptions
 * @prop {String} secret
 * @prop {Array<String>} [hashes] - [ "sha256", "sha1" ] allowed hashes (default first)
 */

// Functions

/**
 * @callback XHubBytesToHex
 * @param {Uint8Array} bytes
 * @returns {String} - hex
 */

/**
 * @callback XHubCreate
 * @param {XHubOptions} opts
 * @returns {XHubSignature}
 */

/**
 * @callback XHubHexToBytes
 * @param {String} hex
 * @returns {Uint8Array} - bytes
 */

/**
 * @callback XHubSign
 * @param {String} payload
 * @param {String} [alg] - "sha1", "sha256"
 * @returns {Promise<String>} - type=hash
 */

/**
 * @callback XHubSignBytes
 * @param {Uint8Array} payloadBytes
 * @param {String} [algo] - "SHA-1", "SHA-256"
 * @returns {Promise<Uint8Array>}
 */

/**
 * @callback XHubVerify
 * @param {String} header
 * @param {String} payload
 * @param {String} [alg] - "sha1", "sha256"
 * @returns {Promise<Boolean>}
 */

/**
 * @callback XHubVerifyBytes
 * @param {Uint8Array} sigBytes
 * @param {Uint8Array} payloadBytes
 * @param {String} [algo] - "SHA-1", "SHA-256"
 * @returns {Promise<Boolean>}
 */
