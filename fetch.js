"use strict";

/**
 * @typedef XHubFetchPackage
 * @prop {XHubFetchCreate} create
 */

/**
 * @callback XHubFetchCreate
 * @param {XHub.XHubOptions} options
 * @returns {XHubFetch}
 */

/**
 * @typedef XHubFetch
 * @prop {fetch} fetch
 */

/** @type {XHubFetchPackage} */
let XHubFetch = module.exports;

let XHub = require("../x-hub-signature.js");

// "application/json"
// "application/json; charset=utf-8"
// "application/vnd.github.v3+json"
// XHubFetch._isJSON = /[\/\+]json($|;\s)/;

XHubFetch.create = function (options) {
  let xhub = XHub.create(options);

  let request = {};

  /** @type {fetch} */
  request.fetch = async function (url, opts) {
    if (!opts?.body) {
      throw new Error("no 'body' to sign");
    }
    //@ts-ignore
    let header = await xhub.sign(opts.body, "sha256");

    let fetchOpts = Object.assign({}, opts);
    if (!fetchOpts.headers) {
      /** @type {Object.<String, String>} */
      let headers = {};
      let isSha256 = header.startsWith("sha256=");
      if (isSha256) {
        headers["X-Hub-Signature-256"] = header;
      } else {
        headers["X-Hub-Signature"] = header;
      }

      //@ts-ignore
      Object.assign(fetchOpts.headers, headers);
    }

    let resp = await fetch(url, fetchOpts);
    return resp;
  };

  return request;
};
