"use strict";

/** @type {XHubExpressPackage} */
let XHubExpress = module.exports;

let XHub = require("./x-hub-signature.js");

/**
 * @typedef XHubExpressPackage
 * @prop {XHubExpressCreate} create
 * @prop {String} XHubExpress._mismatchSignature
 * @prop {String} XHubExpress._missingSignature
 * @prop {_XHubPipe} _pipe
 * @returns {XHubExpress}
 */

/**
 * @typedef XHubExpress
 * @prop {import('express').Handler} readPayload
 * @prop {import('express').Handler} verifyPayload
 * @prop {_XHubPipeVerify} _pipeVerify
 */

/**
 * @typedef {XHub.XHubOptions & XHubExpressOptionsPart} XHubExpressOptions
 *
 * @typedef XHubExpressOptionsPart
 * @prop {Boolean} [allowUnsignedGet]
 * @prop {String} [xhubParam]
 */

XHubExpress._mismatchSignature =
  "X-Hub-Signature(-256) does not match sha1/sha256 hmac of the request body using the shared key";

XHubExpress._missingSignature = "X-Hub-Signature(-256) is not present";

XHubExpress.create = function (opts) {
  let xhub = XHub.create(opts);

  let xhubParam = opts.xhubParam;
  if (!xhubParam) {
    xhubParam = "_xhubSignaturePromise";
  }

  let routes = {};

  // IMPORTANT! This function MUST resolve synchronously so that req
  // can be read simultaneously by the body parser in the same tick

  /** @type {import('express').Handler} */
  routes.readPayload = function (req, res, next) {
    if (req.body) {
      let err = createError(
        "xhub webhook middleware must be 'app.use()'d  before any body parser",
      );
      next(err);
      return;
    }

    let xhubSig256 = req.headers["x-hub-signature-256"];
    let xhubSig1 = req.headers["x-hub-signature"];
    let xhubSig = xhubSig256 || xhubSig1;

    if (!xhubSig) {
      //@ts-ignore
      req[xhubParam] = null;
      next();
      return;
    }

    let hasBody =
      req.headers["content-length"] ||
      "chunked" === req.headers["transfer-encoding"];
    if (!hasBody) {
      //@ts-ignore
      req[xhubParam] = xhub.verify(xhubSig, "");
      next();
      return;
    }

    //@ts-ignore
    req[xhubParam] = routes._pipeVerify(req, xhubSig).catch(function (e) {
      console.error(e);
      return false;
    });
    next();
  };

  /** @type _XHubPipeVerify */
  routes._pipeVerify = async function (req, xhubSig) {
    let payload = await XHubExpress._pipe(req);
    let equal = await xhub.verify(xhubSig, payload);
    return equal;
  };

  /** @type {import('express').Handler} */
  routes.verifyPayload = async function (req, res, next) {
    //@ts-ignore
    let p = req[xhubParam];
    if (!p) {
      let err = createError(XHubExpress._missingSignature);
      next(err);
      return;
    }

    //@ts-ignore
    let result = await req[xhubParam];
    if (true === result) {
      next();
      return;
    }

    if (opts.allowUnsignedGet) {
      if ("GET" === req.method) {
        let xhubSig256 = req.headers["x-hub-signature-256"];
        let xhubSig1 = req.headers["x-hub-signature"];
        let xhubSig = xhubSig256 || xhubSig1;
        if (!xhubSig) {
          next();
          return;
        }
      }
    }

    let err = createError(XHubExpress._mismatchSignature);
    next(err);
  };

  return routes;
};

/**
 * Eventually WebCrypto should be streamable
 * https://webcrypto-streams.proposal.wintercg.org/
 *
 * @param {import('express').Request} req
 */
XHubExpress._pipe = async function (req) {
  /** @type {Array<Buffer>} */
  let chunks = [];
  req.on("readable", function () {
    for (;;) {
      let chunk = req.read();
      if (!chunk) {
        break;
      }
      chunks.push(chunk);
    }
  });

  return new Promise(function (resolve, reject) {
    req.on(
      "error",
      /** @param {Error} e */
      function (e) {
        reject(e);
      },
    );
    req.on("end", function () {
      let data = Buffer.concat(chunks);
      let text = data.toString("utf8");

      resolve(text);
    });
  });
};

/**
 * @param {String} msg
 */
function createError(msg) {
  let err = new Error(msg);
  err.message = msg;
  Object.assign(err, {
    code: "E_XHUB_WEBHOOK",
  });
  return err;
}

/**
 * @callback XHubExpressCreate
 * @param {XHubExpressOptions} opts
 * @returns {XHubExpress}
 */

/**
 * @callback _XHubPipeVerify
 * @param {import('express').Request} req
 * @param {String} xhubSig
 * @returns {Promise<Boolean>}
 */

/**
 * @callback _XHubPipe
 * @param {import('express').Request} req
 * @returns {Promise<String>}
 */
