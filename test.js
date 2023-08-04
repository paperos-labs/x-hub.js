"use strict";

let Zora = require("zora");

let XHub = require("./x-hub-signature.js");
let XHubExpress = require("./express.js");

let secret = `It's a Secret to Everybody`;

let payload = "Hello, World!";
let sha256 = "757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";
let sha1 = "01dc10d0c83e72ed246219cdd91669667fe2ca59";

let secretBad = `Xt's a Secret to Everybody`;
let xhubBad = XHub.create({ secret: secretBad });
let payloadBad = "Xello, World!";

Zora.test("check sha1 signatures", async function (t) {
  let xhub = XHub.create({ secret });
  let headerValue = `sha1=${sha1}`;

  {
    let headerTest = await xhub.sign(payload, "sha1");
    let same = headerValue === headerTest;
    t.ok(same, "good test header should match known header");
  }

  {
    let equal = await xhub.verify(headerValue, payload, "sha1");
    t.ok(equal, "good test header and payload should verify");
  }

  {
    let headerTestBad = await xhubBad.sign(payload, "sha1");
    let same = headerValue === headerTestBad;
    t.notOk(same, "bad test header should NOT match known header");
  }

  {
    let headerBadPayload = await xhub.sign(payloadBad, "sha1");
    let equalBadPayload = await xhub.verify(headerBadPayload, payload, "sha1");
    t.notOk(equalBadPayload, "bad test payload should NOT verify");
  }

  {
    let equalBadHash = await xhub.verify(headerValue, payloadBad, "sha1");
    t.notOk(equalBadHash, "bad test header should NOT verify");
  }
});

Zora.test("check sha256 signatures", async function (t) {
  let xhub = XHub.create({ secret });
  let headerValue = `sha256=${sha256}`;

  {
    let headerTest = await xhub.sign(payload, "sha256");
    let same = headerValue === headerTest;
    t.ok(same, "good test header should match known header");
  }

  {
    let equal = await xhub.verify(headerValue, payload);
    t.ok(equal, "good test header and payload should verify");
  }

  {
    let headerTestBad = await xhubBad.sign(payload, "sha256");
    let same = headerValue === headerTestBad;
    t.notOk(same, "bad test header should NOT match known header");
  }

  {
    let headerBadPayload = await xhub.sign(payloadBad, "sha256");
    let equalBadPayload = await xhub.verify(headerBadPayload, payload);
    t.notOk(equalBadPayload, "bad test payload should NOT verify");
  }

  {
    let equalBadHash = await xhub.verify(headerValue, payloadBad);
    t.notOk(equalBadHash, "bad test header should NOT verify");
  }
});

Zora.test("check allowed hash algos", async function (t) {
  let headerValue = `sha1=${sha1}`;

  {
    let xhub = XHub.create({ secret });
    let msg = "should throw when using 'sha1' unsupported hash";
    try {
      await xhub.verify(headerValue, payload);
      t.ok(false, msg);
    } catch (e) {
      t.ok(true, msg);
    }
  }

  {
    let xhub = XHub.create({ secret });
    let msg = "should NOT throw when using 'sha1' explicitly";
    try {
      await xhub.verify(headerValue, payload, "sha1");
      t.ok(true, msg);
    } catch (e) {
      //@ts-ignore
      t.ok(false, `${msg}:\n\t${e.message}`);
    }
  }

  {
    let xhub = XHub.create({ secret, hashes: ["sha1"] });
    let msg = "should NOT throw when allowing 'sha1'";
    try {
      await xhub.verify(headerValue, payload);
      t.ok(true, msg);
    } catch (e) {
      //@ts-ignore
      t.ok(false, `${msg}:\n\t${e.message}`);
    }
  }

  {
    let xhub = XHub.create({ secret, hashes: ["sha1"] });
    let headerValue256 = `sha256=${sha256}`;
    let msg =
      "should NOT throw on explicit 'sha256', even when restricted to 'sha1'";
    try {
      await xhub.verify(headerValue256, payload, "sha256");
      t.ok(true, msg);
    } catch (e) {
      //@ts-ignore
      t.ok(false, `${msg}:\n\t${e.message}`);
    }
  }

  {
    let xhub = XHub.create({ secret, hashes: ["sha1"] });
    let headerValue256 = `sha256=${sha256}`;
    let msg = "should throw on 'sha256' when restricted to 'sha1'";
    try {
      await xhub.verify(headerValue256, payload);
      t.ok(false, msg);
    } catch (e) {
      //@ts-ignore
      t.ok(true, msg);
    }
  }
});

Zora.test("test express app", async function (t) {
  let FsSync = require("node:fs");
  let Stream = require("node:stream");

  let xhub = XHub.create({ secret });
  let xhubMiddleware = XHubExpress.create({ secret });

  let payloadBytes = FsSync.readFileSync(__filename, "utf8");
  let sig = await xhub.sign(payloadBytes);

  // test that unverified signature fails
  // faux request as file stream
  let req = FsSync.createReadStream(__filename);
  //@ts-ignore
  req.headers = {
    "x-hub-signature-256": sig,
    "content-length": payloadBytes.length,
  };
  await new Promise(function (resolve, reject) {
    //@ts-ignore
    toBuffer(req, null, function _next2(err) {
      if (err) {
        // not expected to get this error
        reject(err);
        return;
      }
      //@ts-ignore
      xhubMiddleware.verifyPayload(req, null, function _next3(err) {
        if (err) {
          reject(err);
          return;
        }
        resolve(null);
      });
    });
  })
    .catch(Object)
    .then(function (err) {
      let msg = "bad/missing signature should fail";
      if (err?.message === XHubExpress._mismatchSignature) {
        t.ok(true, `${msg}: err?.message`);
        return;
      }

      t.ok(false, msg);
    });

  // test that verified signature passes
  req = FsSync.createReadStream(__filename);
  //@ts-ignore
  req.headers = {
    "x-hub-signature-256": sig,
    "content-length": payloadBytes.length,
  };
  await new Promise(function (resolve, reject) {
    //@ts-ignore
    xhubMiddleware.readPayload(req, null, function _next(err) {
      if (err) {
        // not expected (shouldn't be possible)
        reject(err);
        return;
      }

      //@ts-ignore
      toBuffer(req, null, function _next2(err) {
        if (err) {
          // not expected (shouldn't be possible)
          reject(err);
          return;
        }

        //@ts-ignore
        xhubMiddleware.verifyPayload(req, null, function _next3(err) {
          if (err) {
            // not expected (shouldn't be possible)
            reject(err);
            return;
          }

          t.ok(true, `correct signature should verify`);
          resolve(null);
        });
      });
    });
  }).catch(function (e) {
    //t.ok(false, `should not have failed: ${e.message}`);
    t.ok(false, `should not have failed: ${e.stack}`);
  });

  /** @type {import('express').Handler} */
  function toBuffer(req, _, next) {
    var converter = new Stream.Writable();

    //@ts-ignore
    converter.data = [];
    //@ts-ignore
    converter._write = function (chunk) {
      //@ts-ignore
      converter.data.push(chunk);
    };

    converter.on("finish", function () {
      //@ts-ignore
      let buf = Buffer.concat(converter.data);
      req.body = buf.toString("utf8");
      next();
    });
    req.pipe(converter);
    req.on("end", function () {
      // docs say 'finish' should emit when end() is called
      // but experimentation says otherwise...
      converter.end();
      converter.emit("finish");
    });
  }
});
