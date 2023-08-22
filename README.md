# [x-hub.js](https://github.com/therootcompany/x-hub.js)

X-Hub-Signature tools - lightweight, zero-dependency, JS with Types, WebCrypto

```js
let header = req.headers["x-hub-signature-256"];
let equal = await xhub.verify(header, payload);
```

```js
app.use("/api/webhooks/github", xhubMiddleware.hashPayload);
app.use("/api", bodyParser.json());

app.post("/api/webhooks/github", xhubMiddleware.verifyPayload, handleWebhook);
```

Works with GitHub, Facebook, and many other service that provide webhooks with
HMAC signatures.

- Install
- How to Verify with Express
- How to Test with Fetch
- How to Verify a Webhook header
- How to Sign a Webhook header
- How to Raw Verify Bytes
- How to Raw Sign Bytes

## Install

```sh
npm install --save x-hub
```

## How to Verify with Express

```js
let XHubExpress = require("x-hub/express.js");

let secret = "It's a secret to everybody!";
let hashes = ["sha256", "sha1"];
let xhubMiddleware = XHubExpress.create({ secret, hashes });

app.use("/api/webhooks/github", xhubMiddleware.hashPayload);
app.use("/api", bodyParser.json());
app.post("/api/webhooks/github", xhubMiddleware.verifyPayload, handleWebhook);
app.use("/", handleErrors);

async function handleWebhook(req, res) {
  let body = req.body;

  // do stuff

  res.json({ success: true });
}

function handleErrors(err, req, res, next) {
  if ("E_XHUB_WEBHOOK" !== e.code) {
    throw e;
  }

  // ...

  res.json({ error: e.message });
}
```

## How to Test with Fetch

You can test against your server.

```js
let XHub = require("x-hub");
let XHubFetch = require("x-hub/fetch.js");
let xhub = XHubFetch.create({ secret, hashes });

let url = "http://example.com/api/webhoks/github";
let payload = JSON.stringify({ foo: "bar" });
let header256 = await xhub.sign(opts.body, "sha256");
let resp = await xhub.fetch(url, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-Hub-Signature-256": header256,
  },
  body: payload,
});
let data = resp.json();

console.log(data);
```

## How to Verify a Webhook Header

```js
let XHub = require("x-hub");

let secret = "It's a secret to everybody!";
let xhub = XHub.create({ secret, hashes: ["sha256"] });

let hash = "sha256";
let header =
  "sha256=2d9425c2ae617d90196c5d22f48370822036174914268970cc864a7095b065dd";
let payload = JSON.stringify({ foo: "bar" });

let equal = await xhub.verify(header, payload);
console.log(equal);
```

## How to Sign a Webhook Header

```js
let XHub = require("x-hub");

let secret = "It's a secret to everybody!";
let hash = "sha256";
let xhub = XHub.create({ secret });

let payload = JSON.stringify({ foo: "bar" });
let header = await xhub.sign(payload, hash);

let resp = await fetch(url, {
  headers: {
    "Content-Type": "application/json",
    "X-Hub-Signature-256": header,
  },
  body: payload,
});
```

## How to Raw Verify Bytes

Note: although the HTTP header uses `sha256` as the hash algorithm, the
internally it is `SHA-256`.

```js
let XHub = require("x-hub");

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
console.log(equal);
```

## How to Raw Sign Bytes

Note: although the HTTP header uses `sha256` as the hash algorithm, internally
it is `SHA-256`.

```js
let XHub = require("x-hub");

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
```
