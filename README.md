[![npm](https://img.shields.io/npm/dt/did-jwt.svg)](https://www.npmjs.com/package/did-jwt)
[![npm](https://img.shields.io/npm/v/did-jwt.svg)](https://www.npmjs.com/package/did-jwt)
[![Twitter Follow](https://img.shields.io/twitter/follow/veramolabs.svg?style=social&label=Follow)](https://twitter.com/veramolabs)
[![codecov](https://codecov.io/gh/decentralized-identity/did-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/decentralized-identity/did-jwt)

# did-jwt

The did-JWT library allows you to sign and verify [JSON Web Tokens (JWT)](https://tools.ietf.org/html/rfc7519)
using `ES256K` and `EdDSA` algorithms. The non-standard `ES256K-R` is also supported for backward compatibility
reasons, as well as the `Ed25519` legacy name for `EdDSA`.

Public keys are resolved using the [Decentralized ID (DID)](https://w3c.github.io/did-core/#identifier) of the signing
identity of the token, which is passed as the `iss` attribute of the JWT payload.

> **Pluggable algorithms.** Beyond the built-in algorithms, you can plug in your own signing/verification
> by passing an `AbstractSigner` to `createJWT` and an `AbstractVerifier` to `verifyJWT`. Use
> `CompositeSigner` / `CompositeVerifier` to serve several algorithms at once. See
> [Pluggable signing & verification](#pluggable-signing--verification) below.

## DID methods

All DID methods that can be resolved using the [`did-resolver`](https://github.com/decentralized-identity/did-resolver)
interface are supported for verification.

If your DID method requires a different signing algorithm than what is already supported, please create an issue.

## Installation

```bash
npm install did-jwt
```

or if you use `yarn`

```bash
yarn add did-jwt
```

## Example

### 1. Create a did-JWT

In practice, you must secure the key passed to `ES256KSigner`. The key provided in code below is for informational
purposes only.

```ts
import didJWT from 'did-jwt';

const signer = didJWT.ES256KSigner(didJWT.hexToBytes('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'))

let jwt = await didJWT.createJWT(
  { aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', iat: undefined, name: 'uPort Developer' },
  { issuer: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', signer },
  { alg: 'ES256K' }
)
console.log(jwt)
```

### 2. Decode a did-JWT

Try decoding the JWT. You can also do this using [jwt.io](https://jwt.io)

```js
//pass the jwt from step 1
let decoded = didJWT.decodeJWT(jwt)
console.log(decoded)
```

Once decoded a did-JWT will resemble:

```ts
expect(decoded).toEqual({
  header: { alg: 'ES256K', typ: 'JWT' },
  payload: {
    aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    name: 'uPort Developer',
    iss: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
  },
  signature: 'mAhpAnw-9u57hyAaDufj2GPMbmuZyPDlU7aYSUMKk7P_9_cF3iLk-hFjFhb5xaUQB5nXYrciw6ZJ2RSAZI-IDQ',
  data: 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJkaWQ6ZXRocjoweGYzYmVhYzMwYzQ5OGQ5ZTI2ODY1ZjM0ZmNhYTU3ZGJiOTM1YjBkNzQiLCJuYW1lIjoidVBvcnQgRGV2ZWxvcGVyIiwiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0'
})
```

### 3. Verify a did-JWT

You need to provide a did-resolver for the verify function. For this example we will use `did:ethr`, but there are other
methods available. For more information on configuring the Resolver object please
see [did-resolver](https://github.com/decentralized-identity/did-resolver#configure-resolver-object)

```bash
npm install ethr-did-resolver
```

```js
import {Resolver} from 'did-resolver';
import {getResolver} from 'ethr-did-resolver'

let resolver = new Resolver({...getResolver({infuraProjectId: '<get a free ID from infura.io>'})});

// use the JWT from step 1
let verificationResponse = await didJWT.verifyJWT(jwt, {
  resolver,
  audience: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
})
console.log(verificationResponse)
```

A verification response is an object resembling:

```typescript
expect(verificationResponse).toEqual({
  payload: {
    aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    name: 'uPort Developer',
    iss: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
  },
  didResolutionResult: {
    didDocumentMetadata: {},
    didResolutionMetadata: { contentType: 'application/did+ld+json' },
    didDocument: {
      '@context': [
        'https://www.w3.org/ns/did/v1',
        'https://w3id.org/security/suites/secp256k1recovery-2020/v2'
      ],
      id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
      verificationMethod: [
        {
          id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#controller',
          type: 'EcdsaSecp256k1RecoveryMethod2020',
          controller: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
          blockchainAccountId: 'eip155:1:0xF3beAC30C498D9E26865F34fCAa57dBB935b0D74'
        }
      ],
      authentication: [
        'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#controller'
      ],
      assertionMethod: [
        'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#controller'
      ]
    }
  },
  issuer: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
  signer: {
    id: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74#controller',
    type: 'EcdsaSecp256k1RecoveryMethod2020',
    controller: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
    blockchainAccountId: 'eip155:1:0xF3beAC30C498D9E26865F34fCAa57dBB935b0D74'
  },
  jwt: 'eyJhbGciOiJFUzI1NksiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJkaWQ6ZXRocjoweGYzYmVhYzMwYzQ5OGQ5ZTI2ODY1ZjM0ZmNhYTU3ZGJiOTM1YjBkNzQiLCJuYW1lIjoidVBvcnQgRGV2ZWxvcGVyIiwiaXNzIjoiZGlkOmV0aHI6MHhmM2JlYWMzMGM0OThkOWUyNjg2NWYzNGZjYWE1N2RiYjkzNWIwZDc0In0.mAhpAnw-9u57hyAaDufj2GPMbmuZyPDlU7aYSUMKk7P_9_cF3iLk-hFjFhb5xaUQB5nXYrciw6ZJ2RSAZI-IDQ',
  policies: {}
})
```

## Pluggable signing & verification

The built-in algorithms (`ES256` / `ES256K` / `ES256K-R` / `EdDSA`) work out of the box, with no extra
setup, through the bundled `SoftwareSigner` and `SoftwareVerifier`. Beyond those, you can supply your own
signing or verification logic — or use one shipped as a separate package, such as `did-jwt-eip712-signer`
(EIP-712 typed-data) or `did-jwt-webauthn-signer` (passkeys).

### `AbstractSigner` / `AbstractVerifier`

A custom algorithm is a pair of classes:

```ts
import { AbstractSigner, AbstractVerifier } from 'did-jwt'

class MySigner extends AbstractSigner {
  // which JWT `alg` values this signer can produce
  static supportedAlgorithms = ['MyAlg']

  async sign(data: string | Uint8Array, alg: string): Promise<string> {
    /* return the base64url signature segment */
  }
}

class MyVerifier extends AbstractVerifier {
  // maps each `alg` to the DID verification-method types it can check
  static supportedAlgorithmsAndVerificationMethods = { MyAlg: ['JsonWebKey2020'] }

  verify(alg: string, data: string, signature: string, authenticators: VerificationMethod[]) {
    /* return the VerificationMethod that verified the signature, or throw */
  }

  getSupportedVerificationMethods(alg: string): string[] {
    return MyVerifier.supportedAlgorithmsAndVerificationMethods[alg]
  }
}
```

Pass instances straight into the core functions:

```ts
import { createJWT, verifyJWT } from 'did-jwt'

const jwt = await createJWT(payload, { issuer, signer: new MySigner(), alg: 'MyAlg' })
const verified = await verifyJWT(jwt, { resolver }, new MyVerifier())
```

`createJWT` also still accepts a plain legacy `Signer` function — it is auto-wrapped in `SoftwareSigner`.
`verifyJWT` defaults to `SoftwareVerifier` when no verifier is passed.

> **Note:** `AbstractVerifier.verify` may return a `VerificationMethod` **or a `Promise`** of one, so
> verification is async. `verifyJWS`, `verifyJWSDecoded` and `verifyJWTDecoded` are therefore `async` —
> `await` them.

### `CompositeSigner` / `CompositeVerifier`

`createJWT` / `verifyJWT` each take a single signer / verifier. To serve several algorithms at once, wrap
them in a composite, which dispatches by the JWT `alg`:

```ts
import { createJWT, verifyJWT, CompositeSigner, CompositeVerifier, SoftwareSigner, SoftwareVerifier } from 'did-jwt'
import { Eip712Signer, Eip712Verifier } from 'did-jwt-eip712-signer'

const signer = new CompositeSigner([new SoftwareSigner(privateKeys), new Eip712Signer(wallet)])
const jwt = await createJWT(payload, { issuer, signer, alg: 'EIP712' })

const verifier = new CompositeVerifier([new SoftwareVerifier(), new Eip712Verifier()])
const verified = await verifyJWT(jwt, { resolver }, verifier)
```

Each registered signer/verifier's algorithms are auto-discovered from its static `supportedAlgorithms` /
`supportedAlgorithmsAndVerificationMethods`. You can also register explicitly — useful when a class does
not declare its algorithms statically — and chain registrations:

```ts
const verifier = new CompositeVerifier()
  .register(new SoftwareVerifier())
  .register(new Eip712Verifier(), ['EIP712']) // explicit algorithms
```

Registering an algorithm that is already present replaces the previous signer/verifier for it.
