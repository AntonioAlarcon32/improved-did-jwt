import { describe, expect, it } from '@jest/globals'
import type { Resolvable, VerificationMethod } from 'did-resolver'
import { hexToBytes, bytesToBase64url, stringToBytes } from '../util.js'
import { createJWT, verifyJWT } from '../JWT.js'
import { AbstractSigner } from '../AbstractSigner.js'
import { AbstractVerifier } from '../AbstractVerifier.js'
import { CompositeSigner } from '../CompositeSigner.js'
import { CompositeVerifier } from '../CompositeVerifier.js'
import { SoftwareSigner } from '../software-signer/SoftwareSigner.js'
import { SoftwareVerifier } from '../software-verifier/SoftwareVerifier.js'

const privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const publicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
const address = '0xf3beac30c498d9e26865f34fcaa57dbb935b0d74'
const did = `did:ethr:${address}`

// A minimal external algorithm module: the "signature" is just the base64url of the
// signing input, and the verifier matches authenticators of a dedicated method type.
const FAKE_ALG = 'FAKE'
const FAKE_METHOD_TYPE = 'FakeVerificationKey2024'

class FakeSigner extends AbstractSigner {
  static supportedAlgorithms = [FAKE_ALG]

  async sign(data: string | Uint8Array, algorithm: string): Promise<string> {
    if (algorithm !== FAKE_ALG) throw new Error(`Unsupported algorithm ${algorithm}`)
    const input = typeof data === 'string' ? data : new TextDecoder().decode(data)
    return bytesToBase64url(stringToBytes(input))
  }
}

class FakeVerifier extends AbstractVerifier {
  static supportedAlgorithmsAndVerificationMethods: Record<string, string[]> = {
    [FAKE_ALG]: [FAKE_METHOD_TYPE],
  }

  getSupportedVerificationMethods(alg?: string): string[] {
    if (alg === undefined || alg === FAKE_ALG) return [FAKE_METHOD_TYPE]
    throw new Error(`Unsupported algorithm ${alg}`)
  }

  // async on purpose: exercises the Promise side of AbstractVerifier.verify
  async verify(
    alg: string,
    data: string,
    signature: string,
    authenticators: VerificationMethod[]
  ): Promise<VerificationMethod> {
    if (alg !== FAKE_ALG) throw new Error(`Unsupported algorithm ${alg}`)
    const match = authenticators.find(
      (auth) => auth.type === FAKE_METHOD_TYPE && signature === bytesToBase64url(stringToBytes(data))
    )
    if (!match) throw new Error('invalid_signature: fake signature mismatch')
    return match
  }
}

// A signer with no static supportedAlgorithms, to test explicit registration
class UndeclaredSigner extends AbstractSigner {
  async sign(): Promise<string> {
    return 'sig'
  }
}

class UndeclaredVerifier extends AbstractVerifier {
  getSupportedVerificationMethods(): string[] {
    return []
  }

  verify(): VerificationMethod {
    throw new Error('invalid_signature: never matches')
  }
}

const didDocument = {
  '@context': 'https://w3id.org/did/v1',
  id: did,
  verificationMethod: [
    {
      id: `${did}#keys-1`,
      type: 'EcdsaSecp256k1VerificationKey2019',
      controller: did,
      publicKeyHex: publicKey,
    },
    {
      id: `${did}#keys-fake`,
      type: FAKE_METHOD_TYPE,
      controller: did,
    },
  ],
  authentication: [`${did}#keys-1`, `${did}#keys-fake`],
  assertionMethod: [`${did}#keys-1`, `${did}#keys-fake`],
}

const resolver = {
  resolve: async () => ({
    didDocument,
    didDocumentMetadata: {},
    didResolutionMetadata: {},
  }),
} as unknown as Resolvable

describe('CompositeSigner', () => {
  const softwareSigner = new SoftwareSigner(hexToBytes(privateKey), 'ES256K')

  it('auto-registers algorithms from the static supportedAlgorithms', () => {
    const composite = new CompositeSigner([new FakeSigner()])
    expect(composite.supportedAlgorithms()).toEqual([FAKE_ALG])
  })

  it('dispatches sign() to the signer registered for the algorithm', async () => {
    const composite = new CompositeSigner([new FakeSigner()]).register(softwareSigner, ['ES256K'])
    const fakeSig = await composite.sign('a.b', FAKE_ALG)
    expect(fakeSig).toEqual(bytesToBase64url(stringToBytes('a.b')))
    const es256kSig = await composite.sign('a.b', 'ES256K')
    expect(es256kSig).toEqual(await softwareSigner.sign('a.b', 'ES256K'))
  })

  it('rejects unregistered algorithms', async () => {
    const composite = new CompositeSigner([new FakeSigner()])
    await expect(composite.sign('a.b', 'ES256K')).rejects.toThrow(/Unsupported algorithm ES256K/)
  })

  it('requires explicit algorithms for signers without the static', () => {
    expect(() => new CompositeSigner([new UndeclaredSigner()])).toThrow(/invalid_config/)
    const composite = new CompositeSigner().register(new UndeclaredSigner(), ['CUSTOM'])
    expect(composite.supportedAlgorithms()).toEqual(['CUSTOM'])
  })

  it('later registrations replace earlier ones for the same algorithm', async () => {
    const composite = new CompositeSigner().register(new UndeclaredSigner(), [FAKE_ALG]).register(new FakeSigner())
    expect(await composite.sign('a.b', FAKE_ALG)).toEqual(bytesToBase64url(stringToBytes('a.b')))
  })
})

describe('CompositeVerifier', () => {
  it('auto-registers algorithms from the static supportedAlgorithmsAndVerificationMethods', () => {
    const composite = new CompositeVerifier([new SoftwareVerifier(), new FakeVerifier()])
    expect(composite.supportedAlgorithms()).toEqual(expect.arrayContaining(['ES256K', 'EdDSA', FAKE_ALG]))
  })

  it('returns the union of verification methods when no alg is given', () => {
    const composite = new CompositeVerifier([new SoftwareVerifier(), new FakeVerifier()])
    const methods = composite.getSupportedVerificationMethods()
    expect(methods).toEqual(expect.arrayContaining(['EcdsaSecp256k1VerificationKey2019', FAKE_METHOD_TYPE]))
  })

  it('dispatches getSupportedVerificationMethods(alg) to the registered verifier', () => {
    const composite = new CompositeVerifier([new SoftwareVerifier(), new FakeVerifier()])
    expect(composite.getSupportedVerificationMethods(FAKE_ALG)).toEqual([FAKE_METHOD_TYPE])
    expect(() => composite.getSupportedVerificationMethods('NOPE')).toThrow(/Unsupported algorithm NOPE/)
  })

  it('requires explicit algorithms for verifiers without the static', () => {
    expect(() => new CompositeVerifier([new UndeclaredVerifier()])).toThrow(/invalid_config/)
    const composite = new CompositeVerifier().register(new UndeclaredVerifier(), ['CUSTOM'])
    expect(composite.supportedAlgorithms()).toEqual(['CUSTOM'])
  })

  it('rejects unregistered algorithms on verify()', () => {
    const composite = new CompositeVerifier([new FakeVerifier()])
    expect(() => composite.verify('ES256K', 'a.b', 'sig', [])).toThrow(/Unsupported algorithm ES256K/)
  })
})

describe('createJWT/verifyJWT through composite signer and verifier', () => {
  const compositeSigner = new CompositeSigner([
    new SoftwareSigner(hexToBytes(privateKey), 'ES256K'),
    new FakeSigner(),
  ])
  const compositeVerifier = new CompositeVerifier([new SoftwareVerifier(), new FakeVerifier()])

  it('round-trips a built-in algorithm (ES256K)', async () => {
    const jwt = await createJWT({ requested: ['name'] }, { issuer: did, signer: compositeSigner, alg: 'ES256K' })
    const { verified, signer } = await verifyJWT(jwt, { resolver }, compositeVerifier)
    expect(verified).toBe(true)
    expect((signer as VerificationMethod).id).toEqual(`${did}#keys-1`)
  })

  it('round-trips an external algorithm through the same instances', async () => {
    const jwt = await createJWT({ requested: ['name'] }, { issuer: did, signer: compositeSigner, alg: FAKE_ALG })
    const { verified, signer } = await verifyJWT(jwt, { resolver }, compositeVerifier)
    expect(verified).toBe(true)
    expect((signer as VerificationMethod).id).toEqual(`${did}#keys-fake`)
  })

  it('fails verification when the external algorithm is not registered', async () => {
    const jwt = await createJWT({ requested: ['name'] }, { issuer: did, signer: compositeSigner, alg: FAKE_ALG })
    const builtInOnly = new CompositeVerifier([new SoftwareVerifier()])
    await expect(verifyJWT(jwt, { resolver }, builtInOnly)).rejects.toThrow(/Unsupported algorithm FAKE/)
  })
})
