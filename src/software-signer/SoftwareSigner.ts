import { AbstractSigner } from '../AbstractSigner'
import type { Signer } from '../JWT'
import { EcdsaSignature, toJose } from '../util'
import { EdDSASigner } from './signers/EdDSASigner'
import { ES256KSigner } from './signers/ES256KSigner'
import { ES256Signer } from './signers/ES256Signer'

export type SignAlgorithm = 'ES256' | 'ES256K' | 'ES256K-R' | 'EdDSA' | 'Ed25519'

const supportedAlgorithms: Array<SignAlgorithm> = ['ES256', 'ES256K', 'ES256K-R', 'EdDSA', 'Ed25519']

type AlgorithmPrivateKey = {
  [algorithm in SignAlgorithm]: Uint8Array
}

type Signers = {
  [algorithm in SignAlgorithm]: Signer
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function instanceOfEcdsaSignature(object: any): object is EcdsaSignature {
  return typeof object === 'object' && 'r' in object && 's' in object
}

class SoftwareSigner extends AbstractSigner {
  private signers: Signers
  static supportedAlgorithms: Array<SignAlgorithm> = supportedAlgorithms

  constructor(signerFn: Signer, algorithm: SignAlgorithm)
  constructor(privateKey: Uint8Array, algorithm: SignAlgorithm)
  constructor(privateKeys: AlgorithmPrivateKey)
  constructor(
    privateKeysOrSigner: Signer | Uint8Array | { [algorithm in SignAlgorithm]: Uint8Array },
    algorithm?: SignAlgorithm
  ) {
    super()
    this.signers = {} as Signers
    if (typeof privateKeysOrSigner === 'function') {
      if (!algorithm) {
        throw new Error('invalid_config: algorithm is required')
      }
      this.signers[algorithm] = privateKeysOrSigner
    } else if (privateKeysOrSigner instanceof Uint8Array) {
      if (!algorithm) {
        throw new Error('invalid_config: algorithm is required')
      }
      if (algorithm === 'ES256') {
        this.signers[algorithm] = ES256Signer(privateKeysOrSigner)
      } else if (algorithm === 'ES256K') {
        this.signers[algorithm] = ES256KSigner(privateKeysOrSigner)
      } else if (algorithm === 'ES256K-R') {
        this.signers[algorithm] = ES256KSigner(privateKeysOrSigner, true)
      } else if (algorithm === 'Ed25519' || algorithm === 'EdDSA') {
        this.signers[algorithm] = EdDSASigner(privateKeysOrSigner)
      } else {
        throw new Error(`Unsupported algorithm ${algorithm}`)
      }
    } else {
      for (const algorithm in privateKeysOrSigner) {
        if (algorithm === 'ES256') {
          this.signers[algorithm] = ES256Signer(privateKeysOrSigner[algorithm])
        } else if (algorithm === 'ES256K') {
          this.signers[algorithm] = ES256KSigner(privateKeysOrSigner[algorithm])
        } else if (algorithm === 'ES256K-R') {
          this.signers[algorithm] = ES256KSigner(privateKeysOrSigner[algorithm], true)
        } else if (algorithm === 'Ed25519' || algorithm === 'EdDSA') {
          this.signers[algorithm] = EdDSASigner(privateKeysOrSigner[algorithm])
        } else {
          throw new Error(`Unsupported algorithm ${algorithm}`)
        }
      }
    }
  }

  async sign(payload: string, algorithm: SignAlgorithm): Promise<string> {
    if (!this.signers[algorithm]) {
      throw new Error(`${algorithm} is not supported or intialized`)
    }
    const signature: EcdsaSignature | string = await this.signers[algorithm](payload)

    if (algorithm === 'ES256' || algorithm === 'ES256K' || algorithm === 'ES256K-R') {
      if (instanceOfEcdsaSignature(signature)) {
        return toJose(signature, algorithm === 'ES256K-R')
      } else {
        return signature
      }
    } else if (algorithm === 'Ed25519' || algorithm === 'EdDSA') {
      if (!instanceOfEcdsaSignature(signature)) {
        return signature
      } else {
        throw new Error('invalid_config: expected a signer function that returns a string instead of signature object')
      }
    } else {
      throw new Error(`Unsupported algorithm ${algorithm}`)
    }
  }
}

export { SoftwareSigner }
