import { VerificationMethod } from 'did-resolver'
import { AbstractVerifier } from '../AbstractVerifier'
import verifyES256 from './verifiers/ES256Verifier'
import verifyES256K from './verifiers/ES256KVerifier'
import verifyEd25519 from './verifiers/EdDSAVerifier'

const algorithms = {
  ES256: verifyES256['ES256'],
  ES256K: verifyES256K['ES256K'],
  // This is a non-standard algorithm but retained for backwards compatibility
  // see https://github.com/decentralized-identity/did-jwt/issues/146
  'ES256K-R': verifyES256K['ES256K-R'],
  // This is actually incorrect but retained for backwards compatibility
  // see https://github.com/decentralized-identity/did-jwt/issues/130
  Ed25519: verifyEd25519['Ed25519'],
  EdDSA: verifyEd25519['EdDSA'],
}
type SupportedAlg = keyof typeof algorithms

const supportedAlgsAndVerMethods = {} as Record<SupportedAlg, string[]>
for (const alg in algorithms) {
  supportedAlgsAndVerMethods[alg as SupportedAlg] = algorithms[alg as SupportedAlg].supportedVerificationMethods
}
export class SoftwareVerifier extends AbstractVerifier {
  static supportedAlgsAndVerificationMethods = supportedAlgsAndVerMethods

  constructor() {
    super()
  }

  getSupportedVerificationMethods(alg?: SupportedAlg): string[] {
    if (alg === undefined) {
      return Object.values(algorithms).reduce<string[]>(
        (verificationMethodNames, verifier) => verificationMethodNames.concat(verifier.supportedVerificationMethods),
        []
      )
    }
    if (!algorithms[alg]) {
      throw new Error(`Unsupported algorithm ${alg}`)
    }
    return algorithms[alg].supportedVerificationMethods
  }

  verify(alg: SupportedAlg, data: string, signature: string, authenticators: VerificationMethod[]): VerificationMethod {
    const verifier = algorithms[alg]
    if (!verifier) {
      throw new Error(`Unsupported algorithm ${alg}`)
    }
    return verifier.verify(data, signature, authenticators)
  }
}
