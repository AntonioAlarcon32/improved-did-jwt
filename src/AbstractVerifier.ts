import { VerificationMethod } from 'did-resolver'

export abstract class AbstractVerifier {
  abstract verify(
    alg: string,
    data: string,
    signature: string,
    authenticators: VerificationMethod[]
  ): VerificationMethod

  static supportedAlgorithmsAndVerificationMethods: Record<string, string[]>

  abstract getSupportedVerificationMethods(alg?: string): string[]
}
