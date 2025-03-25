import { VerificationMethod } from 'did-resolver'

export abstract class AbstractVerifier {
  /**
   * Verifies the signature of data using the given algorithm and authenticators
   *
   * @param alg - the algorithm to use for verification
   * @param data - the original data that was signed
   * @param signature - the signature using algorithm `alg` to verify
   * @param authenticators - the list of verification methods to use for verification
   *
   * @returns The verification method that successfully verified the signature
   *
   * @throws Error If the algorithm is not supported
   * @throws Error If the signature is invalid
   */
  abstract verify(
    alg: string,
    data: string,
    signature: string,
    authenticators: VerificationMethod[]
  ): VerificationMethod

  /**
   * Returns a list of supported verification methods for every algorithm supported by this verifier class
   *
   * @returns A record of supported algorithms and their verification methods
   */
  static supportedAlgorithmsAndVerificationMethods: Record<string, string[]>

  /**
   * Returns a list of supported verification methods for the given algorithm
   *
   * @param alg The algorithm to get supported verification methods for. If not provided, returns all supported verification methods
   * @returns A list of supported verification methods
   * @throws Error If the algorithm is not supported
   */
  abstract getSupportedVerificationMethods(alg?: string): string[]
}
