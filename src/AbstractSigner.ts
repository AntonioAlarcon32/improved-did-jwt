export abstract class AbstractSigner {
  /**
   * Signs the given data using the given algorithm
   * @param data The data to sign
   * @param algorithm The algorithm to use
   * @returns The signature
   * @throws Error
   * If the algorithm is not supported
   * @throws Error
   * If there is an error signing the data
   */
  abstract sign(data: string | Uint8Array, algorithm: string): Promise<string>

  /**
   * Returns a list of supported signature algorithms for this signer
   */
  static supportedAlgorithms?: string[]
}
