import { AbstractSigner } from './AbstractSigner.js'

/**
 * An {@link AbstractSigner} that holds multiple signers and dispatches `sign` calls
 * to the one registered for the requested JWT `alg`.
 *
 * This is the signer-side counterpart of {@link CompositeVerifier}: it lets a single
 * signer instance passed to `createJWT` serve several algorithms provided by
 * independently distributed modules (e.g. `SoftwareSigner` for the built-in algs
 * plus an external `Eip712Signer`).
 *
 * @example
 * ```ts
 * const signer = new CompositeSigner([new SoftwareSigner(privateKeys), new Eip712Signer(wallet)])
 * const jwt = await createJWT(payload, { issuer, signer, alg: 'EIP712' })
 * ```
 */
export class CompositeSigner extends AbstractSigner {
  private readonly signers: Map<string, AbstractSigner> = new Map()

  /**
   * @param signers - signers to register. Each must declare a static `supportedAlgorithms`;
   *   use {@link CompositeSigner.register} to provide the algorithms explicitly otherwise.
   */
  constructor(signers: AbstractSigner[] = []) {
    super()
    for (const signer of signers) {
      this.register(signer)
    }
  }

  /**
   * Registers a signer for one or more algorithms. When `algorithms` is omitted, they are
   * read from the signer class' static `supportedAlgorithms`. Registering an algorithm that
   * is already present replaces the previous signer for that algorithm.
   *
   * @returns this, so registrations can be chained
   */
  register(signer: AbstractSigner, algorithms?: string[]): this {
    const algs = algorithms ?? (signer.constructor as typeof AbstractSigner).supportedAlgorithms
    if (!algs || algs.length === 0) {
      throw new Error(
        'invalid_config: signer does not declare static supportedAlgorithms; pass the algorithms explicitly'
      )
    }
    for (const alg of algs) {
      this.signers.set(alg, signer)
    }
    return this
  }

  /**
   * The algorithms currently registered on this instance.
   */
  supportedAlgorithms(): string[] {
    return Array.from(this.signers.keys())
  }

  async sign(data: string | Uint8Array, algorithm: string): Promise<string> {
    const signer = this.signers.get(algorithm)
    if (!signer) {
      throw new Error(`Unsupported algorithm ${algorithm}`)
    }
    return signer.sign(data, algorithm)
  }
}
