import { VerificationMethod } from 'did-resolver'
import { AbstractVerifier } from './AbstractVerifier.js'

/**
 * An {@link AbstractVerifier} that holds multiple verifiers and dispatches by JWT `alg`,
 * the same way Veramo's KeyManager fronts multiple KMS implementations.
 *
 * `verifyJWT` accepts a single verifier instance; this class is what makes that seam
 * scale to many independently distributed algorithm modules:
 *
 * @example
 * ```ts
 * const verifier = new CompositeVerifier([new SoftwareVerifier(), new Eip712Verifier()])
 * const result = await verifyJWT(jwt, { resolver }, verifier)
 * ```
 */
export class CompositeVerifier extends AbstractVerifier {
  private readonly verifiers: Map<string, AbstractVerifier> = new Map()

  /**
   * @param verifiers - verifiers to register. Each must declare a static
   *   `supportedAlgorithmsAndVerificationMethods`; use {@link CompositeVerifier.register}
   *   to provide the algorithms explicitly otherwise.
   */
  constructor(verifiers: AbstractVerifier[] = []) {
    super()
    for (const verifier of verifiers) {
      this.register(verifier)
    }
  }

  /**
   * Registers a verifier for one or more algorithms. When `algorithms` is omitted, they are
   * read from the verifier class' static `supportedAlgorithmsAndVerificationMethods`.
   * Registering an algorithm that is already present replaces the previous verifier for it.
   *
   * @returns this, so registrations can be chained
   */
  register(verifier: AbstractVerifier, algorithms?: string[]): this {
    const algs =
      algorithms ??
      Object.keys((verifier.constructor as typeof AbstractVerifier).supportedAlgorithmsAndVerificationMethods ?? {})
    if (algs.length === 0) {
      throw new Error(
        'invalid_config: verifier does not declare static supportedAlgorithmsAndVerificationMethods; ' +
          'pass the algorithms explicitly'
      )
    }
    for (const alg of algs) {
      this.verifiers.set(alg, verifier)
    }
    return this
  }

  /**
   * The algorithms currently registered on this instance.
   */
  supportedAlgorithms(): string[] {
    return Array.from(this.verifiers.keys())
  }

  getSupportedVerificationMethods(alg?: string): string[] {
    if (alg === undefined) {
      const methods = new Set<string>()
      for (const [registeredAlg, verifier] of this.verifiers) {
        for (const method of verifier.getSupportedVerificationMethods(registeredAlg)) {
          methods.add(method)
        }
      }
      return Array.from(methods)
    }
    const verifier = this.verifiers.get(alg)
    if (!verifier) {
      throw new Error(`Unsupported algorithm ${alg}`)
    }
    return verifier.getSupportedVerificationMethods(alg)
  }

  verify(
    alg: string,
    data: string,
    signature: string,
    authenticators: VerificationMethod[]
  ): VerificationMethod | Promise<VerificationMethod> {
    const verifier = this.verifiers.get(alg)
    if (!verifier) {
      throw new Error(`Unsupported algorithm ${alg}`)
    }
    return verifier.verify(alg, data, signature, authenticators)
  }
}
