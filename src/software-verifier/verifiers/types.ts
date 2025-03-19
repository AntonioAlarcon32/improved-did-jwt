import { type VerificationMethod } from 'did-resolver'

export interface VerifierAlg<T> {
  verify: (data: string, signature: string, authenticators: VerificationMethod[]) => VerificationMethod
  supportedVerificationMethods: T[]
}

export type Verifier<K extends string, T extends string> = {
  [alg in K]: VerifierAlg<T>
}
