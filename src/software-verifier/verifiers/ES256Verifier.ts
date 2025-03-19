import { p256 } from '@noble/curves/p256'
import { sha256 } from '../../Digest'
import { toSignatureObject2 } from '../../util'
import { VerificationMethod } from 'did-resolver'
import { extractPublicKeyBytes } from '../../util'
import { Verifier } from './types'

export function verify(data: string, signature: string, authenticators: VerificationMethod[]): VerificationMethod {
  const hash = sha256(data)
  const sig = p256.Signature.fromCompact(toSignatureObject2(signature).compact)
  const fullPublicKeys = authenticators.filter((a: VerificationMethod) => !a.ethereumAddress && !a.blockchainAccountId)

  const signer: VerificationMethod | undefined = fullPublicKeys.find((pk: VerificationMethod) => {
    try {
      const { keyBytes } = extractPublicKeyBytes(pk)
      return p256.verify(sig, hash, keyBytes)
    } catch (err) {
      return false
    }
  })

  if (!signer) throw new Error('invalid_signature: Signature invalid for JWT')
  return signer
}

export type ES256SupportedVerificationMethods = 'JsonWebKey2020' | 'Multikey' | 'EcdsaSecp256r1VerificationKey2019'
const supportedVerificationMethods: Array<ES256SupportedVerificationMethods> = [
  'JsonWebKey2020',
  'Multikey',
  'EcdsaSecp256r1VerificationKey2019',
]

const verifier: Verifier<'ES256', ES256SupportedVerificationMethods> = {
  ES256: { verify, supportedVerificationMethods },
}

export default verifier
