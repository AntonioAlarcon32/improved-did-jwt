import { VerificationMethod } from 'did-resolver'
import { base64ToBytes, extractPublicKeyBytes, stringToBytes } from '../../util'
import { ed25519 } from '@noble/curves/ed25519'
import { Verifier } from './types'

type SupportedAlgs = 'Ed25519' | 'EdDSA'
type SupportedVerificationMethod =
  | 'ED25519SignatureVerification'
  | 'Ed25519VerificationKey2018'
  | 'Ed25519VerificationKey2020'
  | 'JsonWebKey2020'
  | 'Multikey'

function verify(data: string, signature: string, authenticators: VerificationMethod[]): VerificationMethod {
  const clear = stringToBytes(data)
  const signatureBytes = base64ToBytes(signature)
  const signer = authenticators.find((a: VerificationMethod) => {
    const { keyBytes, keyType } = extractPublicKeyBytes(a)
    if (keyType === 'Ed25519') {
      return ed25519.verify(signatureBytes, clear, keyBytes)
    } else {
      return false
    }
  })
  if (!signer) throw new Error('invalid_signature: Signature invalid for JWT')
  return signer
}

const supportedVerificationMethods: Array<SupportedVerificationMethod> = [
  'ED25519SignatureVerification',
  'Ed25519VerificationKey2018',
  'Ed25519VerificationKey2020',
  'JsonWebKey2020',
  'Multikey',
]

const verifier: Verifier<SupportedAlgs, SupportedVerificationMethod> = {
  Ed25519: { verify, supportedVerificationMethods },
  EdDSA: { verify, supportedVerificationMethods },
}

export default verifier
