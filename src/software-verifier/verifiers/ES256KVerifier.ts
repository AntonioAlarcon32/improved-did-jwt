import { VerificationMethod } from 'did-resolver'
import { sha256, toEthereumAddress } from '../../Digest'
import { base64ToBytes, bytesToHex, ECDSASignature, extractPublicKeyBytes } from '../../util'
import { secp256k1 } from '@noble/curves/secp256k1'
import { toSignatureObject2 } from '../../util'
import { verifyBlockchainAccountId } from '../../blockchains'
import { Verifier } from './types'

type SupportedAlgs = 'ES256K' | 'ES256K-R'
type Es256kVerificationMethod =
  | 'EcdsaSecp256k1VerificationKey2019'
  | 'EcdsaSecp256k1RecoveryMethod2020'
  | 'Secp256k1VerificationKey2018'
  | 'Secp256k1SignatureVerificationKey2018'
  | 'EcdsaPublicKeySecp256k1'
  | 'JsonWebKey2020'
  | 'Multikey'
type Es256krVerificationMethod = Es256kVerificationMethod | 'ConditionalProof2022'

export function verifyES256K(
  data: string,
  signature: string,
  authenticators: VerificationMethod[]
): VerificationMethod {
  const hash = sha256(data)
  const signatureNormalized = secp256k1.Signature.fromCompact(base64ToBytes(signature)).normalizeS()
  const fullPublicKeys = authenticators.filter((a: VerificationMethod) => {
    return !a.ethereumAddress && !a.blockchainAccountId
  })
  const blockchainAddressKeys = authenticators.filter((a: VerificationMethod) => {
    return a.ethereumAddress || a.blockchainAccountId
  })

  let signer: VerificationMethod | undefined = fullPublicKeys.find((pk: VerificationMethod) => {
    try {
      const { keyBytes } = extractPublicKeyBytes(pk)
      return secp256k1.verify(signatureNormalized, hash, keyBytes)
    } catch (err) {
      return false
    }
  })

  if (!signer && blockchainAddressKeys.length > 0) {
    signer = verifyRecoverableES256K(data, signature, blockchainAddressKeys)
  }

  if (!signer) throw new Error('invalid_signature: Signature invalid for JWT')
  return signer
}

export function verifyRecoverableES256K(
  data: string,
  signature: string,
  authenticators: VerificationMethod[]
): VerificationMethod {
  const signatures: ECDSASignature[] = []
  if (signature.length > 86) {
    signatures.push(toSignatureObject2(signature, true))
  } else {
    const so = toSignatureObject2(signature, false)
    signatures.push({ ...so, recovery: 0 })
    signatures.push({ ...so, recovery: 1 })
  }
  const hash = sha256(data)

  const checkSignatureAgainstSigner = (sigObj: ECDSASignature): VerificationMethod | undefined => {
    const signature = secp256k1.Signature.fromCompact(sigObj.compact).addRecoveryBit(sigObj.recovery || 0)
    const recoveredPublicKey = signature.recoverPublicKey(hash)
    const recoveredAddress = toEthereumAddress(recoveredPublicKey.toHex(false)).toLowerCase()
    const recoveredPublicKeyHex = recoveredPublicKey.toHex(false)
    const recoveredCompressedPublicKeyHex = recoveredPublicKey.toHex(true)

    return authenticators.find((a: VerificationMethod) => {
      const { keyBytes } = extractPublicKeyBytes(a)
      const keyHex = bytesToHex(keyBytes)
      return (
        keyHex === recoveredPublicKeyHex ||
        keyHex === recoveredCompressedPublicKeyHex ||
        a.ethereumAddress?.toLowerCase() === recoveredAddress ||
        a.blockchainAccountId?.split('@eip155')?.[0].toLowerCase() === recoveredAddress || // CAIP-2
        verifyBlockchainAccountId(recoveredPublicKeyHex, a.blockchainAccountId) // CAIP-10
      )
    })
  }

  // Find first verification method
  for (const signature of signatures) {
    const verificationMethod = checkSignatureAgainstSigner(signature)
    if (verificationMethod) return verificationMethod
  }
  // If no one found matching
  throw new Error('invalid_signature: Signature invalid for JWT')
}

const supportedVerificationMethodsES256K: Array<Es256kVerificationMethod> = [
  'EcdsaSecp256k1VerificationKey2019',
  /**
   * Equivalent to EcdsaSecp256k1VerificationKey2019 when key is an ethereumAddress
   */
  'EcdsaSecp256k1RecoveryMethod2020',
  /**
   * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is
   *   not an ethereumAddress
   */
  'Secp256k1VerificationKey2018',
  /**
   * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is
   *   not an ethereumAddress
   */
  'Secp256k1SignatureVerificationKey2018',
  /**
   * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is
   *   not an ethereumAddress
   */
  'EcdsaPublicKeySecp256k1',
  /**
   *  TODO - support R1 key as well
   *   'ConditionalProof2022',
   */
  'JsonWebKey2020',
  'Multikey',
]

const supportedVerificationMethodsES256KR: Array<Es256krVerificationMethod> = [
  'EcdsaSecp256k1VerificationKey2019',
  /**
   * Equivalent to EcdsaSecp256k1VerificationKey2019 when key is an ethereumAddress
   */
  'EcdsaSecp256k1RecoveryMethod2020',
  /**
   * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is
   *   not an ethereumAddress
   */
  'Secp256k1VerificationKey2018',
  /**
   * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is
   *   not an ethereumAddress
   */
  'Secp256k1SignatureVerificationKey2018',
  /**
   * @deprecated, supported for backward compatibility. Equivalent to EcdsaSecp256k1VerificationKey2019 when key is
   *   not an ethereumAddress
   */
  'EcdsaPublicKeySecp256k1',
  'ConditionalProof2022',
  'JsonWebKey2020',
  'Multikey',
]

const verifier: Verifier<SupportedAlgs, Es256kVerificationMethod | Es256krVerificationMethod> = {
  ES256K: { verify: verifyES256K, supportedVerificationMethods: supportedVerificationMethodsES256K },
  'ES256K-R': { verify: verifyRecoverableES256K, supportedVerificationMethods: supportedVerificationMethodsES256KR },
}

export default verifier
