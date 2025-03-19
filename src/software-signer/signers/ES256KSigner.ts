import { leftpad, toJose } from '../../util.js'
import { Signer } from '../../JWT.js'
import { sha256 } from '../../Digest.js'
import { secp256k1 } from '@noble/curves/secp256k1'

/**
 * Creates a configured signer function for signing data using the ES256K (secp256k1 + sha256) algorithm.
 *
 * The signing function itself takes the data as a `Uint8Array` or `string` and returns a `base64Url`-encoded signature
 *
 * @param privateKey a private key as `Uint8Array`
 * @param recoverable an optional flag to add the recovery param to the generated signatures
 * @returns a configured signer function `(data: string | Uint8Array): Promise<string>`
 */
export function ES256KSigner(privateKey: Uint8Array, recoverable = false): Signer {
  const privateKeyBytes: Uint8Array = privateKey
  if (privateKeyBytes.length !== 32) {
    throw new Error(`bad_key: Invalid private key format. Expecting 32 bytes, but got ${privateKeyBytes.length}`)
  }

  return async (data: string | Uint8Array): Promise<string> => {
    const signature = secp256k1.sign(sha256(data), privateKeyBytes)
    if (recoverable && signature.recovery === undefined) {
      throw new Error(`not_supported: ES256K-R not supported when signer doesn't provide a recovery param`)
    }
    return toJose(
      {
        r: leftpad(signature.r.toString(16)),
        s: leftpad(signature.s.toString(16)),
        recoveryParam: signature.recovery,
      },
      recoverable
    )
  }
}
// export function ES256KSignerAlg(recoverable?: boolean): SignerAlgorithm {
//   return async function sign(payload: string, signer: Signer): Promise<string> {
//     const signature: EcdsaSignature | string = await signer(payload)
//     if (instanceOfEcdsaSignature(signature)) {
//       return toJose(signature, recoverable)
//     } else {
//       if (recoverable && typeof fromJose(signature).recoveryParam === 'undefined') {
//         throw new Error(`not_supported: ES256K-R not supported when signer doesn't provide a recovery param`)
//       }
//       return signature
//     }
//   }
// }
