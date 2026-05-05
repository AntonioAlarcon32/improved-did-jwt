import { createJWT, hexToBytes, decodeJWT, verifyJWT, ES256KSigner } from './src/index'
import { Resolver } from 'did-resolver'
import { getResolver } from 'ethr-did-resolver'

const signer = ES256KSigner(hexToBytes('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'))

const jwt = await createJWT(
  { aud: 'did:ethr:sepolia:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', iat: undefined, name: 'uPort Developer' },
  { issuer: 'did:ethr:sepolia:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', signer },
  { alg: 'ES256K' }
)

//pass the jwt from step 1
const decoded = decodeJWT(jwt)

const providerConfig = {
  rpcUrl: 'https://ethereum-sepolia.rpc.subquery.network/public',
  chainId: 11155111,
  registry: '0x03d5003bf0e79C5F5223588F347ebA39AfbC3818',
  name: 'sepolia',
}

const ethrDidResolver = getResolver(providerConfig)
const didResolver = new Resolver(ethrDidResolver)

// use the JWT from step 1
const verificationResponse = await verifyJWT(jwt, {
  resolver: didResolver,
  audience: 'did:ethr:sepolia:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74',
})

didResolver.resolve('did:ethr:sepolia:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74').then((res) => console.log(JSON.stringify(res, null, 2)))
