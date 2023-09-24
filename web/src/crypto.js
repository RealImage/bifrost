import * as asn1js from 'asn1js';
import { getCrypto, getAlgorithmParameters, CertificationRequest, AttributeTypeAndValue } from 'pkijs'
import { arrayBufferToString, toBase64 } from 'pvutils';

const hashAlg = 'SHA-256'
const signAlg = 'ECDSA'

/**
 * @param {{ namespace : string, key? : string }} req
 * @returns {Promise<{uuid: string, key: string, csr: string}>}
 *
 * @example
 * const { uuid, key, csr } = createKeyAndCSR({
 *   namespace: 'ba64ca66-4f02-431d-8f31-e8ea8d0e8011',
 *   key: '-----BEGIN EC PRIVATE KEY-----\n...\n-----END EC PRIVATE KEY-----'
 * })
 */
export async function createKeyAndCSR(req) {
  const crypto = getWebCrypto()

  let keyPair
  if (req.key == null) {
    keyPair = await generateKeyPair(crypto, getAlgorithm(signAlg, hashAlg))
  } else {
    keyPair = await crypto.importKey('pkcs8', req.key,
      getAlgorithm(signAlg, hashAlg), true, ['encrypt', 'sign', 'verify'])
  }

  const uuid = "" // TODO: calculate uuid

  return {
    uuid: uuid,
    key: `-----BEGIN PRIVATE KEY-----\n${toBase64(
      arrayBufferToString(
        await crypto.exportKey('pkcs8', keyPair.privateKey)))
      }\n-----END PRIVATE KEY-----`,
    csr: `-----BEGIN CERTIFICATE REQUEST-----\n${formatPEM(
      toBase64(
        arrayBufferToString(
          await createCSR(keyPair, hashAlg, uuid, req.namespace)
        )
      )
    )}\n-----END CERTIFICATE REQUEST-----`
  }
}

async function createCSR(keyPair, hashAlg, uuid, namespace) {
  const pkcs10 = new CertificationRequest()
  pkcs10.version = 0
  pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
    type: '2.5.4.10', // organizationName
    value: new asn1js.Utf8String({ value: namespace })
  }))
  pkcs10.subject.typesAndValues.push(new AttributeTypeAndValue({
    type: '2.5.4.3', // commonName
    value: new asn1js.Utf8String({ value: uuid })
  }))

  // Add attributes to make CSR valid
  // Attributes must be "a0:00" if empty
  pkcs10.attributes = []

  await pkcs10.subjectPublicKeyInfo.importKey(keyPair.publicKey)
  // Signing final PKCS#10 request
  await pkcs10.sign(keyPair.privateKey, hashAlg)

  return pkcs10.toSchema().toBER(false)
}

// Add line break every 64th character
function formatPEM(pemString) {
  return pemString.replace(/(.{64})/g, '$1\n')
}

function getWebCrypto() {
  const crypto = getCrypto()
  if (typeof crypto === 'undefined')
    throw 'No WebCrypto extension found'
  return crypto
}

function getAlgorithm(signAlg, hashAlg) {
  crypto.subtle.generateKey
  const algorithm = getAlgorithmParameters(signAlg, 'generatekey')
  if ('hash' in algorithm.algorithm)
    algorithm.algorithm.hash.name = hashAlg
  return algorithm
}

function generateKeyPair(crypto, algorithm) {
  return crypto.generateKey(algorithm.algorithm, true, algorithm.usages)
}
