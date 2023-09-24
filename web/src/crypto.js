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
    const keybuf = pemToArrayBuffer(req.key)
    keyPair = await crypto.importKey('pkcs8', keybuf,
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

// PEM to ArrayBuffer courtesy of https://stackoverflow.com/q/41529138/1656503
function pemToArrayBuffer(pem) {
  var lines = pem.split('\n');
  var encoded = '';
  for (var i = 0; i < lines.length; i++) {
    if (lines[i].trim().length > 0 &&
      lines[i].indexOf('-----BEGIN RSA PRIVATE KEY-----') < 0 &&
      lines[i].indexOf('-----BEGIN RSA PUBLIC KEY-----') < 0 &&
      lines[i].indexOf('-----BEGIN PUBLIC KEY-----') < 0 &&
      lines[i].indexOf('-----END PUBLIC KEY-----') < 0 &&
      lines[i].indexOf('-----BEGIN PRIVATE KEY-----') < 0 &&
      lines[i].indexOf('-----END PRIVATE KEY-----') < 0 &&
      lines[i].indexOf('-----END RSA PRIVATE KEY-----') < 0 &&
      lines[i].indexOf('-----END RSA PUBLIC KEY-----') < 0) {
      encoded += lines[i].trim();
    }
  }
  return base64StringToArrayBuffer(encoded);
}

function base64StringToArrayBuffer(b64str) {
  b64str = b64EncodeUnicode(b64str);
  var byteStr = atob(b64str);
  var bytes = new Uint8Array(byteStr.length);
  for (var i = 0; i < byteStr.length; i++) {
    bytes[i] = byteStr.charCodeAt(i);
  }
  return bytes.buffer;
}


function b64EncodeUnicode(str) {
  return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function (match, p1) {
    return String.fromCharCode('0x' + p1);
  }));
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
  const algorithm = getAlgorithmParameters(signAlg, 'generatekey')
  if ('hash' in algorithm.algorithm)
    algorithm.algorithm.hash.name = hashAlg
  return algorithm
}

function generateKeyPair(crypto, algorithm) {
  return crypto.generateKey(algorithm.algorithm, true, algorithm.usages)
}
