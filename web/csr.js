import * as asn1js from "asn1js";
import {
  getCrypto,
  getAlgorithmParameters,
  CertificationRequest,
  AttributeTypeAndValue,
} from "pkijs";
import { v5 as uuidv5 } from "uuid";
import { arrayBufferToString, toBase64 } from "pvutils";

const hashAlg = "SHA-256";
const signAlg = "ECDSA";

/**
 * @returns {Promise<{ keyPair: CryptoKeyPair, keyPem: string }>}
 * @example
 * const { keyPair, keyPem } = await generateKey()
 *
 */
export async function generateKey() {
  const crypto = getWebCrypto();
  const algorithm = getAlgorithm(signAlg, hashAlg);
  let keyPair = await crypto.generateKey(
    algorithm.algorithm,
    true,
    algorithm.usages,
  );

  return {
    keyPair: keyPair,
    keyPem: `-----BEGIN PRIVATE KEY-----\n${formatPEM(
      toBase64(
        arrayBufferToString(
          await crypto.exportKey("pkcs8", keyPair.privateKey),
        ),
      ),
    )}\n-----END PRIVATE KEY-----`,
  };
}

/**
 * @param {string} ns
 * @param {CryptoKeyPair} keyPair
 * @returns {Promise<{ id: string, csrPem: string }>}
 * @example
 * const { id, csr } = await createCsr('ba64ca66-4f02-431d-8f31-e8ea8d0e8011', keyPair)
 *
 */
export async function createCsr(ns, keyPem) {
  const crypto = getWebCrypto();

  const pubKey = await crypto.exportKey("raw", keyPair.publicKey);
  const id = bifrostId(pubKey, ns);

  const pkcs10 = new CertificationRequest();
  pkcs10.version = 0;
  pkcs10.subject.typesAndValues.push(
    new AttributeTypeAndValue({
      type: "2.5.4.3", // commonName
      value: new asn1js.Utf8String({ value: id }),
    }),
  );
  pkcs10.subject.typesAndValues.push(
    new AttributeTypeAndValue({
      type: "2.5.4.10", // organizationName
      value: new asn1js.Utf8String({ value: ns }),
    }),
  );

  pkcs10.attributes = [];

  await pkcs10.subjectPublicKeyInfo.importKey(keyPair.publicKey);

  // Signing final PKCS#10 request
  await pkcs10.sign(keyPair.privateKey, hashAlg);

  const csr = pkcs10.toSchema().toBER(false);

  return {
    id: id,
    csrPem: `-----BEGIN CERTIFICATE REQUEST-----\n${formatPEM(
      toBase64(arrayBufferToString(csr)),
    )}\n-----END CERTIFICATE REQUEST-----`,
  };
}

/**
 * @param {ArrayBuffer} pubKey
 * @param {string} ns
 * @returns {string}
 * @example
 * const pubkey = await crypto.exportKey('raw', keyPair.publicKey);
 * const id = bifrostId(pubKey, 'ba64ca66-4f02-431d-8f31-e8ea8d0e8011')
 */
function bifrostId(pubKey, ns) {
  const xyBytes = pubKey.slice(1, 65);
  return uuidv5(new Uint8Array(xyBytes), ns);
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
  return btoa(
    encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function (match, p1) {
      return String.fromCharCode("0x" + p1);
    }),
  );
}

// Add line break every 64th character
function formatPEM(pemString) {
  return pemString.replace(/(.{64})/g, "$1\n");
}

function getWebCrypto() {
  const crypto = getCrypto();
  if (typeof crypto === "undefined") throw "No WebCrypto extension found";
  return crypto;
}

function getAlgorithm(signAlg, hashAlg) {
  const algorithm = getAlgorithmParameters(signAlg, "generatekey");
  if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = hashAlg;
  return algorithm;
}
