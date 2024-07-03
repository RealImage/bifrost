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
 * @param {string} caUrl
 * @returns {Promise<string>}
 * @example
 * const namespace = await getNamespace()
 *
 */
export async function getNamespace(caUrl) {
  nsUrl = "/namespace";
  if (caUrl) nsUrl = caUrl + nsUrl;

  const response = await fetch(nsUrl);
  return await response.text();
}

/**
 * @returns {Promise<CryptoKeyPair>}
 * @example
 * const keyPair = await generateKey()
 *
 */
export async function generateKey() {
  const crypto = getWebCrypto();
  const algorithm = getAlgorithm(signAlg, hashAlg);

  return await crypto.generateKey(
    algorithm.algorithm,
    true,
    algorithm.usages,
  );
}

/**
 * @typedef {("pem"|"der")} OutputFormat
 */

/**
 * @param {CryptoKeyPair} keyPair
 * @param {OutputFormat} [format="pem"]
 * @returns {Promise<(string|ArrayBuffer)>}
 * @example
 * const keyPem = await generateKey(keyPair, 'pem')
 * const keyDer = await generateKey(keyPair, 'der')
 */
export async function exportKey(keyPair, format = "pem") {
  const crypto = getWebCrypto();
  const key = await crypto.exportKey("pkcs8", keyPair.privateKey);

  switch (format) {
    case "der":
      return key;
    case "pem":
      return formatPEM("PRIVATE KEY", key);
    default:
      throw new Error("invalid format");
  }
}

/**
 * @param {string} namespace
 * @param {CryptoKeyPair} keyPair
 * @param {OutputFormat} [format="pem"]
 * @returns {Promise<(string|ArrayBuffer)>}
 * @example
 * const csrPem = await createCsr('ba64ca66-4f02-431d-8f31-e8ea8d0e8011', keyPair)
 * const csrDer = await createCsr('ba64ca66-4f02-431d-8f31-e8ea8d0e8011', keyPair, 'der')
 */
export async function createCsr(namespace, keyPair, format = "pem") {
  const id = await bifrostId(namespace, keyPair.publicKey);

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
      value: new asn1js.Utf8String({ value: namespace }),
    }),
  );

  pkcs10.attributes = [];

  await pkcs10.subjectPublicKeyInfo.importKey(keyPair.publicKey);

  // Signing final PKCS#10 request
  await pkcs10.sign(keyPair.privateKey, hashAlg);

  const csr = pkcs10.toSchema(true).toBER();


  switch (format) {
    case "der":
      return csr;
    case "pem":
      return formatPEM("CERTIFICATE REQUEST", csr);
    default:
      throw new Error("invalid format");
  }
}

/**
 * @param {string} namespace
 * @param {CryptoKey} pubKey
 * @returns {Promise<string>}
 * @example
 * const id = await bifrostId(keyPair.publicKey)
 */
export async function bifrostId(namespace, pubKey) {
  const crypto = getWebCrypto();
  const rawKey = await crypto.exportKey("raw", pubKey);
  const xyBytes = rawKey.slice(1, 65);
  return uuidv5(new Uint8Array(xyBytes), namespace);
}

/**
 * @param {string} type
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
function formatPEM(type, buffer) {
  return `-----BEGIN ${type}-----\n${toBase64(
    arrayBufferToString(buffer)).replace(/(.{64})/g, "$1\n")}\n-----END ${type}-----`;
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
