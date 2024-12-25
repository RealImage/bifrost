import * as asn1js from "asn1js";
import {
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
  let nsUrl = "/namespace";
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
  const algorithm = getAlgorithm(signAlg, hashAlg);

  return await crypto.subtle.generateKey(
    algorithm.algorithm,
    true,
    algorithm.usages,
  );
}

/**
 * Export the private key in PEM or DER format.
 *
 * @param {CryptoKey} privateKey
 * @param {("pem"|"der")} [format="pem"]
 * @returns {Promise<(string|ArrayBuffer)>}
 * @example
 * const keyPem = await generateKey(keyPair, 'pem')
 * const keyDer = await generateKey(keyPair, 'der')
 */
export async function exportPrivateKey(privateKey, format = "pem") {
  const key = await crypto.subtle.exportKey("pkcs8", privateKey);

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
 * Returns the sha256 fingerprint of the public key as a hex string.
 *
 * @param {CryptoKey} publicKey
 * @returns {Promise<string>}
 */
export async function publicKeyFingerprint(publicKey) {
  const key = await crypto.subtle.exportKey("raw", publicKey);
  const msgBuffer = new TextEncoder().encode(key);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return hashHex;
}

/**
 * @param {string} namespace
 * @param {CryptoKeyPair} keyPair
 * @param {("pem"|"der")} [format="pem"]
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
  const rawKey = await crypto.subtle.exportKey("raw", pubKey);
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
    arrayBufferToString(buffer),
  ).replace(/(.{64})/g, "$1\n")}\n-----END ${type}-----`;
}

/**
 *
 * @param {string} signAlg
 * @param {string} hashAlg
 * @returns {pkijs.CryptoEngineAlgorithmParams}
 */
function getAlgorithm(signAlg, hashAlg) {
  const algorithm = getAlgorithmParameters(signAlg, "generatekey");
  if ("hash" in algorithm.algorithm) algorithm.algorithm.hash.name = hashAlg;
  return algorithm;
}
