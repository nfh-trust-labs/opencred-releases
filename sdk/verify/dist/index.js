import { promises } from 'dns';
import { isIP } from 'net';
import { X509Certificate, createPublicKey, verify, createVerify, createHash } from 'crypto';
import * as _jsonldNs from 'jsonld';
import * as jose2 from 'jose';
import { importJWK, compactVerify } from 'jose';
import { canonicalize as canonicalize$1 } from 'json-canonicalize';
import 'fs';
import { resolve4, resolve6 } from 'dns/promises';
import { promisify } from 'util';
import { gunzip as gunzip$1 } from 'zlib';
import 'fs/promises';
import 'path';
import { PDFDocument, PDFDict, PDFName, PDFString, PDFHexString } from 'pdf-lib';
import { createRequire } from 'module';

var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};

// ../shared/dist/errors.js
function posixBasename(match) {
  const segments = match.split("/").filter(Boolean);
  const basename = segments[segments.length - 1] ?? "";
  return basename.length > 0 ? `[PATH]/${basename}` : "[PATH]";
}
function windowsBasename(match) {
  const segments = match.split("\\").filter(Boolean);
  const basename = segments[segments.length - 1] ?? "";
  return basename.length > 0 ? `[PATH]\\${basename}` : "[PATH]";
}
function sanitizeErrorMessage(raw) {
  if (typeof raw !== "string") {
    return "An error occurred";
  }
  let out = raw;
  for (const [pattern, replacement] of SANITIZE_PATTERNS) {
    if (typeof replacement === "string") {
      out = out.replace(pattern, replacement);
    } else {
      out = out.replace(pattern, replacement);
    }
  }
  out = out.replace(/\s+/g, " ").trim();
  if (out.length > MAX_HTTP_MESSAGE_LENGTH) {
    out = `${out.slice(0, MAX_HTTP_MESSAGE_LENGTH - 3)}...`;
  }
  if (out.length === 0) {
    return "An error occurred";
  }
  return out;
}
var SANITIZE_PATTERNS, MAX_HTTP_MESSAGE_LENGTH, OpenCredError, PayloadTooLargeError, CryptoError, DIDResolutionError, DeDiClientError, VerificationError;
var init_errors = __esm({
  "../shared/dist/errors.js"() {
    SANITIZE_PATTERNS = [
      // PEM blocks (private keys, encrypted keys, certificates). Match
      // greedily across newlines so the entire block is redacted.
      [/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, "[REDACTED_PEM]"],
      // Stack-trace lines (Node V8 format): "    at functionName (file:line:col)"
      // Strip the whole "at ..." frame; it contains both the file path and
      // internal symbol names. Do this BEFORE path stripping so the frame
      // collapses cleanly.
      [/\s*at\s+[^\n]+\([^)]*\)/g, ""],
      [/\s*at\s+[^\n]+:\d+:\d+/g, ""],
      // POSIX absolute paths — /home/..., /Users/..., /tmp/..., /var/...,
      // /private/..., /opt/..., /srv/..., /root/..., /etc/... — keep only
      // the final basename. A function replacement is used so "a/b/c/f.bin"
      // collapses to "[PATH]/f.bin" without having to spell out a multi-
      // segment capture group.
      [/\/(?:home|Users|tmp|var|private|opt|srv|root|etc|usr|mnt)\/[^\s:"'<>()]+/g, posixBasename],
      // Windows absolute paths: C:\Users\..., D:\Windows\..., etc.
      [
        /[A-Za-z]:\\(?:Users|Windows|Program Files|Program Files \(x86\)|ProgramData|Temp)\\[^\s:"'<>()]+/g,
        windowsBasename
      ],
      // UNC paths (\\server\share\...)
      [/\\\\[^\s\\"'<>()]+\\[^\s"'<>()]+/g, "[PATH]"],
      // file:// URLs — these embed absolute paths.
      [/file:\/\/[^\s"'<>()]+/g, "[FILE_URL]"],
      // Hex blobs of 40+ chars — likely fingerprints, signatures, keys.
      // 40 chars is the length of a SHA-1 digest. Must run BEFORE the
      // base64 pattern because hex is a subset of base64.
      [/\b[0-9a-fA-F]{40,}\b/g, "[REDACTED_HEX]"],
      // Long base64 blobs (40+ chars) — almost always key material,
      // signatures, or ciphertext. Short base64 (e.g. short IDs under
      // 40 chars) is left alone so legitimate identifiers still surface.
      [/[A-Za-z0-9+/]{40,}={0,2}/g, "[REDACTED_B64]"]
    ];
    MAX_HTTP_MESSAGE_LENGTH = 512;
    OpenCredError = class extends Error {
      code;
      statusCode;
      kind;
      constructor(message, code, statusCode = 500, options) {
        super(message, options);
        this.name = "OpenCredError";
        this.code = code;
        this.statusCode = statusCode;
        this.kind = options?.kind ?? "OpenCredError";
        Object.setPrototypeOf(this, new.target.prototype);
      }
      /**
       * Return the sanitized HTTP-visible body for this error.
       *
       * The body contains only `code` and a sanitized `message`. It never
       * contains stack traces, filesystem paths, PEM blocks, or raw key
       * material, even if the underlying `.message` did.
       *
       * Subclasses that want to expose additional safe fields should
       * override this method and call `super.toJSON()` to obtain the
       * sanitized base body first.
       */
      toJSON() {
        return {
          error: {
            code: this.code,
            message: sanitizeErrorMessage(this.message)
          }
        };
      }
      /**
       * Explicit alias for `toJSON()` — returns the sanitized HTTP body.
       *
       * Preferred in HTTP middleware because the intent ("this is the body
       * I'm about to send over the wire") is clearer at the call site.
       */
      toHttpBody() {
        return this.toJSON();
      }
    };
    PayloadTooLargeError = class extends OpenCredError {
      constructor(message = "Payload too large") {
        super(message, "PAYLOAD_TOO_LARGE", 413, { kind: "PayloadTooLargeError" });
        this.name = "PayloadTooLargeError";
      }
    };
    CryptoError = class extends OpenCredError {
      constructor(message, options) {
        super(message, "CRYPTO_ERROR", 500, { ...options ?? {}, kind: "CryptoError" });
        this.name = "CryptoError";
      }
    };
    DIDResolutionError = class extends OpenCredError {
      constructor(message) {
        super(message, "DID_RESOLUTION_ERROR", 500, { kind: "DIDResolutionError" });
        this.name = "DIDResolutionError";
      }
    };
    DeDiClientError = class extends OpenCredError {
      constructor(message, statusCode = 502) {
        super(message, "DEDI_CLIENT_ERROR", statusCode, { kind: "DeDiClientError" });
        this.name = "DeDiClientError";
      }
    };
    VerificationError = class extends OpenCredError {
      constructor(message) {
        super(message, "VERIFICATION_ERROR", 400, { kind: "VerificationError" });
        this.name = "VerificationError";
      }
    };
  }
});
function isPrivateIPv4(ip) {
  for (const prefix of PRIVATE_IPV4_PREFIXES) {
    if (ip.startsWith(prefix))
      return true;
  }
  if (ip.startsWith("172.")) {
    const secondOctet = parseInt(ip.split(".")[1], 10);
    if (secondOctet >= 16 && secondOctet <= 31)
      return true;
  }
  if (ip.startsWith("192.168."))
    return true;
  if (ip.startsWith("100.")) {
    const secondOctet = parseInt(ip.split(".")[1], 10);
    if (secondOctet >= 64 && secondOctet <= 127)
      return true;
  }
  if (ip.startsWith("198.18.") || ip.startsWith("198.19."))
    return true;
  const firstOctet = parseInt(ip.split(".")[0], 10);
  if (firstOctet >= 224)
    return true;
  return false;
}
function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase();
  if (normalized === "::1")
    return true;
  if (normalized === "::")
    return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd"))
    return true;
  if (/^fe[89ab][0-9a-f]:/.test(normalized))
    return true;
  if (normalized.startsWith("ff"))
    return true;
  if (normalized.startsWith("0100:"))
    return true;
  if (/^100:(?::|0:)/.test(normalized))
    return true;
  const dottedMatch = normalized.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dottedMatch)
    return isPrivateIPv4(dottedMatch[1]);
  const hexMatch = normalized.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (hexMatch) {
    const hi = parseInt(hexMatch[1], 16);
    const lo = parseInt(hexMatch[2], 16);
    const a = hi >> 8 & 255;
    const b = hi & 255;
    const c = lo >> 8 & 255;
    const d = lo & 255;
    return isPrivateIPv4(`${a}.${b}.${c}.${d}`);
  }
  return false;
}
function isPrivateIP(ip) {
  if (isIP(ip) === 4)
    return isPrivateIPv4(ip);
  if (isIP(ip) === 6)
    return isPrivateIPv6(ip);
  return false;
}
var PRIVATE_IPV4_PREFIXES;
var init_ssrf = __esm({
  "../shared/dist/ssrf.js"() {
    PRIVATE_IPV4_PREFIXES = ["10.", "127.", "0.", "169.254."];
  }
});

// ../shared/dist/credential-format.js
function detectCredentialInputFormat(input) {
  if (input.startsWith("OPENCRED1:")) {
    return "pixelpass";
  }
  const trimmed = input.trimStart();
  if (trimmed.startsWith("{")) {
    return "json";
  }
  if (input.includes("~")) {
    return "jwt-compact";
  }
  const parts = input.split(".");
  if (parts.length === 3 && parts[0].length > 0 && parts[1].length > 0 && parts[2].length > 0 && BASE64URL_RE.test(parts[0]) && BASE64URL_RE.test(parts[1]) && BASE64URL_RE.test(parts[2])) {
    return "jwt-compact";
  }
  return "unknown";
}
var BASE64URL_RE;
var init_credential_format = __esm({
  "../shared/dist/credential-format.js"() {
    BASE64URL_RE = /^[A-Za-z0-9_-]+$/;
  }
});

// ../shared/dist/jwt-size.js
function assertJwtSize(token) {
  if (Buffer.byteLength(token, "utf8") > MAX_JWT_BYTES) {
    throw new PayloadTooLargeError(`JWT exceeds maximum allowed size of ${MAX_JWT_BYTES} bytes`);
  }
}
var MAX_JWT_BYTES;
var init_jwt_size = __esm({
  "../shared/dist/jwt-size.js"() {
    init_errors();
    MAX_JWT_BYTES = 1048576;
  }
});

// ../shared/dist/index.js
var init_dist = __esm({
  "../shared/dist/index.js"() {
    init_errors();
    init_ssrf();
    init_credential_format();
    init_jwt_size();
  }
});

// ../vc-core/dist/types.js
var W3C_CREDENTIALS_V2_CONTEXT, DATA_INTEGRITY_V1_CONTEXT, TRACEABILITY_V1_CONTEXT, OPEN_BADGES_V3_CONTEXT, OPENCRED_SCHEMAS_SHA, OPENCRED_SCHEMAS_BASE, OPENCRED_ELECTRICITY_V1_CONTEXT, OPENCRED_IMMUNIZATION_V1_CONTEXT, OPENCRED_PRESCRIPTION_V1_CONTEXT, OPENCRED_TEST_RESULT_V1_CONTEXT, OPENCRED_INSURANCE_POLICY_V1_CONTEXT, OPENCRED_FUNCTIONAL_IDENTITY_V1_CONTEXT, OPENCRED_EMPLOYMENT_OFFER_LETTER_V1_CONTEXT, OPENCRED_BUSINESS_ENTITY_V1_CONTEXT;
var init_types = __esm({
  "../vc-core/dist/types.js"() {
    W3C_CREDENTIALS_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";
    DATA_INTEGRITY_V1_CONTEXT = "https://w3id.org/security/data-integrity/v1";
    TRACEABILITY_V1_CONTEXT = "https://w3id.org/traceability/v1";
    OPEN_BADGES_V3_CONTEXT = "https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json";
    OPENCRED_SCHEMAS_SHA = "ed460795866ce51aebf92e9fccc5f30ff0482dcb";
    OPENCRED_SCHEMAS_BASE = `https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/${OPENCRED_SCHEMAS_SHA}/schemas`;
    OPENCRED_ELECTRICITY_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/electricity/v1/context.jsonld`;
    OPENCRED_IMMUNIZATION_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/immunization/v1/context.jsonld`;
    OPENCRED_PRESCRIPTION_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/prescription/v1/context.jsonld`;
    OPENCRED_TEST_RESULT_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/test-result/v1/context.jsonld`;
    OPENCRED_INSURANCE_POLICY_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/insurance-policy/v1/context.jsonld`;
    OPENCRED_FUNCTIONAL_IDENTITY_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/functional-identity/v1/context.jsonld`;
    OPENCRED_EMPLOYMENT_OFFER_LETTER_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/employment-offer-letter/v1/context.jsonld`;
    OPENCRED_BUSINESS_ENTITY_V1_CONTEXT = `${OPENCRED_SCHEMAS_BASE}/business-entity/v1/context.jsonld`;
  }
});

// ../vc-core/dist/context-generator.js
var init_context_generator = __esm({
  "../vc-core/dist/context-generator.js"() {
  }
});
var init_credential_builder = __esm({
  "../vc-core/dist/credential-builder.js"() {
    init_types();
  }
});

// ../vc-core/dist/context-errors.js
var ContextNotFoundError;
var init_context_errors = __esm({
  "../vc-core/dist/context-errors.js"() {
    init_dist();
    ContextNotFoundError = class extends OpenCredError {
      contextUrl;
      constructor(url) {
        super(`JSON-LD context not found: ${url}. The context is not bundled and not in the local context store. Import the context or use VC-JWT proof format.`, "CONTEXT_NOT_FOUND", 422);
        this.contextUrl = url;
        this.name = "ContextNotFoundError";
      }
    };
  }
});

// ../vc-core/dist/context-data.js
var credentialsV2, dataIntegrityV1, traceabilityV1, businessEntityV1, electricityV1, employmentOfferLetterV1, functionalIdentityV1, immunizationV1, insurancePolicyV1, openBadgesV3, prescriptionV1, testResultV1;
var init_context_data = __esm({
  "../vc-core/dist/context-data.js"() {
    credentialsV2 = {
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "description": "https://schema.org/description",
        "digestMultibase": {
          "@id": "https://w3id.org/security#digestMultibase",
          "@type": "https://w3id.org/security#multibase"
        },
        "digestSRI": {
          "@id": "https://www.w3.org/2018/credentials#digestSRI",
          "@type": "https://www.w3.org/2018/credentials#sriString"
        },
        "mediaType": {
          "@id": "https://schema.org/encodingFormat"
        },
        "name": "https://schema.org/name",
        "VerifiableCredential": {
          "@id": "https://www.w3.org/2018/credentials#VerifiableCredential",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "confidenceMethod": {
              "@id": "https://www.w3.org/2018/credentials#confidenceMethod",
              "@type": "@id"
            },
            "credentialSchema": {
              "@id": "https://www.w3.org/2018/credentials#credentialSchema",
              "@type": "@id"
            },
            "credentialStatus": {
              "@id": "https://www.w3.org/2018/credentials#credentialStatus",
              "@type": "@id"
            },
            "credentialSubject": {
              "@id": "https://www.w3.org/2018/credentials#credentialSubject",
              "@type": "@id"
            },
            "description": "https://schema.org/description",
            "evidence": {
              "@id": "https://www.w3.org/2018/credentials#evidence",
              "@type": "@id"
            },
            "issuer": {
              "@id": "https://www.w3.org/2018/credentials#issuer",
              "@type": "@id"
            },
            "name": "https://schema.org/name",
            "proof": {
              "@id": "https://w3id.org/security#proof",
              "@type": "@id",
              "@container": "@graph"
            },
            "refreshService": {
              "@id": "https://www.w3.org/2018/credentials#refreshService",
              "@type": "@id"
            },
            "relatedResource": {
              "@id": "https://www.w3.org/2018/credentials#relatedResource",
              "@type": "@id"
            },
            "renderMethod": {
              "@id": "https://www.w3.org/2018/credentials#renderMethod",
              "@type": "@id"
            },
            "termsOfUse": {
              "@id": "https://www.w3.org/2018/credentials#termsOfUse",
              "@type": "@id"
            },
            "validFrom": {
              "@id": "https://www.w3.org/2018/credentials#validFrom",
              "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
            },
            "validUntil": {
              "@id": "https://www.w3.org/2018/credentials#validUntil",
              "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
            }
          }
        },
        "EnvelopedVerifiableCredential": "https://www.w3.org/2018/credentials#EnvelopedVerifiableCredential",
        "VerifiablePresentation": {
          "@id": "https://www.w3.org/2018/credentials#VerifiablePresentation",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "holder": {
              "@id": "https://www.w3.org/2018/credentials#holder",
              "@type": "@id"
            },
            "proof": {
              "@id": "https://w3id.org/security#proof",
              "@type": "@id",
              "@container": "@graph"
            },
            "termsOfUse": {
              "@id": "https://www.w3.org/2018/credentials#termsOfUse",
              "@type": "@id"
            },
            "verifiableCredential": {
              "@id": "https://www.w3.org/2018/credentials#verifiableCredential",
              "@type": "@id",
              "@container": "@graph",
              "@context": null
            }
          }
        },
        "EnvelopedVerifiablePresentation": "https://www.w3.org/2018/credentials#EnvelopedVerifiablePresentation",
        "JsonSchemaCredential": "https://www.w3.org/2018/credentials#JsonSchemaCredential",
        "JsonSchema": {
          "@id": "https://www.w3.org/2018/credentials#JsonSchema",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "jsonSchema": {
              "@id": "https://www.w3.org/2018/credentials#jsonSchema",
              "@type": "@json"
            }
          }
        },
        "BitstringStatusListCredential": "https://www.w3.org/ns/credentials/status#BitstringStatusListCredential",
        "BitstringStatusList": {
          "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusList",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "encodedList": {
              "@id": "https://www.w3.org/ns/credentials/status#encodedList",
              "@type": "https://w3id.org/security#multibase"
            },
            "statusPurpose": "https://www.w3.org/ns/credentials/status#statusPurpose",
            "ttl": "https://www.w3.org/ns/credentials/status#ttl"
          }
        },
        "BitstringStatusListEntry": {
          "@id": "https://www.w3.org/ns/credentials/status#BitstringStatusListEntry",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "statusListCredential": {
              "@id": "https://www.w3.org/ns/credentials/status#statusListCredential",
              "@type": "@id"
            },
            "statusListIndex": "https://www.w3.org/ns/credentials/status#statusListIndex",
            "statusPurpose": "https://www.w3.org/ns/credentials/status#statusPurpose",
            "statusMessage": {
              "@id": "https://www.w3.org/ns/credentials/status#statusMessage",
              "@context": {
                "@protected": true,
                "id": "@id",
                "type": "@type",
                "message": "https://www.w3.org/ns/credentials/status#message",
                "status": "https://www.w3.org/ns/credentials/status#status"
              }
            },
            "statusReference": {
              "@id": "https://www.w3.org/ns/credentials/status#statusReference",
              "@type": "@id"
            },
            "statusSize": {
              "@id": "https://www.w3.org/ns/credentials/status#statusSize",
              "@type": "https://www.w3.org/2001/XMLSchema#integer"
            }
          }
        },
        "DataIntegrityProof": {
          "@id": "https://w3id.org/security#DataIntegrityProof",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "challenge": "https://w3id.org/security#challenge",
            "created": {
              "@id": "http://purl.org/dc/terms/created",
              "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
            },
            "cryptosuite": {
              "@id": "https://w3id.org/security#cryptosuite",
              "@type": "https://w3id.org/security#cryptosuiteString"
            },
            "domain": "https://w3id.org/security#domain",
            "expires": {
              "@id": "https://w3id.org/security#expiration",
              "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
            },
            "nonce": "https://w3id.org/security#nonce",
            "previousProof": {
              "@id": "https://w3id.org/security#previousProof",
              "@type": "@id"
            },
            "proofPurpose": {
              "@id": "https://w3id.org/security#proofPurpose",
              "@type": "@vocab",
              "@context": {
                "@protected": true,
                "id": "@id",
                "type": "@type",
                "assertionMethod": {
                  "@id": "https://w3id.org/security#assertionMethod",
                  "@type": "@id",
                  "@container": "@set"
                },
                "authentication": {
                  "@id": "https://w3id.org/security#authenticationMethod",
                  "@type": "@id",
                  "@container": "@set"
                },
                "capabilityDelegation": {
                  "@id": "https://w3id.org/security#capabilityDelegationMethod",
                  "@type": "@id",
                  "@container": "@set"
                },
                "capabilityInvocation": {
                  "@id": "https://w3id.org/security#capabilityInvocationMethod",
                  "@type": "@id",
                  "@container": "@set"
                },
                "keyAgreement": {
                  "@id": "https://w3id.org/security#keyAgreementMethod",
                  "@type": "@id",
                  "@container": "@set"
                }
              }
            },
            "proofValue": {
              "@id": "https://w3id.org/security#proofValue",
              "@type": "https://w3id.org/security#multibase"
            },
            "verificationMethod": {
              "@id": "https://w3id.org/security#verificationMethod",
              "@type": "@id"
            }
          }
        },
        "...": {
          "@id": "https://www.iana.org/assignments/jwt#..."
        },
        "_sd": {
          "@id": "https://www.iana.org/assignments/jwt#_sd",
          "@type": "@json"
        },
        "_sd_alg": {
          "@id": "https://www.iana.org/assignments/jwt#_sd_alg"
        },
        "aud": {
          "@id": "https://www.iana.org/assignments/jwt#aud",
          "@type": "@id"
        },
        "cnf": {
          "@id": "https://www.iana.org/assignments/jwt#cnf",
          "@context": {
            "@protected": true,
            "kid": {
              "@id": "https://www.iana.org/assignments/jwt#kid",
              "@type": "@id"
            },
            "jwk": {
              "@id": "https://www.iana.org/assignments/jwt#jwk",
              "@type": "@json"
            }
          }
        },
        "exp": {
          "@id": "https://www.iana.org/assignments/jwt#exp",
          "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
        },
        "iat": {
          "@id": "https://www.iana.org/assignments/jwt#iat",
          "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
        },
        "iss": {
          "@id": "https://www.iana.org/assignments/jose#iss",
          "@type": "@id"
        },
        "jku": {
          "@id": "https://www.iana.org/assignments/jose#jku",
          "@type": "@id"
        },
        "kid": {
          "@id": "https://www.iana.org/assignments/jose#kid",
          "@type": "@id"
        },
        "nbf": {
          "@id": "https://www.iana.org/assignments/jwt#nbf",
          "@type": "https://www.w3.org/2001/XMLSchema#nonNegativeInteger"
        },
        "sub": {
          "@id": "https://www.iana.org/assignments/jose#sub",
          "@type": "@id"
        },
        "x5u": {
          "@id": "https://www.iana.org/assignments/jose#x5u",
          "@type": "@id"
        }
      }
    };
    dataIntegrityV1 = {
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "DataIntegrityProof": {
          "@id": "https://w3id.org/security#DataIntegrityProof",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "challenge": "https://w3id.org/security#challenge",
            "created": {
              "@id": "http://purl.org/dc/terms/created",
              "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
            },
            "cryptosuite": {
              "@id": "https://w3id.org/security#cryptosuite",
              "@type": "https://w3id.org/security#cryptosuiteString"
            },
            "domain": "https://w3id.org/security#domain",
            "expires": {
              "@id": "https://w3id.org/security#expiration",
              "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
            },
            "nonce": "https://w3id.org/security#nonce",
            "proofPurpose": {
              "@id": "https://w3id.org/security#proofPurpose",
              "@type": "@vocab",
              "@context": {
                "@version": 1.1,
                "@protected": true,
                "id": "@id",
                "type": "@type",
                "assertionMethod": {
                  "@id": "https://w3id.org/security#assertionMethod",
                  "@type": "@id",
                  "@container": "@set"
                },
                "authentication": {
                  "@id": "https://w3id.org/security#authenticationMethod",
                  "@type": "@id",
                  "@container": "@set"
                },
                "capabilityDelegation": {
                  "@id": "https://w3id.org/security#capabilityDelegationMethod",
                  "@type": "@id",
                  "@container": "@set"
                },
                "capabilityInvocation": {
                  "@id": "https://w3id.org/security#capabilityInvocationMethod",
                  "@type": "@id",
                  "@container": "@set"
                },
                "keyAgreement": {
                  "@id": "https://w3id.org/security#keyAgreementMethod",
                  "@type": "@id",
                  "@container": "@set"
                }
              }
            },
            "proofValue": {
              "@id": "https://w3id.org/security#proofValue",
              "@type": "https://w3id.org/security#multibase"
            },
            "verificationMethod": {
              "@id": "https://w3id.org/security#verificationMethod",
              "@type": "@id"
            }
          }
        }
      }
    };
    traceabilityV1 = {
      "@context": {
        "@version": 1.1,
        "@vocab": "https://www.w3.org/ns/credentials/issuer-dependent#",
        "id": "@id",
        "type": "@type",
        "name": "https://schema.org/name",
        "description": "https://schema.org/description",
        "identifier": "https://schema.org/identifier",
        "image": { "@id": "https://schema.org/image", "@type": "@id" },
        "relatedLink": { "@id": "https://w3id.org/traceability#LinkRole" },
        "manufacturer": "https://vocabulary.uncefact.org/manufacturerParty",
        "manufacturingCountry": "https://vocabulary.uncefact.org/manufactureCountry",
        "product": "https://w3id.org/traceability#SteelProduct",
        "rawMaterial": "https://w3id.org/traceability#rawMaterial",
        "items": "https://schema.org/ItemList",
        "dateOfExport": {
          "@id": "https://vocabulary.uncefact.org/exportExitDateTime",
          "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
        },
        "TraceablePresentation": {
          "@id": "https://w3id.org/traceability#traceable-presentation",
          "@context": {
            "replace": { "@id": "https://w3id.org/traceability#workflow-replace", "@type": "@id" },
            "workflow": {
              "@id": "https://w3id.org/traceability#workflow",
              "@context": {
                "definition": {
                  "@id": "https://w3id.org/traceability#workflow-definition",
                  "@type": "@id"
                },
                "instance": { "@id": "https://w3id.org/traceability#workflow-instance", "@type": "@id" }
              }
            }
          }
        },
        "AgricultureActivity": {
          "@id": "https://w3id.org/traceability#AgricultureActivity",
          "@context": {
            "business": { "@id": "https://w3id.org/traceability#dfn-entities" },
            "actor": { "@id": "https://w3id.org/traceability#Person" },
            "location": { "@id": "https://www.gs1.org/voc/Place" },
            "activityDate": { "@id": "https://schema.org/endDate" },
            "activityType": { "@id": "https://schema.org/description" },
            "agricultureProduct": { "@id": "https://schema.org/ItemList" },
            "observation": { "@id": "https://w3id.org/traceability#observation" }
          }
        },
        "AgricultureInspectionCommonInfo": {
          "@id": "https://w3id.org/traceability#AgricultureInspectionCommonInfo",
          "@context": {
            "applicant": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "facility": { "@id": "https://www.gs1.org/voc/location" },
            "inspector": { "@id": "https://w3id.org/traceability#Inspector" },
            "delegateOf": { "@id": "https://vocabulary.uncefact.org/specifiedLegalOrganization" },
            "regulatoryAgency": { "@id": "https://vocabulary.uncefact.org/specifiedLegalOrganization" },
            "inspectionStarted": { "@id": "https://vocabulary.uncefact.org/startDateTime" },
            "inspectionEnded": { "@id": "https://vocabulary.uncefact.org/endDateTime" }
          }
        },
        "AgricultureInspectionGeneric": {
          "@id": "https://w3id.org/traceability#AgricultureInspectionGeneric",
          "@context": {
            "commonInfo": { "@id": "https://w3id.org/traceability#AgricultureInspectionCommonInfo" },
            "shipment": { "@id": "https://vocabulary.uncefact.org/transportPackage" },
            "inspectionType": { "@id": "https://www.gs1.org/voc/certificationType" },
            "observation": { "@id": "https://vocabulary.uncefact.org/relatedObservation" },
            "name": { "@id": "https://schema.org/name" },
            "status": { "@id": "https://vocabulary.uncefact.org/status" },
            "productQuantity": { "@id": "https://vocabulary.uncefact.org/Measurement" },
            "packageSize": { "@id": "https://vocabulary.uncefact.org/Measurement" },
            "inspectorCounted": { "@id": "https://vocabulary.uncefact.org/applicableSpecifiedAction" }
          }
        },
        "AgriculturePackage": {
          "@id": "https://w3id.org/traceability#AgriculturePackage",
          "@context": {
            "packageName": { "@id": "https://schema.org/name" },
            "grade": { "@id": "https://w3id.org/traceability#grade" },
            "responsibleParty": { "@id": "https://w3id.org/traceability#responsibleParty" },
            "voicePickCode": { "@id": "https://w3id.org/traceability#voicePickCode" },
            "packingDate": { "@id": "https://www.gs1.org/voc/packagingDate" },
            "harvestDate": { "@id": "https://vocabulary.uncefact.org/harvestDateTime" },
            "bestByDate": { "@id": "https://vocabulary.uncefact.org/bestBeforeDateTime" },
            "labelImageUrl": { "@id": "https://schema.org/url" },
            "labelImageHash": { "@id": "https://schema.org/sha256" },
            "agricultureProduct": { "@id": "https://schema.org/ItemList" },
            "harvest": { "@id": "https://w3id.org/traceability#AgricultureActivity" },
            "instrumentOfTrade": { "@id": "https://w3id.org/traceability#InstrumentOfTrade" }
          }
        },
        "AgricultureParcelDelivery": {
          "@id": "https://w3id.org/traceability#AgricultureParcelDelivery",
          "@context": {
            "deliveryAddress": { "@id": "https://schema.org/deliveryAddress" },
            "originAddress": { "@id": "https://schema.org/originAddress" },
            "foreignPortExport": { "@id": "https://schema.org/itinerary" },
            "portOfEntry": { "@id": "https://schema.org/itinerary" },
            "deliveryMethod": { "@id": "https://schema.org/hasDeliveryMethod" },
            "trackingNumber": { "@id": "https://schema.org/trackingNumber" },
            "expectedArrival": { "@id": "https://schema.org/expectedArrivalFrom" },
            "specialInstructions": { "@id": "https://schema.org/comment" },
            "consignee": { "@id": "https://schema.org/Organization" },
            "agriculturePackage": { "@id": "https://schema.org/itemShipped" },
            "movementPoints": { "@id": "https://schema.org/itinerary" },
            "plannedRoute": { "@id": "https://schema.org/itinerary" },
            "shipper": { "@id": "https://schema.org/seller" },
            "purchaser": { "@id": "https://schema.org/buyer" },
            "carrier": { "@id": "https://schema.org/carrier" },
            "broker": { "@id": "https://schema.org/broker" }
          }
        },
        "AgricultureProduct": {
          "@id": "https://w3id.org/traceability#AgricultureProduct",
          "@context": {
            "plu": { "@id": "https://schema.org/identifier" },
            "product": { "@id": "https://www.gs1.org/voc/Product" },
            "unitQuantity": { "@id": "https://vocabulary.uncefact.org/actualQuantity" },
            "scientificName": { "@id": "https://vocabulary.uncefact.org/scientificName" },
            "plantParts": {},
            "labelImageUrl": { "@id": "https://schema.org/url" },
            "labelImageHash": { "@id": "https://schema.org/sha256" },
            "name": { "@id": "https://schema.org/name" },
            "variety": { "@id": "https://www.gs1.org/voc/consumerProductVariant" },
            "commodityDesignation": { "@id": "https://www.gs1.org/voc/additionalProductDescription" },
            "packType": { "@id": "https://www.gs1.org/voc/packaging" }
          }
        },
        "BankAccount": {
          "@id": "https://w3id.org/traceability#BankAccount",
          "@context": {
            "accountId": { "@id": "https://w3id.org/traceability#accountId" },
            "BIC11": { "@id": "https://w3id.org/traceability#BIC11" },
            "iban": { "@id": "https://w3id.org/traceability#iban" },
            "routingInfo": { "@id": "https://w3id.org/traceability#routingInfo" },
            "familyName": { "@id": "http://schema.org/familyName" },
            "givenName": { "@id": "http://schema.org/givenName" },
            "address": { "@id": "https://schema.org/PostalAddress" }
          }
        },
        "BankAccountHolderAffirmation": {
          "@id": "https://w3id.org/traceability#BankAccountHolderAffirmation",
          "@context": {
            "affirmingParty": { "@id": "https://w3id.org/traceability#evidenceVerifier" },
            "bankAccountHolderAffirmationApproach": { "@id": "https://schema.org/name" },
            "bank": { "@id": "https://schema.org/Organization" }
          }
        },
        "BillOfLading": {
          "@id": "https://w3id.org/traceability#BillOfLading",
          "@context": {
            "billOfLadingNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BM" },
            "bookingNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BN" },
            "relatedDocuments": { "@id": "https://schema.org/Purchase" },
            "carrier": { "@id": "https://vocabulary.uncefact.org/carrierParty" },
            "consignor": { "@id": "https://vocabulary.uncefact.org/consignorParty" },
            "consignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "notify": { "@id": "https://vocabulary.uncefact.org/notifiedParty" },
            "freightForwarder": { "@id": "https://vocabulary.uncefact.org/freightForwarderParty" },
            "freight": { "@id": "https://schema.org/ParcelDelivery" },
            "nmfcFreightClass": { "@id": "https://w3id.org/traceability#nmfcFreightClass" },
            "hazardCode": { "@id": "https://w3id.org/traceability#hazardCode" },
            "portOfLoading": { "@id": "https://vocabulary.uncefact.org/LocationFunctionCodeList#9" },
            "portOfDischarge": { "@id": "https://vocabulary.uncefact.org/LocationFunctionCodeList#11" },
            "particulars": { "@id": "https://vocabulary.uncefact.org/includedConsignmentItem" }
          }
        },
        "BusinessRegistrationVerification": {
          "@id": "https://w3id.org/traceability#BusinessRegistrationVerification",
          "@context": {
            "affirmingParty": { "@id": "https://w3id.org/traceability#affirmingParty" },
            "registrationUrl": { "@id": "https://schema.org/url" },
            "taxIdentificationNumber": { "@id": "https://vocabulary.uncefact.org/uncl1153#AHP" },
            "countryOfRegistration": { "@id": "https://schema.org/country" }
          }
        },
        "CBPEntry": {
          "@id": "https://w3id.org/traceability#CBPEntry",
          "@context": {
            "portOfEntry": { "@id": "https://schema.org/Place" },
            "bondType": { "@id": "https://w3id.org/traceability#bondType" },
            "importer": { "@id": "https://vocabulary.uncefact.org/importerParty" },
            "importerOfRecord": { "@id": "https://w3id.org/traceability#importerOfRecord" },
            "entryNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#AQM" },
            "bondValue": { "@id": "https://schema.org/MonetaryAmount" },
            "entryValue": { "@id": "https://schema.org/MonetaryAmount" },
            "centralizedExaminationSite": {
              "@id": "https://w3id.org/traceability#centralizedExaminationSite"
            },
            "entryType": { "@id": "https://w3id.org/traceability#entryType" },
            "originatingWarehouseEntryNumber": {
              "@id": "https://w3id.org/traceability#originatingWarehouseEntryNumber"
            },
            "suretyCode": { "@id": "https://w3id.org/traceability#suretyCode" },
            "portOfUnlading": { "@id": "https://schema.org/Place" },
            "transportMode": { "@id": "https://w3id.org/traceability#transportMode" },
            "locationOfGoods": { "@id": "https://schema.org/Place" },
            "generalOrderNumber": { "@id": "https://w3id.org/traceability#generalOrderNumber" },
            "conveyanceNameOrFreeTradeZoneID": {
              "@id": "https://w3id.org/traceability#conveyanceNameOrFreeTradeZoneID"
            },
            "referenceIDCode": { "@id": "https://w3id.org/traceability#referenceIDCode" },
            "referenceIDNumber": { "@id": "https://w3id.org/traceability#referenceIDNumber" },
            "lineItems": { "@id": "https://w3id.org/traceability#lineItems" },
            "nonAMS": { "@id": "https://w3id.org/traceability#nonAMS" },
            "splitBill": { "@id": "https://w3id.org/traceability#splitBill" },
            "bolType": { "@id": "https://w3id.org/traceability#bolType" },
            "scac": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#AAZ" },
            "inBondNumber": { "@id": "https://w3id.org/traceability#inBondNumber" },
            "bolNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BM" },
            "quantity": { "@id": "https://w3id.org/traceability#quantity" },
            "voyageFlightTrip": { "@id": "https://w3id.org/traceability#voyageFlightTrip" },
            "conveyanceName": { "@id": "https://w3id.org/traceability#conveyanceName" },
            "arrivalDate": { "@id": "https://vocabulary.uncefact.org/actualArrivalRelatedDateTime" }
          }
        },
        "CBPEntryEntity": {
          "@id": "https://w3id.org/traceability#CBPEntryEntity",
          "@context": {
            "importerOfRecord": { "@id": "https://w3id.org/traceability#importerOfRecord" }
          }
        },
        "CBPEntryLineItem": {
          "@id": "https://w3id.org/traceability#CBPEntryLineItem",
          "@context": {
            "commodity": { "@id": "https://w3id.org/traceability#Commodity" },
            "productDescription": { "@id": "https://schema.org/description" },
            "itemCount": { "@id": "https://vocabulary.uncefact.org/despatchedQuantity" },
            "itemParty": { "@id": "https://w3id.org/traceability#itemParty" },
            "freeTradeZoneFilingDate": { "@id": "https://schema.org/endDate" },
            "freeTradeZoneStatus": { "@id": "https://w3id.org/traceability#freeTradeZoneStatus" },
            "countryOfOrigin": { "@id": "https://vocabulary.uncefact.org/originCountry" },
            "value": { "@id": "https://schema.org/MonetaryAmount" }
          }
        },
        "CBPEntrySummary": {
          "@id": "https://w3id.org/traceability#CBPEntrySummary",
          "@context": {
            "entryNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#AQM" },
            "entryType": { "@id": "https://w3id.org/traceability#entryType" },
            "summaryDate": { "@id": "https://vocabulary.uncefact.org/submissionDateTime" },
            "suretyCode": { "@id": "https://w3id.org/traceability#suretyCode" },
            "bondType": { "@id": "https://w3id.org/traceability#bondType" },
            "portCode": { "@id": "https://schema.org/Place" },
            "entryDate": { "@id": "https://vocabulary.uncefact.org/jurisdictionEntryDateTime" },
            "importingCarrier": { "@id": "https://vocabulary.uncefact.org/carrierParty" },
            "transportMode": { "@id": "https://w3id.org/traceability#transportMode" },
            "countryOfOrigin": { "@id": "https://w3id.org/traceability#countryOfOrigin" },
            "importDate": { "@id": "https://vocabulary.uncefact.org/arrivalRelatedDateTime" },
            "billOfLadingNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BM" },
            "manufacturerId": { "@id": "https://w3id.org/traceability#manufacturerId" },
            "exportingCountry": { "@id": "https://schema.org/addressCountry" },
            "exportDate": { "@id": "https://vocabulary.uncefact.org/departureRelatedDateTime" },
            "immediateTransportationNumber": {
              "@id": "https://w3id.org/traceability#immediateTransportationNumber"
            },
            "immediateTransportationDate": {
              "@id": "https://vocabulary.uncefact.org/actualOccurrenceDateTime"
            },
            "missingDocuments": { "@id": "https://w3id.org/traceability#missingDocuments" },
            "portOfLoading": { "@id": "https://schema.org/Place" },
            "portOfUnlading": { "@id": "https://schema.org/Place" },
            "locationOfGoods": { "@id": "https://schema.org/Place" },
            "consigneeNumber": { "@id": "https://w3id.org/traceability#consigneeNumber" },
            "importerNumber": { "@id": "https://w3id.org/traceability#importerOfRecord" },
            "referenceNumber": { "@id": "https://w3id.org/traceability#referenceNumber" },
            "ultimateConsignee": { "@id": "https://vocabulary.uncefact.org/shipToParty" },
            "importerOfRecord": { "@id": "https://vocabulary.uncefact.org/importerParty" },
            "descriptionOfMerchandise": {
              "@id": "https://w3id.org/traceability#descriptionOfMerchandise"
            },
            "otherFeeSummary": { "@id": "https://w3id.org/traceability#otherFeeSummary" },
            "totalEnteredValue": { "@id": "https://schema.org/MonetaryAmount" },
            "declarationOfImporter": { "@id": "https://w3id.org/traceability#declarationOfImporter" },
            "duty": { "@id": "https://schema.org/MonetaryAmount" },
            "tax": { "@id": "https://schema.org/MonetaryAmount" },
            "other": { "@id": "https://schema.org/MonetaryAmount" },
            "total": { "@id": "https://schema.org/MonetaryAmount" }
          }
        },
        "CBPEntrySummaryLineItem": {
          "@id": "https://w3id.org/traceability#CBPEntrySummaryLineItem",
          "@context": {
            "commodity": { "@id": "https://w3id.org/traceability#Commodity" },
            "adCvdNumber": { "@id": "https://w3id.org/traceability#adCvdNumber" },
            "categoryNumber": { "@id": "https://w3id.org/traceability#categoryNumber" },
            "otherFees": { "@id": "https://w3id.org/traceability#otherFees" },
            "grossWeight": { "@id": "https://schema.org/weight" },
            "manifestQuantity": { "@id": "https://w3id.org/traceability#manifestQuantity" },
            "netQuantity": { "@id": "https://schema.org/Quantity" },
            "enteredValue": { "@id": "https://schema.org/MonetaryAmount" },
            "charges": { "@id": "https://schema.org/MonetaryAmount" },
            "relationship": { "@id": "https://schema.org/MonetaryAmount" },
            "htsRate": { "@id": "https://w3id.org/traceability#htsRate" },
            "adCvdRate": { "@id": "https://w3id.org/traceability#adCvdRate" },
            "ircRate": { "@id": "https://w3id.org/traceability#ircRate" },
            "visaNumber": { "@id": "https://w3id.org/traceability#visaNumber" },
            "agriculturalLicenseNumber": {
              "@id": "https://w3id.org/traceability#agriculturalLicenseNumber"
            },
            "dutyAndIRTax": { "@id": "https://w3id.org/traceability#dutyAndIRTax" }
          }
        },
        "CBPEntryType86": {
          "@id": "https://w3id.org/traceability#CBPEntryType86",
          "@context": {
            "bolNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BM" },
            "entryNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#AQM" },
            "portOfEntry": { "@id": "https://schema.org/Place" },
            "shipper": { "@id": "https://vocabulary.uncefact.org/consignorParty" },
            "consignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "countryOfOrigin": { "@id": "https://vocabulary.uncefact.org/originCountry" },
            "quantity": { "@id": "https://w3id.org/traceability#quantity" },
            "fairRetailValue": { "@id": "https://schema.org/MonetaryAmount" },
            "htsusNumber": { "@id": "https://w3id.org/traceability#commodityCode" },
            "importerOfRecord": { "@id": "https://w3id.org/traceability#importerOfRecord" }
          }
        },
        "CBPImporterOfRecord": {
          "@id": "https://w3id.org/traceability#CBPImporterOfRecord",
          "@context": {
            "number": { "@id": "https://w3id.org/traceability#CBPImporterOfRecordNumber" },
            "identifierType": { "@id": "https://w3id.org/traceability#CBPImporterOfRecordType" }
          }
        },
        "CTPAT": {
          "@id": "https://w3id.org/traceability#CTPAT",
          "@context": {
            "sviNumber": { "@id": "https://w3id.org/traceability#sviNumber" },
            "ctpatAccountNumber": { "@id": "https://w3id.org/traceability#ctpatAccountNumber" },
            "tradeSector": { "@id": "https://schema.org/industry" },
            "tier": { "@id": "https://w3id.org/traceability#ctpatTier" },
            "dateOfLastValidation": { "@id": "https://schema.org/endDate" },
            "issuingCountry": { "@id": "https://schema.org/addressCountry" }
          }
        },
        "CTPATEIPApplication": {
          "@id": "https://w3id.org/traceability#CTPAT",
          "@context": {
            "applicant": { "@id": "https://w3id.org/traceability#applicant" },
            "applicantType": { "@id": "https://w3id.org/traceability#applicantType" }
          }
        },
        "CTPATMember": {
          "@id": "https://schema.org/Organization",
          "@context": {
            "name": { "@id": "https://schema.org/name" },
            "scac": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#AAZ" },
            "iataCarrierCode": { "@id": "https://onerecord.iata.org/cargo/Company#airlineCode" },
            "importerOfRecord": { "@id": "https://w3id.org/traceability#importerOfRecord" },
            "faxNumber": { "@id": "https://schema.org/faxNumber" },
            "url": { "@id": "https://schema.org/url" },
            "logo": { "@id": "https://schema.org/logo" }
          }
        },
        "CargoItem": {
          "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/cargoItem",
          "@context": {
            "cargoLineItems": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/cargoLineItem"
            },
            "carrierBookingReference": { "@id": "https://vocabulary.uncefact.org/carrierAssignedId" },
            "weight": { "@id": "https://schema.org/weight" },
            "volume": { "@id": "https://vocabulary.uncefact.org/grossVolumeMeasure" },
            "weightUnit": { "@id": "https://schema.org/unitCode" },
            "volumeUnit": { "@id": "https://schema.org/unitCode" },
            "numberOfPackages": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "packageCode": { "@id": "https://vocabulary.uncefact.org/packageTypeCode" }
          }
        },
        "CargoLineItem": {
          "@id": "https://w3id.org/traceability#CargoLineItem",
          "@context": {
            "cargoLineItemID": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/cargoLineItemID"
            },
            "shippingMarks": { "@id": "https://vocabulary.uncefact.org/physicalShippingMarks" },
            "descriptionOfGoods": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/descriptionOfGoods"
            },
            "HSCode": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/HSCode"
            }
          }
        },
        "ChargeDeclaration": {
          "@id": "https://w3id.org/traceability#ChargeDeclaration",
          "@context": {
            "weightCharge": { "@id": "https://schema.org/price" },
            "valuationCharge": { "@id": "https://schema.org/price" },
            "tax": { "@id": "https://schema.org/price" },
            "dueAgent": { "@id": "https://schema.org/price" },
            "dueCarrier": { "@id": "https://schema.org/price" },
            "total": { "@id": "https://schema.org/totalPrice" }
          }
        },
        "ChemicalProperty": {
          "@id": "https://w3id.org/traceability#ChemicalProperty",
          "@context": {
            "identifier": { "@id": "https://schema.org/identifier" },
            "name": { "@id": "https://schema.org/name" },
            "description": { "@id": "https://schema.org/description" },
            "formula": { "@id": "https://purl.obolibrary.org/obo/chebi/formula" },
            "inchi": { "@id": "https://purl.obolibrary.org/obo/chebi/inchi" },
            "inchikey": { "@id": "https://purl.obolibrary.org/obo/chebi/inchikey" }
          }
        },
        "CommissionEvent": {
          "@id": "https://w3id.org/traceability#CommissionEvent",
          "@context": {
            "place": { "@id": "https://schema.org/Place" },
            "organization": { "@id": "https://w3id.org/traceability#Organization" },
            "products": { "@id": "https://schema.org/Product" }
          }
        },
        "Commodity": {
          "@id": "https://w3id.org/traceability#Commodity",
          "@context": {
            "commodityCode": { "@id": "https://w3id.org/traceability#commodityCode" },
            "commodityCodeType": { "@id": "https://w3id.org/traceability#commodityCodeType" },
            "description": { "@id": "https://schema.org/description" }
          }
        },
        "ConsignmentItem": {
          "@id": "https://vocabulary.uncefact.org/ConsignmentItem",
          "@context": {
            "marksAndNumbers": { "@id": "https://vocabulary.uncefact.org/ShippingMarks" },
            "descriptionOfPackagesAndGoods": {
              "@id": "https://vocabulary.uncefact.org/natureIdentificationCargo"
            },
            "commodity": { "@id": "https://w3id.org/traceability#Commodity" },
            "packageQuantity": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "netWeight": { "@id": "https://vocabulary.uncefact.org/netWeightMeasure" },
            "grossWeight": { "@id": "https://vocabulary.uncefact.org/grossWeightMeasure" },
            "grossVolume": { "@id": "https://vocabulary.uncefact.org/grossVolumeMeasure" },
            "countryOfOrigin": { "@id": "https://vocabulary.uncefact.org/originCountry" },
            "manufacturer": { "@id": "https://vocabulary.uncefact.org/manufacturerParty" },
            "transportPackages": { "@id": "https://vocabulary.uncefact.org/transportPackage" }
          }
        },
        "ConsignmentRatingDetail": {
          "@id": "https://w3id.org/traceability#ConsignmentRatingDetail",
          "@context": {
            "numberOfPieces": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "grossWeight": { "@id": "https://vocabulary.uncefact.org/grossWeightMeasure" },
            "grossWeightUnit": { "@id": "https://schema.org/unitCode" },
            "rateClass": { "@id": "https://vocabulary.uncefact.org/freightChargeTariffClassCode" },
            "commodityItemNumber": { "@id": "https://vocabulary.uncefact.org/discountIndicator" },
            "chargeableWeight": { "@id": "https://schema.org/weight" },
            "rateCharge": { "@id": "https://schema.org/price" },
            "total": { "@id": "https://schema.org/totalPrice" },
            "natureAndVolumeOfGoods": { "@id": "https://schema.org/description" }
          }
        },
        "ContactPoint": {
          "@id": "https://schema.org/ContactPoint",
          "@context": {
            "name": { "@id": "https://schema.org/name" },
            "place": { "@id": "https://w3id.org/traceability#place" },
            "email": { "@id": "https://schema.org/email" },
            "phoneNumber": { "@id": "https://schema.org/telephone" },
            "jobTitle": { "@id": "https://schema.org/jobTitle" }
          }
        },
        "Customer": {
          "@id": "https://w3id.org/traceability#Customer",
          "@context": {
            "name": { "@id": "https://schema.org/name" },
            "address": { "@id": "https://schema.org/PostalAddress" },
            "telephone": { "@id": "https://schema.org/telephone" },
            "email": { "@id": "https://schema.org/email" }
          }
        },
        "DCSAShippingInstruction": {
          "@id": "https://vocabulary.uncefact.org/TransportInstructions",
          "@context": {
            "shippingInstructionID": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#TIN" },
            "transportDocumentType": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/transportDocumentType"
            },
            "preCarriageUnderShippersResponsibility": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/preCarriageUnderShippersResponsibility"
            },
            "invoicePayableAt": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/invoicePayableAt"
            },
            "carrierBookingReference": {
              "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BN"
            },
            "cargoItems": { "@id": "https://vocabulary.uncefact.org/includedConsignmentItem" },
            "utilizedTransportEquipments": {
              "@id": "https://vocabulary.uncefact.org/utilizedTransportEquipment"
            },
            "shipmentLocations": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DOCUMENTATION_DOMAIN/1.0.0#/components/schemas/shipmentLocation"
            },
            "shipper": { "@id": "https://vocabulary.uncefact.org/consignorParty" },
            "consignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "invoicePayerShipper": { "@id": "https://vocabulary.uncefact.org/consignorParty" },
            "invoicePayerConsignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "firstNotify": { "@id": "https://vocabulary.uncefact.org/notifiedParty" },
            "secondNotify": { "@id": "https://vocabulary.uncefact.org/notifiedParty" },
            "otherNotify": { "@id": "https://vocabulary.uncefact.org/notifiedParty" },
            "shippersFreightForwarder": {
              "@id": "https://vocabulary.uncefact.org/freightForwarderParty"
            },
            "consigneesFreightForwarder": {
              "@id": "https://vocabulary.uncefact.org/freightForwarderParty"
            }
          }
        },
        "DCSATransportDocument": {
          "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/transportDocument",
          "@context": {
            "transportDocumentReference": {
              "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BM"
            },
            "placeOfIssue": { "@id": "https://vocabulary.uncefact.org/issueLocation" },
            "issueDate": { "@id": "https://vocabulary.uncefact.org/issueDateTime" },
            "shippedOnBoardDate": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.2#/components/schemas/shippedOnBoardDate"
            },
            "receivedForShipmentDate": {
              "@id": "https://vocabulary.uncefact.org/availabilityDueDateTime"
            },
            "termsAndConditions": {
              "@id": "https://vocabulary.uncefact.org/termsAndConditionsDescription"
            },
            "issuerCode": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#AAZ" },
            "issuerCodeListProvider": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.2#/components/schemas/issuerCodeListProvider"
            },
            "declaredValueCurrency": { "@id": "https://schema.org/currency" },
            "cargoMovementTypeAtOrigin": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.2#/components/schemas/cargoMovementTypeAtOrigin"
            },
            "cargoMovementTypeAtDestination": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.2#/components/schemas/cargoMovementTypeAtDestination"
            },
            "receiptDeliveryTypeAtOrigin": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.2#/components/schemas/receiptDeliveryTypeAtOrigin"
            },
            "receiptDeliveryTypeAtDestination": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.2#/components/schemas/receiptDeliveryTypeAtDestination"
            },
            "serviceContractReference": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.2#/components/schemas/serviceContractReference"
            },
            "shippingInstruction": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/shippingInstruction"
            },
            "charges": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/charges"
            },
            "clauses": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/clauses"
            },
            "transports": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/transports"
            }
          }
        },
        "DeMinimisShipment": {
          "@id": "https://w3id.org/traceability#DeMinimisShipment",
          "@context": {
            "originatorCode": { "@id": "https://w3id.org/traceability#originatorCode" },
            "participantFilerType": { "@id": "https://w3id.org/traceability#participantFilerType" },
            "shipmentTrackingNumber": {
              "@id": "https://vocabulary.uncefact.org/MarkingInstructionCodeList#37"
            },
            "houseBillOfLadingNumber": {
              "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BH"
            },
            "masterBillOfLadingNumber": {
              "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BM"
            },
            "modeOfTransportation": { "@id": "https://vocabulary.uncefact.org/mode" },
            "shipmentInitiator": { "@id": "https://w3id.org/traceability#shipmentInitiator" },
            "seller": { "@id": "https://vocabulary.uncefact.org/sellerParty" },
            "buyer": { "@id": "https://vocabulary.uncefact.org/buyerParty" },
            "finalDeliverTo": { "@id": "https://vocabulary.uncefact.org/shipToParty" },
            "enhancedProductDescription": {
              "@id": "https://w3id.org/traceability#enhancedProductDescription"
            },
            "shipmentSecurityScan": { "@id": "https://w3id.org/traceability#shipmentSecurityScan" },
            "knownCarrierCustomerFlag": {
              "@id": "https://w3id.org/traceability#knownCarrierCustomerFlag"
            },
            "knownMarketplaceSellerFlag": {
              "@id": "https://w3id.org/traceability#knownMarketplaceSellerFlag"
            },
            "marketplaceSellerAccountNumber": {
              "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#ADE"
            },
            "productPicture": { "@id": "https://schema.org/image" },
            "listedPriceOnMarketplace": { "@id": "https://schema.org/price" }
          }
        },
        "DeliverySchedule": {
          "@id": "https://w3id.org/traceability#DeliverySchedule",
          "@context": {
            "transporter": { "@id": "https://schema.org/agent" },
            "batchNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BT" },
            "commodity": { "@id": "https://w3id.org/traceability#Commodity" },
            "place": { "@id": "https://schema.org/toLocation" },
            "consignor": { "@id": "https://vocabulary.uncefact.org/consignorParty" },
            "consignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "scheduledVolume": { "@id": "https://w3id.org/traceability#QuantitativeValue" },
            "scheduledDate": { "@id": "https://schema.org/departureTime" },
            "injectionVolume": { "@id": "https://w3id.org/traceability#QuantitativeValue" },
            "injectionDate": { "@id": "https://schema.org/departureTime" },
            "injectionEndDate": { "@id": "https://schema.org/departureTime" },
            "deliveryDate": { "@id": "https://schema.org/arrivalTime" },
            "deliveryEndDate": { "@id": "https://schema.org/arrivalTime" },
            "portOfEntry": { "@id": "https://w3id.org/traceability#Place" },
            "portOfDestination": { "@id": "https://w3id.org/traceability#Place" },
            "portOfArrival": { "@id": "https://w3id.org/traceability#Place" },
            "addressCountry": { "@id": "https://schema.org/addressCountry" }
          }
        },
        "DeliveryStatement": {
          "@id": "https://w3id.org/traceability#DeliveryStatement",
          "@context": {
            "commodity": { "@id": "https://w3id.org/traceability#Commodity" },
            "deliveredDate": { "@id": "https://schema.org/endDate" },
            "deliveredVolume": { "@id": "https://schema.org/MeasuredValue" },
            "transporter": { "@id": "https://schema.org/agent" },
            "consignor": { "@id": "https://vocabulary.uncefact.org/consignorParty" },
            "place": { "@id": "https://schema.org/toLocation" },
            "observation": { "@id": "https://w3id.org/traceability#observation" }
          }
        },
        "EDDShape": {
          "@id": "https://w3id.org/traceability#EDDShape",
          "@context": {
            "meta": { "@id": "https://w3id.org/traceability#EDDShapeMeta" },
            "reporter": { "@id": "https://schema.org/name" },
            "scientificName": { "@id": "http://rs.tdwg.org/dwc/terms/scientificName" },
            "commonName": { "@id": "http://rs.tdwg.org/dwc/terms/vernacularName" },
            "subjectNativity": { "@id": "http://rs.tdwg.org/dwc/terms/establishmentMeans" },
            "occurrenceStatus": { "@id": "http://rs.tdwg.org/dwc/iri/measurementValue" },
            "status": { "@id": "https://schema.org/description" },
            "observationDate": { "@id": "http://rs.tdwg.org/dwc/terms/eventDate" },
            "dateEntered": { "@id": "http://rs.tdwg.org/dwc/terms/eventDate" },
            "dateUpdated": { "@id": "http://rs.tdwg.org/dwc/terms/eventDate" },
            "location": { "@id": "https://schema.org/location" },
            "mapResources": { "@id": "https://w3id.org/traceability#MapResource" },
            "naDatum": { "@id": "http://rs.tdwg.org/dwc/terms/geodeticDatum" },
            "coordinateUncertainty": {
              "@id": "http://rs.tdwg.org/dwc/terms/coordinateUncertaintyInMeters"
            },
            "centroidType": { "@id": "https://schema.org/polygon" },
            "abundance": { "@id": "https://schema.org/description" },
            "infestedAreaAcres": { "@id": "http://rs.tdwg.org/dwc/terms/measurementValue" },
            "grossAreaAcres": { "@id": "http://rs.tdwg.org/dwc/terms/measurementValue" },
            "percentCover": { "@id": "http://rs.tdwg.org/dwc/terms/measurementValue" },
            "density": { "@id": "http://rs.tdwg.org/dwc/terms/measurementRemarks" },
            "quantity": { "@id": "http://rs.tdwg.org/dwc/terms/organismQuantity" },
            "quantityUnits": { "@id": "http://rs.tdwg.org/dwc/terms/organismQuantityType" },
            "approximateQuantity": { "@id": "http://rs.tdwg.org/dwc/terms/organismQuantity" },
            "incidence": { "@id": "http://rs.tdwg.org/dwc/terms/measurementValue" },
            "severity": { "@id": "http://rs.tdwg.org/dwc/terms/measurementValue" },
            "managementStatus": { "@id": "https://schema.org/status" },
            "habitat": { "@id": "http://rs.tdwg.org/dwc/terms/habitat" },
            "siteName": { "@id": "http://rs.tdwg.org/dwc/terms/locationID" },
            "recordBasis": { "@id": "http://rs.tdwg.org/dwc/terms/samplingProtocol" },
            "surveyor": { "@id": "http://rs.tdwg.org/dwc/terms/recordedBy" },
            "dateUncertaintyDays": { "@id": "http://rs.tdwg.org/dwc/terms/measurementAccuracy" },
            "visitType": { "@id": "https://schema.org/description" },
            "persistentId": { "@id": "http://rs.tdwg.org/dwc/terms/occurrenceID" },
            "uuid": { "@id": "http://rs.tdwg.org/dwc/terms/dateIdentified" },
            "reviewer": { "@id": "http://rs.tdwg.org/dwc/terms/identifiedBy" },
            "verificationMethod": { "@id": "http://rs.tdwg.org/dwc/terms/identificationRemarks" },
            "verified": { "@id": "http://rs.tdwg.org/dwc/terms/identificationVerificationStatus" },
            "identificationCredibility": { "@id": "http://rs.tdwg.org/dwc/terms/identificationRemarks" }
          }
        },
        "EDDShapeMeta": {
          "@id": "https://w3id.org/traceability#EDDShapeMeta",
          "@context": {
            "recordOwner": { "@id": "https://schema.org/name" },
            "shapeType": { "@id": "https://schema.org/description" },
            "method": { "@id": "http://rs.tdwg.org/dwc/terms/locationRemarks" },
            "numberCollected": { "@id": "http://rs.tdwg.org/dwc/terms/measurementRemarks" },
            "populationStatus": { "@id": "http://rs.tdwg.org/dwc/terms/degreeOfEstablishment" },
            "smallestOrganismSampled": { "@id": "https://schema.org/size" },
            "largestOrganismSampled": { "@id": "https://schema.org/size" },
            "hostScientificName": { "@id": "http://rs.tdwg.org/dwc/terms/scientificName" },
            "hostName": { "@id": "http://rs.tdwg.org/dwc/terms/vernacularName" },
            "hostPhenology": { "@id": "http://rs.tdwg.org/dwc/terms/lifeStage" },
            "hostDamage": { "@id": "https://schema.org/description" },
            "localOwnership": { "@id": "http://rs.tdwg.org/dwc/terms/locality" },
            "museum": { "@id": "https://schema.org/name" },
            "museumRecord": { "@id": "http://rs.tdwg.org/dwc/terms/catalogNumber" },
            "voucher": { "@id": "http://rs.tdwg.org/dwc/terms/disposition" },
            "observationId": { "@id": "http://rs.tdwg.org/dwc/terms/identifiedBy" },
            "collectionTimeMinutes": { "@id": "https://schema.org/activityDuration" },
            "originalRecordId": { "@id": "http://rs.tdwg.org/dwc/terms/recordNumber" },
            "originalReportedName": { "@id": "http://rs.tdwg.org/dwc/terms/verbatimIdentification" },
            "recordSourceType": { "@id": "http://rs.tdwg.org/dwc/terms/measurementRemarks" },
            "dataCollectionMethod": { "@id": "http://rs.tdwg.org/dwc/terms/measurementMethod" },
            "trapType": { "@id": "http://rs.tdwg.org/dwc/terms/samplingProtocol" },
            "numberTraps": { "@id": "http://rs.tdwg.org/dwc/terms/samplingEffort" },
            "targetName": { "@id": "http://rs.tdwg.org/dwc/terms/organismName" },
            "targetCount": { "@id": "http://rs.tdwg.org/dwc/terms/organismQuantity" },
            "targetRange": { "@id": "http://rs.tdwg.org/dwc/terms/organismQuantity" },
            "phenology": { "@id": "http://rs.tdwg.org/dwc/terms/organismRemarks" },
            "lifeStatus": { "@id": "http://rs.tdwg.org/dwc/terms/occurrenceRemarks" },
            "sex": { "@id": "http://rs.tdwg.org/dwc/terms/sex" },
            "waterBodyName": { "@id": "http://rs.tdwg.org/dwc/terms/waterBody" },
            "waterBodyType": { "@id": "http://rs.tdwg.org/dwc/terms/occurrenceRemarks" },
            "substrate": { "@id": "http://rs.tdwg.org/dwc/terms/occurrenceRemarks" },
            "treatmentArea": { "@id": "http://rs.tdwg.org/dwc/iri/measurementValue" },
            "plantsTreated": { "@id": "http://rs.tdwg.org/dwc/terms/organismQuantity" },
            "treatmentComments": { "@id": "http://rs.tdwg.org/dwc/terms/eventRemarks" },
            "reference": { "@id": "http://rs.tdwg.org/dwc/terms/associatedReferences" },
            "locality": { "@id": "http://rs.tdwg.org/dwc/terms/locationRemarks" },
            "comments": { "@id": "http://rs.tdwg.org/dwc/terms/eventRemarks" },
            "publicReviewerComments": { "@id": "http://rs.tdwg.org/dwc/terms/identificationRemarks" }
          }
        },
        "Entity": {
          "@id": "https://w3id.org/traceability#Entity",
          "@context": {
            "entityType": { "@id": "https://schema.org/additionalType" },
            "name": { "@id": "https://schema.org/name" },
            "legalName": { "@id": "https://schema.org/legalName" },
            "url": { "@id": "https://schema.org/url" },
            "taxId": { "@id": "https://schema.org/taxID" },
            "address": { "@id": "https://schema.org/PostalAddress" },
            "email": { "@id": "https://schema.org/email" },
            "phoneNumber": { "@id": "https://schema.org/telephone" },
            "faxNumber": { "@id": "https://schema.org/faxNumber" }
          }
        },
        "EntryNumber": {
          "@id": "https://w3id.org/traceability#EntryNumber",
          "@context": {
            "entryNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#AQM" }
          }
        },
        "Event": { "@id": "https://w3id.org/traceability#EventCredential", "@context": {} },
        "ExternalResource": {
          "@id": "https://w3id.org/traceability#ExternalResource",
          "@context": {
            "uri": { "@id": "https://schema.org/contentUrl" },
            "hash": { "@id": "https://schema.org/sha256" }
          }
        },
        "FSMAAbstractKDE": {
          "@id": "https://w3id.org/traceability#FSMAAbstractKDE",
          "@context": {
            "name": { "@id": "https://schema.org/propertyID" },
            "value": { "@id": "https://schema.org/value" }
          }
        },
        "FSMACreatingCTE": {
          "@id": "https://w3id.org/traceability#FSMACreatingCTE",
          "@context": {
            "food": { "@id": "https://w3id.org/traceability#FSMAProduct" },
            "location": { "@id": "https://schema.org/location" },
            "dateCompleted": { "@id": "https://vocabulary.uncefact.org/creationDateTime" },
            "additionalData": { "@id": "https://w3id.org/traceability#FSMAAbstractKDE" }
          }
        },
        "FSMAFirstReceiverData": {
          "@id": "https://w3id.org/traceability#FSMAFirstReceiverData",
          "@context": {
            "traceabilityLot": { "@id": "https://w3id.org/traceability#FSMATraceabilityLot" },
            "originatorLocation": { "@id": "https://schema.org/location" },
            "harvestDate": { "@id": "https://vocabulary.uncefact.org/harvestDateTime" },
            "coolingLocation": { "@id": "https://schema.org/location" },
            "coolingDate": { "@id": "https://vocabulary.uncefact.org/actualOccurrenceDateTime" },
            "packingLocation": { "@id": "https://schema.org/location" },
            "packingDate": { "@id": "https://www.gs1.org/voc/packagingDate" },
            "additionalData": { "@id": "https://w3id.org/traceability#FSMAAbstractKDE" }
          }
        },
        "FSMAGrowingCTE": {
          "@id": "https://w3id.org/traceability#FSMAGrowingCTE",
          "@context": {
            "traceabilityLot": { "@id": "https://w3id.org/traceability#FSMATraceabilityLot" },
            "growingAreaCoordinates": { "@id": "https://w3id.org/traceability#GeoCoordinates" },
            "additionalData": { "@id": "https://w3id.org/traceability#FSMAAbstractKDE" }
          }
        },
        "FSMAProduct": {
          "@id": "https://w3id.org/traceability#FSMAProduct",
          "@context": {
            "traceabilityLot": { "@id": "https://w3id.org/traceability#FSMATraceabilityLot" },
            "quantity": { "@id": "https://vocabulary.uncefact.org/applicableQuantity" },
            "unit": { "@id": "https://vocabulary.uncefact.org/applicableQuantityUnitTypeCode" },
            "additionalData": { "@id": "https://w3id.org/traceability#FSMAAbstractKDE" }
          }
        },
        "FSMAReceivingCTE": {
          "@id": "https://w3id.org/traceability#FSMAReceivingCTE",
          "@context": {
            "shipment": { "@id": "https://w3id.org/traceability#FSMAShipment" },
            "dateReceived": { "@id": "https://vocabulary.uncefact.org/receivedDateTime" },
            "additionalData": { "@id": "https://w3id.org/traceability#FSMAAbstractKDE" }
          }
        },
        "FSMAShipment": {
          "@id": "https://w3id.org/traceability#FSMAShipment",
          "@context": {
            "product": { "@id": "https://w3id.org/traceability#FSMAProduct" },
            "from": { "@id": "https://schema.org/fromLocation" },
            "to": { "@id": "https://schema.org/toLocation" },
            "additionalData": { "@id": "https://w3id.org/traceability#FSMAAbstractKDE" }
          }
        },
        "FSMAShippingCTE": {
          "@id": "https://w3id.org/traceability#FSMAShippingCTE",
          "@context": {
            "shipment": { "@id": "https://w3id.org/traceability#FSMAShipment" },
            "dateShipped": { "@id": "https://schema.org/startDate" },
            "additionalData": { "@id": "https://w3id.org/traceability#FSMAAbstractKDE" }
          }
        },
        "FSMATraceabilityLot": {
          "@id": "https://w3id.org/traceability#FSMATraceabilityLot",
          "@context": {
            "lotCode": { "@id": "https://www.gs1.org/voc/hasBatchLotNumber" },
            "lotCodeAssignmentMethod": { "@id": "https://schema.org/description" },
            "lotCodeGeneratorLocation": { "@id": "https://schema.org/location" },
            "lotCodeGeneratorPOC": { "@id": "https://schema.org/contactPoint" },
            "lotType": { "@id": "https://schema.org/additionalType" },
            "additionalData": { "@id": "https://w3id.org/traceability#FSMAAbstractKDE" }
          }
        },
        "FSMATransformingCTE": {
          "@id": "https://w3id.org/traceability#FSMATransformingCTE",
          "@context": {
            "foodUsed": { "@id": "https://w3id.org/traceability#FSMAProduct" },
            "foodProduced": { "@id": "https://w3id.org/traceability#FSMAProduct" },
            "locationTransformed": { "@id": "https://schema.org/location" },
            "dateCompleted": { "@id": "https://vocabulary.uncefact.org/occurrenceDateTime" },
            "additionalData": { "@id": "https://w3id.org/traceability#FSMAAbstractKDE" }
          }
        },
        "FoodDefenseDeficiency": {
          "@id": "https://w3id.org/traceability#FoodDefenseDeficiency",
          "@context": {
            "number": { "@id": "https://schema.org/identifier" },
            "description": { "@id": "https://schema.org/description" },
            "proposedCorrectionDate": { "@id": "https://vocabulary.uncefact.org/occurrenceDateTime" },
            "dateCorrected": { "@id": "https://vocabulary.uncefact.org/occurrenceDateTime" }
          }
        },
        "FoodDefenseInspection": {
          "@id": "https://w3id.org/traceability#FoodDefenseInspection",
          "@context": {
            "commonInfo": { "@id": "https://w3id.org/traceability#AgricultureInspectionCommonInfo" },
            "questions": { "@id": "https://w3id.org/traceability#FoodDefenseQuestion" },
            "deficiencies": { "@id": "https://w3id.org/traceability#FoodDefenseDeficiency" }
          }
        },
        "FoodDefenseQuestion": {
          "@id": "https://w3id.org/traceability#FoodDefenseQuestion",
          "@context": {
            "number": { "@id": "https://schema.org/identifier" },
            "facility": { "@id": "https://schema.org/location" },
            "response": { "@id": "https://vocabulary.uncefact.org/assertion" },
            "rating": { "@id": "https://vocabulary.uncefact.org/assertion" }
          }
        },
        "FoodGradeInspection": {
          "@id": "https://w3id.org/traceability#FoodGradeInspection",
          "@context": {
            "commonInfo": { "@id": "https://w3id.org/traceability#AgricultureInspectionCommonInfo" },
            "shipment": { "@id": "https://vocabulary.uncefact.org/transportPackage" },
            "loadingStatus": { "@id": "https://vocabulary.uncefact.org/DocumentCodeList#287" },
            "carrierTypeName": { "@id": "https://vocabulary.uncefact.org/utilizedTransportEquipment" },
            "refrigerationUnitOn": { "@id": "https://vocabulary.uncefact.org/DocumentCodeList#287" },
            "doorsOpen": { "@id": "https://vocabulary.uncefact.org/DocumentCodeList#287" },
            "lots": { "@id": "https://w3id.org/traceability#FoodGradeInspectionLot" },
            "generalRemarks": { "@id": "https://vocabulary.uncefact.org/remarks" },
            "estimatedCharges": { "@id": "https://vocabulary.uncefact.org/applicableServiceCharge" }
          }
        },
        "FoodGradeInspectionDefect": {
          "@id": "https://w3id.org/traceability#FoodGradeInspectionDefect",
          "@context": {
            "offsizeDefect": { "@id": "https://vocabulary.uncefact.org/damageRemarks" },
            "averageDefects": { "@id": "https://qudt.org/vocab/unit/PERCENT" },
            "damage": { "@id": "https://qudt.org/vocab/unit/PERCENT" },
            "seriousDamage": { "@id": "https://qudt.org/vocab/unit/PERCENT" },
            "verySeriousDamage": { "@id": "https://qudt.org/vocab/unit/PERCENT" }
          }
        },
        "FoodGradeInspectionLot": {
          "@id": "https://w3id.org/traceability#FoodGradeInspectionLot",
          "@context": {
            "agricultureProduct": { "@id": "https://w3id.org/traceability#AgricultureProduct" },
            "lotIdentifier": { "@id": "https://www.gs1.org/voc/hasBatchLotNumber" },
            "numberContainers": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "countInspected": { "@id": "https://vocabulary.uncefact.org/remark" },
            "brandMarkings": { "@id": "https://vocabulary.uncefact.org/brandName" },
            "samples": { "@id": "https://w3id.org/traceability#FoodGradeInspectionSample" },
            "defects": { "@id": "https://w3id.org/traceability#FoodGradeInspectionDefect" },
            "grade": { "@id": "https://w3id.org/traceability#FoodGradeInspectionResult" },
            "remarks": { "@id": "https://vocabulary.uncefact.org/remark" },
            "minTemperature": { "@id": "https://schema.org/measuredValue" },
            "maxTemperature": { "@id": "https://schema.org/measuredValue" }
          }
        },
        "FoodGradeInspectionResult": {
          "@id": "https://w3id.org/traceability#FoodGradeInspectionResult",
          "@context": {
            "gradeInspected": { "@id": "https://vocabulary.uncefact.org/standard" },
            "requirementsMet": { "@id": "https://vocabulary.uncefact.org/assertion" },
            "details": { "@id": "https://vocabulary.uncefact.org/additionalInformationNote" }
          }
        },
        "FoodGradeInspectionSample": {
          "@id": "https://w3id.org/traceability#FoodGradeInspectionSample",
          "@context": {
            "sampleSizeValue": { "@id": "https://vocabulary.uncefact.org/applicableQuantity" },
            "sampleSizeUnits": {
              "@id": "https://vocabulary.uncefact.org/applicableQuantityUnitTypeCode"
            },
            "sampleProperties": {
              "@id": "https://w3id.org/traceability#FoodGradeInspectionSampleProperty"
            }
          }
        },
        "FoodGradeInspectionSampleProperty": {
          "@id": "https://w3id.org/traceability#FoodGradeInspectionSampleProperty",
          "@context": {
            "propertyName": { "@id": "https://vocabulary.uncefact.org/parameterValue" },
            "propertyValue": { "@id": "https://vocabulary.uncefact.org/measuredValue" }
          }
        },
        "ForeignChargeDeclaration": {
          "@id": "https://w3id.org/traceability#ForeignChargeDeclaration",
          "@context": {
            "foreignCurrencyConvertionRate": { "@id": "https://schema.org/currentExchangeRate" },
            "foreignChargesCurrency": { "@id": "https://schema.org/currency" },
            "foreignCharges": { "@id": "https://schema.org/price" }
          }
        },
        "FreightManifest": {
          "@id": "https://vocabulary.uncefact.org/manifestRelatedDocument",
          "@context": {
            "carrier": { "@id": "https://vocabulary.uncefact.org/carrierParty" },
            "carrierCode": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#AAZ" },
            "transportMeans": { "@id": "https://vocabulary.uncefact.org/transportMeans" },
            "transportMeansId": { "@id": "https://schema.org/identifier" },
            "voyage": { "@id": "https://vocabulary.uncefact.org/TransportMovement" },
            "billsOfLading": { "@id": "https://vocabulary.uncefact.org/manifestRelatedDocument" }
          }
        },
        "GAPCorrectiveActionReport": {
          "@id": "https://w3id.org/traceability#GAPCorrectiveActionReport",
          "@context": {
            "nonconformityDescription": { "@id": "https://schema.org/description" },
            "notifiedCompanyStaff": { "@id": "https://schema.org/actionStatus" },
            "correctiveAction": { "@id": "https://schema.org/potentialAction" },
            "affirmingRepresentative": { "@id": "https://vocabulary.uncefact.org/associatedParty" }
          }
        },
        "GAPInspection": {
          "@id": "https://w3id.org/traceability#GAPInspection",
          "@context": {
            "GAPPlus": { "@id": "https://vocabulary.uncefact.org/documentTypeCode" },
            "commonInfo": { "@id": "https://w3id.org/traceability#AgricultureInspectionCommonInfo" },
            "usesLogo": { "@id": "https://vocabulary.uncefact.org/assertion" },
            "subjectToRule": { "@id": "https://vocabulary.uncefact.org/regulationConformityId" },
            "operationDescription": { "@id": "https://schema.org/description" },
            "harvestCompany": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "otherContractors": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "commoditiesCovered": { "@id": "https://schema.org/ItemList" },
            "commoditiesProduced": { "@id": "https://schema.org/ItemList" },
            "totalArea": { "@id": "https://www.gs1.org/voc/grossArea" },
            "fieldOpsHarvestingScope": { "@id": "https://www.gs1.org/voc/certificationStatement" },
            "postHarvestOpsScope": { "@id": "https://www.gs1.org/voc/certificationStatement" },
            "logoUseScope": { "@id": "https://www.gs1.org/voc/certificationStatement" },
            "tomatoProdHarvestingScope": { "@id": "https://www.gs1.org/voc/certificationStatement" },
            "tomatoPackinghouseScope": { "@id": "https://www.gs1.org/voc/certificationStatement" },
            "tomatoGreenhouseScope": { "@id": "https://www.gs1.org/voc/certificationStatement" },
            "tomatoPackingDistributionScope": {
              "@id": "https://www.gs1.org/voc/certificationStatement"
            },
            "personsInterviewed": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "requestedBy": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "distributeTo": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "additionalComments": { "@id": "https://vocabulary.uncefact.org/remarks" },
            "reviewingOfficial": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "dateReviewed": { "@id": "https://www.gs1.org/voc/certificationAuditDate" },
            "meetsCriteria": { "@id": "https://www.gs1.org/voc/certificationStatus" },
            "requirementResults": { "@id": "https://w3id.org/traceability#GAPRequirementResult" }
          }
        },
        "GAPLocationCertification": {
          "@id": "https://w3id.org/traceability#GAPLocationCertification",
          "@context": {
            "location": { "@id": "https://www.gs1.org/voc/certificationSubject" },
            "gapInspection": { "@id": "https://www.gs1.org/voc/certification" },
            "isCertified": { "@id": "https://www.gs1.org/voc/certificationStatus" }
          }
        },
        "GAPRequirementResult": {
          "@id": "https://w3id.org/traceability#GAPRequirementResult",
          "@context": {
            "requirementNumber": { "@id": "https://vocabulary.uncefact.org/standard" },
            "resultCode": { "@id": "https://vocabulary.uncefact.org/assertionCode" },
            "auditorComments": { "@id": "https://vocabulary.uncefact.org/remarks" },
            "correctiveActionReport": {
              "@id": "https://w3id.org/traceability#GAPCorrectiveActionReport"
            }
          }
        },
        "GeoCoordinates": {
          "@id": "https://schema.org/GeoCoordinates",
          "@context": {
            "latitude": { "@id": "https://schema.org/latitude" },
            "longitude": { "@id": "https://schema.org/longitude" }
          }
        },
        "HouseBillOfLading": {
          "@id": "https://w3id.org/traceability#HouseBillOfLading",
          "@context": {
            "billOfLadingNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BM" },
            "bookingNumber": { "@id": "https://vocabulary.uncefact.org/carrierAssignedId" },
            "shippersReferences": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#FF" },
            "shipper": { "@id": "https://vocabulary.uncefact.org/consignorParty" },
            "consignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "notifyParty": { "@id": "https://vocabulary.uncefact.org/notifiedParty" },
            "carrier": { "@id": "https://vocabulary.uncefact.org/carrierParty" },
            "preCarriageTransportMovement": {
              "@id": "https://vocabulary.uncefact.org/preCarriageTransportMovement"
            },
            "mainCarriageTransportMovement": {
              "@id": "https://vocabulary.uncefact.org/mainCarriageTransportMovement"
            },
            "onCarriageTransportMovement": {
              "@id": "https://vocabulary.uncefact.org/onCarriageTransportMovement"
            },
            "placeOfReceipt": { "@id": "https://schema.org/Place" },
            "portOfLoading": { "@id": "https://vocabulary.uncefact.org/transshipmentLocation" },
            "placeOfDelivery": { "@id": "https://schema.org/Place" },
            "portOfDischarge": { "@id": "https://vocabulary.uncefact.org/unloadingLocation" },
            "totalNumberOfPackages": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "transportEquipmentQuantity": {
              "@id": "https://vocabulary.uncefact.org/transportEquipmentQuantity"
            },
            "includedConsignmentItems": {
              "@id": "https://vocabulary.uncefact.org/includedConsignmentItem"
            },
            "freightAndCharges": { "@id": "https://vocabulary.uncefact.org/applicableServiceCharge" },
            "declaredValue": {
              "@id": "https://vocabulary.uncefact.org/declaredValueForCarriageAmount"
            },
            "termsAndConditions": {
              "@id": "https://vocabulary.uncefact.org/termsAndConditionsDescription"
            }
          }
        },
        "IATAAirWaybill": {
          "@id": "https://w3id.org/traceability#IATAAirWaybill",
          "@context": {
            "airWaybillNumber": { "@id": "https://schema.org/orderNumber" },
            "waybillType": { "@id": "https://schema.org/DigitalDocument" },
            "airlineCodeNumber": { "@id": "https://onerecord.iata.org/cargo/Company#airlineCode" },
            "serialNumber": { "@id": "https://schema.org/serialNumber" },
            "airportOfDeparture": { "@id": "https://onerecord.iata.org/cargo/Location#code" },
            "carrier": { "@id": "https://vocabulary.uncefact.org/carrierParty" },
            "conditionsOfContract": { "@id": "https://schema.org/termsOfService" },
            "shipper": { "@id": "https://vocabulary.uncefact.org/consignorParty" },
            "shippersAccountNumber": { "@id": "https://schema.org/accountId" },
            "consignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "consigneesAccountNumber": { "@id": "https://schema.org/accountId" },
            "issuingCarrierAgent": { "@id": "https://vocabulary.uncefact.org/carrierAgentParty" },
            "agentIATACode": { "@id": "https://onerecord.iata.org/cargo/Company#iataCargoAgentCode" },
            "agentAccountNumber": { "@id": "https://schema.org/accountId" },
            "requestedRouting": { "@id": "https://schema.org/Trip" },
            "destinationAirport": { "@id": "https://onerecord.iata.org/cargo/Company#airlineCode" },
            "requestedFlight": { "@id": "https://schema.org/Flight" },
            "requestedDate": { "@id": "https://w3id.org/traceability#requestDate" },
            "accountingInformation": { "@id": "https://vocabulary.uncefact.org/typeCode" },
            "currency": { "@id": "https://schema.org/currency" },
            "chargeCodes": { "@id": "https://vocabulary.uncefact.org/chargeCategoryCode" },
            "weightValuationChargesType": {
              "@id": "https://vocabulary.uncefact.org/chargeCategoryCode"
            },
            "otherChargesType": { "@id": "https://vocabulary.uncefact.org/chargeCategoryCode" },
            "declaredValueForCarriage": {
              "@id": "https://vocabulary.uncefact.org/declaredValueForCarriageAmount"
            },
            "declaredValueForCustoms": {
              "@id": "https://vocabulary.uncefact.org/customsValueSpecifiedAmount"
            },
            "amountOfInsurance": { "@id": "https://vocabulary.uncefact.org/insuranceValueAmount" },
            "insuranceClauses": { "@id": "https://vocabulary.uncefact.org/contractualClause" },
            "handlingInformation": { "@id": "https://vocabulary.uncefact.org/handlingInstructions" },
            "specialCustomsInformation": {
              "@id": "https://vocabulary.uncefact.org/SpecifiedDeclaration"
            },
            "consignmentRatingDetails": {
              "@id": "https://vocabulary.uncefact.org/includedConsignmentItem"
            },
            "totalNumberOfPieces": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "totalGrossWeight": { "@id": "https://vocabulary.uncefact.org/grossWeightMeasure" },
            "totalCharge": { "@id": "https://schema.org/totalPrice" },
            "otherCharges": { "@id": "https://schema.org/price" },
            "prepaidChargeDeclaration": {
              "@id": "https://w3id.org/traceability#PrepaidChargeDeclaration"
            },
            "prepaidTotal": { "@id": "https://schema.org/totalPrice" },
            "collectChargeDeclaration": {
              "@id": "https://w3id.org/traceability#CollectChargeDeclaration"
            },
            "destinationCollectChargeDeclaration": {
              "@id": "https://w3id.org/traceability#DestinationCollectChargeDeclaration"
            },
            "collectTotal": { "@id": "https://schema.org/totalPrice" },
            "shippersCertificationBox": {
              "@id": "https://vocabulary.uncefact.org/CertificateTypeCodeList#2"
            },
            "executedOn": { "@id": "https://w3id.org/traceability#executionTime" },
            "executedAt": { "@id": "https://schema.org/Place" }
          }
        },
        "ImporterSecurityFiling": {
          "@id": "https://w3id.org/traceability#ImporterSecurityFiling",
          "@context": {
            "seller": { "@id": "https://vocabulary.uncefact.org/sellerParty" },
            "buyer": { "@id": "https://vocabulary.uncefact.org/buyerParty" },
            "importer": { "@id": "https://vocabulary.uncefact.org/importerParty" },
            "consignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "shipToParty": { "@id": "https://vocabulary.uncefact.org/shipToParty" },
            "filingItems": { "@id": "https://vocabulary.uncefact.org/includedConsignmentItem" },
            "containerStuffingLocation": {
              "@id": "https://w3id.org/traceability#containerStuffingLocation"
            },
            "consolidator": { "@id": "https://vocabulary.uncefact.org/consolidatorParty" }
          }
        },
        "Inbond": {
          "@id": "https://w3id.org/traceability#Inbond",
          "@context": {
            "product": { "@id": "https://www.gs1.org/voc/Product" },
            "shipment": { "@id": "https://schema.org/ParcelDelivery" },
            "inBondNumber": { "@id": "https://w3id.org/traceability#inBondNumber" },
            "entryId": { "@id": "https://w3id.org/traceability#entryId" },
            "ftzNo": { "@id": "https://w3id.org/traceability#ftzNo" },
            "inBondType": { "@id": "https://w3id.org/traceability#inBondType" },
            "portOfEntry": { "@id": "https://www.gs1.org/voc/Place" },
            "portOfDestination": { "@id": "https://www.gs1.org/voc/Place" },
            "portOfArrival": { "@id": "https://www.gs1.org/voc/Place" },
            "carrier": { "@id": "https://vocabulary.uncefact.org/carrierParty" },
            "irsNumber": { "@id": "https://w3id.org/traceability#irsNumber" },
            "recipient": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "billOfLadingNumber": { "@id": "https://w3id.org/traceability#billOfLadingNumber" },
            "expectedDeliveryDate": { "@id": "https://schema.org/endDate" },
            "valuePerItem": { "@id": "https://schema.org/PriceSpecification" },
            "totalOrderValue": { "@id": "https://schema.org/PriceSpecification" }
          }
        },
        "InspectionReport": {
          "@id": "https://w3id.org/traceability#InspectionReport",
          "@context": {
            "comment": { "@id": "https://schema.org/comment" },
            "inspectors": { "@id": "https://schema.org/Person" },
            "place": { "@id": "https://schema.org/Place" },
            "chemicalObservation": { "@id": "https://schema.org/ItemList" },
            "mechanicalObservation": { "@id": "https://schema.org/ItemList" }
          }
        },
        "Inspector": {
          "@id": "https://w3id.org/traceability#Inspector",
          "@context": {
            "person": { "@id": "https://schema.org/Person" },
            "qualification": { "@id": "https://w3id.org/traceability#qualification" }
          }
        },
        "Instructions": {
          "@id": "https://vocabulary.uncefact.org/TransportInstructions",
          "@context": { "description": { "@id": "https://schema.org/description" } }
        },
        "InstrumentOfTrade": {
          "@id": "https://w3id.org/traceability#InstrumentOfTrade",
          "@context": {}
        },
        "IntellectualPropertyRights": {
          "@id": "https://w3id.org/traceability#IntellectualPropertyRights",
          "@context": {
            "intellectualPropertyRightsOwner": {
              "@id": "https://w3id.org/traceability#intellectualPropertyRightsOwner"
            },
            "intellectualPropertyRightsType": {
              "@id": "https://w3id.org/traceability#intellectualPropertyRightsType"
            },
            "intellectualPropertyRightsProduct": {
              "@id": "https://w3id.org/traceability#intellectualPropertyRightsProduct"
            }
          }
        },
        "IntellectualPropertyRightsAffirmation": {
          "@id": "https://w3id.org/traceability#IntellectualPropertyRightsAffirmation",
          "@context": {
            "affirmingParty": { "@id": "https://w3id.org/traceability#affirmingParty" },
            "intellectualPropertyRightsType": {
              "@id": "https://w3id.org/traceability#intellectualPropertyRightsType"
            },
            "evidenceDocumentUrl": { "@id": "https://schema.org/url" }
          }
        },
        "IntellectualPropertyRightsLicense": {
          "@id": "https://w3id.org/traceability#IntellectualPropertyRightsLicense",
          "@context": {}
        },
        "IntentToImport": {
          "@id": "https://w3id.org/traceability#IntentToImport",
          "@context": {
            "exporter": { "@id": "https://vocabulary.uncefact.org/exporterParty" },
            "importer": { "@id": "https://vocabulary.uncefact.org/importerParty" },
            "product": { "@id": "https://www.gs1.org/voc/Product" },
            "declarationDate": { "@id": "https://schema.org/startDate" }
          }
        },
        "Invoice": {
          "@id": "https://schema.org/Invoice",
          "@context": {
            "identifier": { "@id": "https://schema.org/identifier" },
            "invoiceNumber": { "@id": "https://vocabulary.uncefact.org/invoiceIssuerReference" },
            "customerReferenceNumber": {
              "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#CR"
            },
            "referencesOrder": { "@id": "https://schema.org/referencesOrder" },
            "billOfLadingNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BM" },
            "letterOfCreditNumber": { "@id": "https://vocabulary.uncefact.org/letterOfCreditDocument" },
            "portOfEntry": { "@id": "https://schema.org/Place" },
            "originCountry": { "@id": "https://vocabulary.uncefact.org/originCountry" },
            "destinationCountry": { "@id": "https://vocabulary.uncefact.org/destinationCountry" },
            "invoiceDate": { "@id": "https://vocabulary.uncefact.org/invoiceDateTime" },
            "purchaseDate": { "@id": "https://schema.org/paymentDueDate" },
            "seller": { "@id": "https://vocabulary.uncefact.org/sellerParty" },
            "buyer": { "@id": "https://vocabulary.uncefact.org/buyerParty" },
            "consignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "itemsShipped": { "@id": "https://schema.org/itemShipped" },
            "comments": { "@id": "https://schema.org/Comment" },
            "packageQuantity": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "totalWeight": { "@id": "https://schema.org/weight" },
            "termsOfDelivery": { "@id": "https://vocabulary.uncefact.org/specifiedDeliveryTerms" },
            "termsOfPayment": { "@id": "https://vocabulary.uncefact.org/specifiedPaymentTerms" },
            "termsOfSettlement": { "@id": "https://schema.org/currency" },
            "totalPaymentDue": { "@id": "https://schema.org/totalPaymentDue" },
            "discounts": { "@id": "https://schema.org/discount" },
            "deductions": { "@id": "https://vocabulary.uncefact.org/deductionAmount" },
            "tax": { "@id": "https://vocabulary.uncefact.org/taxTotalAmount" },
            "freightCost": { "@id": "https://schema.org/DeliveryChargeSpecification" },
            "insuranceCost": { "@id": "https://vocabulary.uncefact.org/insuranceChargeTotalAmount" }
          }
        },
        "LEIAddress": {
          "@id": "https://www.gleif.org/ontology/Base/PhysicalAddress",
          "@context": {
            "language": { "@id": "https://schema.org/inLanguage" },
            "firstAddressLine": { "@id": "https://www.gleif.org/ontology/Base/hasFirstAddressLine" },
            "addressNumberWithinBuilding": {
              "@id": "https://www.gleif.org/ontology/Base/hasAddressNumberWithinBuilding"
            },
            "mailRouting": { "@id": "https://www.gleif.org/ontology/Base/hasMailRouting" },
            "city": { "@id": "https://www.gleif.org/ontology/Base/hasCity" },
            "region": { "@id": "https://schema.org/addressRegion" },
            "country": { "@id": "https://schema.org/addressCountry" },
            "postalCode": { "@id": "https://www.gleif.org/ontology/Base/hasPostalCode" }
          }
        },
        "LEIAuthority": {
          "@id": "https://w3id.org/traceability#LEIAuthority",
          "@context": {
            "validationAuthorityID": { "@id": "https://schema.org/identifier" },
            "otherValidationAuthorityID": { "@id": "https://schema.org/taxID" },
            "validationAuthorityEntityID": { "@id": "https://schema.org/leiCode" }
          }
        },
        "LEIEntity": {
          "@id": "https://w3id.org/traceability#LEIEntity",
          "@context": {
            "legalName": { "@id": "https://schema.org/legalName" },
            "legalAddress": { "@id": "https://www.gleif.org/ontology/Base/hasAddressLegal" },
            "headquartersAddress": {
              "@id": "https://www.gleif.org/ontology/Base/hasAddressHeadquarters"
            },
            "registrationAuthority": { "@id": "https://w3id.org/traceability#LEIAuthority" },
            "legalJurisdiction": { "@id": "https://schema.org/countryOfOrigin" },
            "entityCategory": { "@id": "https://schema.org/category" },
            "legalForm": { "@id": "https://schema.org/additionalType" },
            "associatedEntity": { "@id": "https://schema.org/Organization" },
            "status": { "@id": "https://schema.org/status" },
            "validUntil": { "@id": "https://schema.org/expires" },
            "expirationReason": { "@id": "https://schema.org/Answer" },
            "successorEntity": { "@id": "https://schema.org/Corporation" },
            "otherAddresses": { "@id": "https://schema.org/Place" }
          }
        },
        "LEIRegistration": {
          "@id": "https://w3id.org/traceability#LEIRegistration",
          "@context": {
            "initialRegistrationDate": { "@id": "https://schema.org/dateIssued" },
            "lastUpdateDate": { "@id": "https://schema.org/dateModified" },
            "status": { "@id": "https://schema.org/status" },
            "nextRenewalDate": { "@id": "https://schema.org/validThrough" },
            "managingLou": {
              "@id": "https://www.gleif.org/en/about-lei/iso-17442-the-lei-code-structure#"
            },
            "validationSources": { "@id": "https://schema.org/eventStatus" },
            "validationAuthority": { "@id": "https://w3id.org/traceability#LEIAuthority" }
          }
        },
        "LaceyActProductDeclaration": {
          "@id": "https://w3id.org/traceability#LaceyActProductDeclaration",
          "@context": {
            "htsNumber": { "@id": "https://vocabulary.uncefact.org/applicableRegulatoryProcedure" },
            "enteredValue": { "@id": "https://vocabulary.uncefact.org/customsValueSpecifiedAmount" },
            "articleOrComponent": { "@id": "https://vocabulary.uncefact.org/procedureCode" },
            "plantScientificNames": { "@id": "https://w3id.org/traceability#Taxonomy" },
            "countryOfHarvest": { "@id": "https://vocabulary.uncefact.org/originCountry" },
            "quantityOfPlantMaterial": {
              "@id": "https://vocabulary.uncefact.org/totalPackageSpecifiedQuantity"
            },
            "percentRecycled": { "@id": "https://qudt.org/vocab/unit/PERCENT" }
          }
        },
        "LinkRole": {
          "@id": "https://schema.org/LinkRole",
          "@context": {
            "target": { "@id": "https://schema.org/target" },
            "linkRelationship": { "@id": "https://schema.org/linkRelationship" }
          }
        },
        "MapResource": {
          "@id": "https://w3id.org/traceability#MapResource",
          "@context": {
            "resourceType": { "@id": "https://schema.org/additionalType" },
            "external": { "@id": "https://w3id.org/traceability#ExternalResource" },
            "geoJson": { "@id": "https://schema.org/geo" }
          }
        },
        "MasterBillOfLading": {
          "@id": "https://w3id.org/traceability#MasterBillOfLading",
          "@context": {
            "billOfLadingNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BM" },
            "bookingNumber": { "@id": "https://vocabulary.uncefact.org/carrierAssignedId" },
            "shippersReferences": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#FF" },
            "carrier": { "@id": "https://vocabulary.uncefact.org/carrierParty" },
            "shipper": { "@id": "https://vocabulary.uncefact.org/consignorParty" },
            "consignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "forwardingAgent": { "@id": "https://vocabulary.uncefact.org/freightForwarderParty" },
            "notifyParty": { "@id": "https://vocabulary.uncefact.org/notifiedParty" },
            "preCarriageTransportMovement": {
              "@id": "https://vocabulary.uncefact.org/preCarriageTransportMovement"
            },
            "mainCarriageTransportMovement": {
              "@id": "https://vocabulary.uncefact.org/mainCarriageTransportMovement"
            },
            "onCarriageTransportMovement": {
              "@id": "https://vocabulary.uncefact.org/onCarriageTransportMovement"
            },
            "placeOfReceipt": { "@id": "https://schema.org/Place" },
            "portOfLoading": { "@id": "https://vocabulary.uncefact.org/transshipmentLocation" },
            "placeOfDelivery": { "@id": "https://schema.org/Place" },
            "portOfDischarge": { "@id": "https://vocabulary.uncefact.org/unloadingLocation" },
            "totalNumberOfPackages": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "transportEquipmentQuantity": {
              "@id": "https://vocabulary.uncefact.org/transportEquipmentQuantity"
            },
            "includedConsignmentItems": {
              "@id": "https://vocabulary.uncefact.org/includedConsignmentItem"
            },
            "utilizedTransportEquipment": {
              "@id": "https://vocabulary.uncefact.org/utilizedTransportEquipment"
            },
            "freightAndCharges": { "@id": "https://vocabulary.uncefact.org/applicableServiceCharge" },
            "declaredValue": {
              "@id": "https://vocabulary.uncefact.org/declaredValueForCarriageAmount"
            },
            "shippedOnBoardDate": { "@id": "https://schema.org/endDate" },
            "termsAndConditions": {
              "@id": "https://vocabulary.uncefact.org/termsAndConditionsDescription"
            }
          }
        },
        "MeasuredProperty": { "@id": "https://w3id.org/traceability#MeasuredProperty", "@context": {} },
        "MeasuredValue": {
          "@id": "https://schema.org/QuantitativeValue",
          "@context": {
            "value": { "@id": "https://schema.org/value" },
            "unitCode": { "@id": "https://schema.org/unitCode" }
          }
        },
        "MechanicalProperty": {
          "@id": "https://w3id.org/traceability#MechanicalProperty",
          "@context": {
            "identifier": { "@id": "https://schema.org/identifier" },
            "name": { "@id": "https://schema.org/name" },
            "description": { "@id": "https://schema.org/description" }
          }
        },
        "MonetaryAmount": {
          "@id": "https://schema.org/MonetaryAmount",
          "@context": {
            "value": { "@id": "https://schema.org/value" },
            "currency": { "@id": "https://schema.org/currency" }
          }
        },
        "MonthlyAdvanceManifest": {
          "@id": "https://w3id.org/traceability#MonthlyAdvanceManifest",
          "@context": { "date": { "@id": "https://schema.org/endDate" } }
        },
        "MonthlyDeliveryStatement": {
          "@id": "https://w3id.org/traceability#MonthlyDeliveryStatement",
          "@context": { "itemsDelivered": { "@id": "https://w3id.org/traceability#DeliveryStatement" } }
        },
        "MultiModalBillOfLading": {
          "@id": "https://w3id.org/traceability#MultiModalBillOfLading",
          "@context": {
            "billOfLadingNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BM" },
            "bookingNumber": { "@id": "https://vocabulary.uncefact.org/carrierAssignedId" },
            "shippersReferences": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#SI" },
            "freightForwardersReferences": {
              "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#FF"
            },
            "shipper": { "@id": "https://vocabulary.uncefact.org/consignorParty" },
            "consignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "forwardingAgent": { "@id": "https://vocabulary.uncefact.org/freightForwarderParty" },
            "notifyParty": { "@id": "https://vocabulary.uncefact.org/notifiedParty" },
            "carrier": { "@id": "https://vocabulary.uncefact.org/carrierParty" },
            "preCarriageTransportMovement": {
              "@id": "https://vocabulary.uncefact.org/preCarriageTransportMovement"
            },
            "mainCarriageTransportMovement": {
              "@id": "https://vocabulary.uncefact.org/mainCarriageTransportMovement"
            },
            "onCarriageTransportMovement": {
              "@id": "https://vocabulary.uncefact.org/onCarriageTransportMovement"
            },
            "placeOfReceipt": { "@id": "https://schema.org/Place" },
            "portOfLoading": { "@id": "https://vocabulary.uncefact.org/loadingLocation" },
            "transshipmentLocation": { "@id": "https://vocabulary.uncefact.org/transshipmentLocation" },
            "placeOfDelivery": { "@id": "https://schema.org/Place" },
            "portOfDischarge": { "@id": "https://vocabulary.uncefact.org/unloadingLocation" },
            "totalNumberOfPackages": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "transportEquipmentQuantity": {
              "@id": "https://vocabulary.uncefact.org/transportEquipmentQuantity"
            },
            "particulars": { "@id": "https://vocabulary.uncefact.org/includedConsignmentItem" },
            "utilizedTransportEquipment": {
              "@id": "https://vocabulary.uncefact.org/utilizedTransportEquipment"
            },
            "freightAndCharges": { "@id": "https://vocabulary.uncefact.org/applicableServiceCharge" },
            "declaredValue": {
              "@id": "https://vocabulary.uncefact.org/declaredValueForCarriageAmount"
            },
            "shippedOnBoardDate": { "@id": "https://schema.org/endDate" },
            "termsAndConditions": {
              "@id": "https://vocabulary.uncefact.org/termsAndConditionsDescription"
            }
          }
        },
        "NAISMADateTime": {
          "@id": "https://w3id.org/traceability#NAISMADateTime",
          "@context": {
            "collectionDate": { "@id": "http://rs.tdwg.org/dwc/terms/endDate" },
            "dateAccuracyDays": { "@id": "http://rs.tdwg.org/dwc/iri/measurementMethod" }
          }
        },
        "NAISMAInfestation": {
          "@id": "https://w3id.org/traceability#NAISMAInfestation",
          "@context": {
            "infestedArea": { "@id": "http://rs.tdwg.org/dwc/terms/measurementValue" },
            "areaSurveyed": { "@id": "http://rs.tdwg.org/dwc/terms/measurementValue" },
            "incidence": { "@id": "http://rs.tdwg.org/dwc/terms/measurementValue" },
            "severity": { "@id": "http://rs.tdwg.org/dwc/terms/measurementValue" },
            "severityUnits": { "@id": "https://schema.org/unitText" },
            "organismQuantity": { "@id": "http://rs.tdwg.org/dwc/terms/organismQuantity" },
            "organismQuantityUnits": { "@id": "https://schema.org/unitText" }
          }
        },
        "NAISMAInformationSource": {
          "@id": "https://w3id.org/traceability#NAISMAInformationSource",
          "@context": {
            "reference": { "@id": "http://rs.tdwg.org/dwc/terms/associatedReferences" },
            "examiner": { "@id": "http://rs.tdwg.org/dwc/terms/recordedBy" },
            "dataSource": { "@id": "https://w3id.org/traceability#Entity" }
          }
        },
        "NAISMALocation": {
          "@id": "https://w3id.org/traceability#NAISMALocation",
          "@context": {
            "location": { "@id": "https://w3id.org/traceability#Place" },
            "description": { "@id": "https://schema.org/description" },
            "datum": { "@id": "http://rs.tdwg.org/dwc/terms/geodeticDatum" },
            "wellKnownText": { "@id": "http://rs.tdwg.org/dwc/terms/footprintWKT" },
            "centroidType": { "@id": "https://schema.org/polygon" },
            "dataType": { "@id": "https://schema.org/additionalType" },
            "coordinateUncertainty": {
              "@id": "http://rs.tdwg.org/dwc/terms/coordinateUncertaintyInMeters"
            },
            "sourceOfLocation": { "@id": "http://rs.tdwg.org/dwc/terms/georeferenceProtocol" },
            "ecosystem": { "@id": "http://rs.tdwg.org/dwc/terms/locationRemarks" }
          }
        },
        "NAISMARecordLevelIdentifiers": {
          "@id": "https://w3id.org/traceability#NAISMARecordLevelIdentifiers",
          "@context": {
            "uuid": { "@id": "http://rs.tdwg.org/dwc/terms/resourceID" },
            "pid": { "@id": "https://w3id.org/traceabilit#pid" },
            "catalogNumber": { "@id": "http://rs.tdwg.org/dwc/terms/catalogNumber" }
          }
        },
        "NAISMARecordStatus": {
          "@id": "https://w3id.org/traceability#NAISMARecordStatus",
          "@context": {
            "occurrenceStatus": { "@id": "https://schema.org/status" },
            "populationStatus": { "@id": "http://rs.tdwg.org/dwc/terms/degreeOfEstablishment" },
            "managementStatus": { "@id": "https://schema.org/status" },
            "recordBasis": { "@id": "http://rs.tdwg.org/dwc/terms/samplingProtocol" },
            "recordType": { "@id": "https://schema.org/description" },
            "method": { "@id": "http://rs.tdwg.org/dwc/terms/measurementMethod" },
            "verificationMethod": { "@id": "http://rs.tdwg.org/dwc/terms/identificationRemarks" }
          }
        },
        "NAISMASubject": {
          "@id": "https://w3id.org/traceability#NAISMASubject",
          "@context": {
            "lifeStage": { "@id": "http://rs.tdwg.org/dwc/terms/lifeStage" },
            "sex": { "@id": "http://rs.tdwg.org/dwc/terms/sex" },
            "hostSpecies": { "@id": "https://w3id.org/traceability#Taxonomy" },
            "comments": { "@id": "http://rs.tdwg.org/dwc/terms/occurrenceRemarks" }
          }
        },
        "NAISMATaxonomy": {
          "@id": "https://w3id.org/traceability#NAISMATaxonomy",
          "@context": {
            "speciesName": { "@id": "https://w3id.org/traceability#Taxonomy" },
            "commonName": { "@id": "http://rs.tdwg.org/dwc/terms/vernacularName" },
            "taxonomicSerialNumber": { "@id": "http://rs.tdwg.org/dwc/terms/taxonID" }
          }
        },
        "Observation": {
          "@id": "https://schema.org/Observation",
          "@context": {
            "property": { "@id": "https://schema.org/measuredProperty" },
            "measurement": { "@id": "https://w3id.org/traceability#MeasuredValue" },
            "date": { "@id": "https://schema.org/observationDate" }
          }
        },
        "OilAndGasDeliveryTicket": {
          "@id": "https://w3id.org/traceability#OilAndGasDeliveryTicket",
          "@context": {
            "createdDate": { "@id": "https://schema.org/dateIssued" },
            "openDate": { "@id": "https://schema.org/startDate" },
            "closeDate": { "@id": "https://schema.org/endDate" },
            "transporter": { "@id": "https://schema.org/agent" },
            "consignor": { "@id": "https://vocabulary.uncefact.org/consignorParty" },
            "consignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "ticketControlNumber": { "@id": "https://schema.org/ticketNumber" },
            "batchNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BT" },
            "place": { "@id": "https://schema.org/toLocation" },
            "product": { "@id": "https://www.gs1.org/voc/Product" },
            "observation": { "@id": "https://w3id.org/traceability#observation" }
          }
        },
        "OilAndGasProduct": {
          "@id": "https://w3id.org/traceability#OilAndGasProduct",
          "@context": {
            "product": { "@id": "https://www.gs1.org/voc/Product" },
            "facility": { "@id": "https://www.gs1.org/voc/Place" },
            "UWI": { "@id": "https://schema.org/identifier" },
            "productionDate": { "@id": "https://schema.org/endDate" },
            "observation": { "@id": "https://w3id.org/traceability#observation" }
          }
        },
        "Order": {
          "@id": "https://schema.org/Order",
          "@context": {
            "orderNumber": { "@id": "https://schema.org/orderNumber" },
            "orderedItems": { "@id": "https://schema.org/orderedItem" }
          }
        },
        "OrderItem": {
          "@id": "https://schema.org/OrderItem",
          "@context": {
            "marketplace": { "@id": "https://vocabulary.uncefact.org/Marketplace" },
            "fulfillmentCenter": {
              "@id": "https://vocabulary.uncefact.org/logisticsServiceProviderParty"
            },
            "orderedItem": { "@id": "https://schema.org/orderedItem" },
            "orderedQuantity": { "@id": "https://schema.org/orderQuantity" }
          }
        },
        "OrganicCertificate": {
          "@id": "https://w3id.org/traceability#OrganicCertificate",
          "@context": {
            "countryOfIssuance": { "@id": "https://www.gs1.org/voc/countryCode" },
            "certifiedOperation": { "@id": "https://www.gs1.org/voc/certificationSubject" },
            "certifyingAgent": { "@id": "https://www.gs1.org/voc/certificationAgency" },
            "effectiveDate": { "@id": "https://www.gs1.org/voc/certificationStartDate" },
            "issueDate": { "@id": "https://www.gs1.org/voc/initialCertificationDate" },
            "anniversaryDate": { "@id": "https://www.gs1.org/voc/certificationEndDate" },
            "operationCategory": { "@id": "https://www.gs1.org/voc/certificationStatement" },
            "organicProducts": { "@id": "https://www.gs1.org/voc/certificationStatement" }
          }
        },
        "OrganicInspection": {
          "@id": "https://w3id.org/traceability#OrganicInspection",
          "@context": {
            "commonInfo": { "@id": "https://w3id.org/traceability#AgricultureInspectionCommonInfo" },
            "applicantCertificationNumber": { "@id": "https://vocabulary.uncefact.org/identification" },
            "authorizedOperationContacts": {
              "@id": "https://vocabulary.uncefact.org/specifiedContactPerson"
            },
            "peoplePresent": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "newApplicant": { "@id": "https://vocabulary.uncefact.org/information" },
            "continuingCertification": { "@id": "https://vocabulary.uncefact.org/information" },
            "newLocationActivity": { "@id": "https://vocabulary.uncefact.org/information" },
            "reinstatement": { "@id": "https://vocabulary.uncefact.org/information" },
            "announcedInspection": { "@id": "https://vocabulary.uncefact.org/information" },
            "estimatedHarvestDate": { "@id": "https://www.gs1.org/voc/harvestDate" },
            "pesticideResidueSampling": { "@id": "https://vocabulary.uncefact.org/information" },
            "samplingDetails": { "@id": "https://vocabulary.uncefact.org/content" },
            "introductionOperationDescription": { "@id": "https://schema.org/description" },
            "resolutionIssuesActionItems": { "@id": "https://schema.org/description" },
            "issuesRequests": { "@id": "https://vocabulary.uncefact.org/additionalDescription" },
            "attachments": { "@id": "https://vocabulary.uncefact.org/additionalDocument" },
            "OSPSectionReviews": { "@id": "https://w3id.org/traceability#OrganicOSPSectionReview" }
          }
        },
        "OrganicOSPSectionReview": {
          "@id": "https://w3id.org/traceability#OrganicOSPSectionReview",
          "@context": {
            "OSPSectionCode": { "@id": "https://vocabulary.uncefact.org/standard" },
            "resultCode": { "@id": "https://vocabulary.uncefact.org/assertionCode" },
            "verificationExplanations": { "@id": "https://vocabulary.uncefact.org/remarks" },
            "attachments": { "@id": "https://vocabulary.uncefact.org/additionalDocument" }
          }
        },
        "OrganicProductCertificate": {
          "@id": "https://w3id.org/traceability#OrganicProductCertificate",
          "@context": {
            "agricultureProduct": { "@id": "https://www.gs1.org/voc/certificationSubject" },
            "organicCertificate": { "@id": "https://www.gs1.org/voc/certification" },
            "isCertified": { "@id": "https://www.gs1.org/voc/certificationStatus" }
          }
        },
        "OrganicReview": {
          "@id": "https://w3id.org/traceability#OrganicReview",
          "@context": {
            "inspectionReport": { "@id": "https://w3id.org/traceability#OrganicInspection" },
            "reviewer": { "@id": "https://vocabulary.uncefact.org/specifiedContactPerson" },
            "decisionMaker": { "@id": "https://vocabulary.uncefact.org/specifiedContactPerson" },
            "certificationDecision": { "@id": "https://www.gs1.org/voc/certificationStatus" },
            "additionalInformation": { "@id": "https://vocabulary.uncefact.org/content" }
          }
        },
        "Organization": {
          "@id": "https://schema.org/Organization",
          "@context": {
            "name": { "@id": "https://schema.org/name" },
            "legalName": { "@id": "https://schema.org/legalName" },
            "leiCode": { "@id": "https://schema.org/leiCode" },
            "url": { "@id": "https://schema.org/url" },
            "description": { "@id": "https://schema.org/description" },
            "globalLocationNumber": { "@id": "https://schema.org/globalLocationNumber" },
            "location": { "@id": "https://schema.org/location" },
            "email": { "@id": "https://schema.org/email" },
            "phoneNumber": { "@id": "https://schema.org/telephone" },
            "logo": { "@id": "https://schema.org/logo" },
            "faxNumber": { "@id": "https://schema.org/faxNumber" },
            "contactPoint": { "@id": "https://schema.org/ContactPoint" },
            "taxId": { "@id": "https://schema.org/taxID" },
            "iataCarrierCode": { "@id": "https://onerecord.iata.org/cargo/Company#airlineCode" },
            "scac": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#AAZ" }
          }
        },
        "PGAShipmentStatus": {
          "@id": "https://w3id.org/traceability#PGAShipmentStatus",
          "@context": {
            "recordNo": { "@id": "https://w3id.org/traceability#recordNo" },
            "entryNo": { "@id": "https://w3id.org/traceability#entryNo" },
            "entryLineSequence": { "@id": "https://w3id.org/traceability#entryLineSequence" },
            "statusCode": { "@id": "https://w3id.org/traceability#statusCode" },
            "statusCodeDescription": { "@id": "https://w3id.org/traceability#statusCodeDescription" },
            "validCodeReason": { "@id": "https://w3id.org/traceability#validCodeReason" },
            "validCodeReasonDescription": {
              "@id": "https://w3id.org/traceability#validCodeReasonDescription"
            },
            "subReasonCode": { "@id": "https://w3id.org/traceability#subReasonCode" },
            "subReasonCodeDescription": {
              "@id": "https://w3id.org/traceability#subReasonCodeDescription"
            }
          }
        },
        "PGAShipmentStatusList": {
          "@id": "https://w3id.org/traceability#PGAShipmentStatusList",
          "@context": { "pgaShipmentStatusItems": { "@id": "https://schema.org/ItemList" } }
        },
        "Package": {
          "@id": "https://vocabulary.uncefact.org/Package",
          "@context": {
            "physicalShippingMarks": { "@id": "https://vocabulary.uncefact.org/physicalShippingMarks" },
            "packagingType": { "@id": "https://www.gs1.org/voc/packagingMaterial" },
            "perPackageUnitQuantity": {
              "@id": "https://vocabulary.uncefact.org/perPackageUnitQuantity"
            },
            "includedTradeLineItems": {
              "@id": "https://vocabulary.uncefact.org/specifiedTradeLineItem"
            },
            "netWeight": { "@id": "https://vocabulary.uncefact.org/netWeightMeasure" },
            "grossWeight": { "@id": "https://vocabulary.uncefact.org/grossWeightMeasure" },
            "height": { "@id": "https://schema.org/height" },
            "width": { "@id": "https://schema.org/width" },
            "depth": { "@id": "https://schema.org/depth" },
            "grossVolume": { "@id": "https://vocabulary.uncefact.org/grossVolumeMeasure" }
          }
        },
        "PackingList": {
          "@id": "https://w3id.org/traceability#PackingList",
          "@context": {
            "seller": { "@id": "https://vocabulary.uncefact.org/sellerParty" },
            "buyer": { "@id": "https://vocabulary.uncefact.org/buyerParty" },
            "consignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "shipFromParty": { "@id": "https://vocabulary.uncefact.org/shipFromParty" },
            "shipToParty": { "@id": "https://vocabulary.uncefact.org/shipToParty" },
            "orderNumber": { "@id": "https://schema.org/orderNumber" },
            "invoiceId": { "@id": "https://schema.org/identifier" },
            "billOfLadingNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BM" },
            "trackingNumber": { "@id": "https://schema.org/trackingNumber" },
            "deliveryStatus": { "@id": "https://schema.org/deliveryStatus" },
            "estimatedTimeOfArrival": { "@id": "https://schema.org/arrivalTime" },
            "hasDeliveryMethod": { "@id": "https://schema.org/hasDeliveryMethod" },
            "handlingInstructions": { "@id": "https://vocabulary.uncefact.org/handlingInstructions" },
            "items": { "@id": "https://vocabulary.uncefact.org/includedConsignmentItem" },
            "totalNetWeight": { "@id": "https://vocabulary.uncefact.org/netWeightMeasure" },
            "totalGrossWeight": { "@id": "https://vocabulary.uncefact.org/grossWeightMeasure" },
            "totalGrossVolume": { "@id": "https://vocabulary.uncefact.org/grossVolumeMeasure" },
            "totalNumberOfPackages": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "totalItemQuantity": { "@id": "https://vocabulary.uncefact.org/tradeLineItemQuantity" }
          }
        },
        "ParcelDelivery": {
          "@id": "https://schema.org/ParcelDelivery",
          "@context": {
            "deliveryAddress": { "@id": "https://schema.org/deliveryAddress" },
            "originAddress": { "@id": "https://schema.org/originAddress" },
            "deliveryMethod": { "@id": "https://schema.org/DeliveryMethod" },
            "trackingNumber": { "@id": "https://schema.org/trackingNumber" },
            "expectedArrival": { "@id": "https://schema.org/expectedArrivalFrom" },
            "specialInstructions": { "@id": "https://schema.org/comment" },
            "consignee": { "@id": "https://schema.org/Organization" },
            "item": { "@id": "https://schema.org/itemShipped" },
            "partOfOrder": { "@id": "https://schema.org/partOfOrder" }
          }
        },
        "PartOfOrder": {
          "@id": "https://schema.org/OrderItem",
          "@context": {
            "manufacturer": { "@id": "https://schema.org/Organization" },
            "orderNumber": { "@id": "https://schema.org/orderNumber" },
            "transportPackages": { "@id": "https://vocabulary.uncefact.org/Package" },
            "netWeight": { "@id": "https://vocabulary.uncefact.org/netWeightMeasure" },
            "grossWeight": { "@id": "https://vocabulary.uncefact.org/grossWeightMeasure" },
            "grossVolume": { "@id": "https://vocabulary.uncefact.org/grossVolumeMeasure" },
            "packageQuantity": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "itemQuantity": { "@id": "https://vocabulary.uncefact.org/tradeLineItemQuantity" }
          }
        },
        "Person": {
          "@id": "https://schema.org/Person",
          "@context": {
            "firstName": { "@id": "https://schema.org/givenName" },
            "lastName": { "@id": "https://schema.org/familyName" },
            "email": { "@id": "https://schema.org/email" },
            "phoneNumber": { "@id": "https://schema.org/telephone" },
            "worksFor": { "@id": "https://schema.org/worksFor" },
            "jobTitle": { "@id": "https://schema.org/jobTitle" },
            "taxId": { "@id": "https://schema.org/taxID" }
          }
        },
        "PestDetermination": {
          "@id": "https://w3id.org/traceability#PestDetermination",
          "@context": {
            "final": { "@id": "https://dwc.tdwg.org/list/#dwc_identificationVerificationStatus" },
            "determination": { "@id": "https://w3id.org/traceability#Taxonomy" },
            "notes": { "@id": "https://dwc.tdwg.org/list/#dwc_identificationRemarks" },
            "method": { "@id": "https://dwc.tdwg.org/list/#dwc_measurementMethod" },
            "reportable": { "@id": "https://dwc.tdwg.org/list/#dwc_occurrenceStatus" },
            "determinedBy": { "@id": "https://dwc.tdwg.org/list/#dwc_identifiedBy" },
            "date": { "@id": "https://dwc.tdwg.org/list/#dwc_dateIdentified" }
          }
        },
        "PestSample": {
          "@id": "https://w3id.org/traceability#PestSample",
          "@context": {
            "hostName": { "@id": "https://w3id.org/traceability#Taxonomy" },
            "hostQuantity": { "@id": "http://rs.tdwg.org/dwc/terms/organismQuantity" },
            "affected": { "@id": "https://dwc.tdwg.org/list/#dwc_measurementValue" },
            "plantDistribution": { "@id": "http://rs.tdwg.org/dwc/terms/degreeOfEstablishment" },
            "plantPartsAffected": { "@id": "http://rs.tdwg.org/dwc/terms/occurrenceRemarks" },
            "pestDistribution": { "@id": "http://rs.tdwg.org/dwc/terms/degreeOfEstablishment" },
            "pestProximity": { "@id": "http://rs.tdwg.org/dwc/terms/occurrenceRemarks" },
            "pestType": { "@id": "http://rs.tdwg.org/dwc/terms/occurrenceRemarks" },
            "aliveLarvae": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "alivePupae": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "aliveAdults": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "aliveEggs": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "aliveNymphs": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "aliveJuveniles": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "aliveCysts": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "deadLarvae": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "deadPupae": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "deadAdults": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "deadEggs": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "deadNymphs": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "deadJuveniles": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "deadCysts": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "castSkins": { "@id": "http://rs.tdwg.org/dwc/terms/individualCount" },
            "samplingMethod": { "@id": "http://rs.tdwg.org/dwc/terms/samplingProtocol" },
            "trapLureType": { "@id": "http://rs.tdwg.org/dwc/terms/samplingProtocol" },
            "trapNumber": { "@id": "http://rs.tdwg.org/dwc/terms/samplingProtocol" }
          }
        },
        "Phytosanitary": {
          "@id": "https://w3id.org/traceability#Phytosanitary",
          "@context": {
            "certificateNumber": { "@id": "https://schema.org/identifier" },
            "plantOrg": { "@id": "https://www.gs1.org/voc/Organization" },
            "distinguishingMarks": { "@id": "https://www.gs1.org/voc/variantDescription" },
            "portOfEntry": { "@id": "https://w3id.org/traceability#portOfEntry" },
            "additionalDeclaration": { "@id": "https://schema.org/Comment" },
            "disinfectionDate": { "@id": "https://schema.org/validFrom" },
            "disinfectionTreatment": { "@id": "https://w3id.org/traceability#disinfectionTreatment" },
            "disinfectionChemical": { "@id": "https://schema.org/activeIngredient" },
            "disinfectionDuration": { "@id": "https://schema.org/duration" },
            "disinfectionTemperature": { "@id": "https://schema.org/MeasuredValue" },
            "disinfectionConcentration": {
              "@id": "https://w3id.org/traceability#disinfectionConcentration"
            },
            "signatureDate": { "@id": "https://vocabulary.uncefact.org/signedDateTime" },
            "facility": { "@id": "https://www.gs1.org/voc/Place" },
            "inspector": { "@id": "https://w3id.org/traceability#Inspector" },
            "shipment": { "@id": "https://schema.org/AgricultureParcelDelivery" },
            "agriculturePackage": { "@id": "https://w3id.org/traceability#AgriculturePackage" },
            "applicant": { "@id": "https://w3c-ccg.github.io/traceability-vocab/#dfn-entities" },
            "inspectionDate": { "@id": "https://vocabulary.uncefact.org/inspectionDateTime" },
            "inspectionType": { "@id": "https://vocabulary.uncefact.org/inspectionStandard" },
            "notes": { "@id": "https://schema.org/Comment" },
            "observation": { "@id": "https://schema.org/ItemList" }
          }
        },
        "Place": {
          "@id": "https://schema.org/Place",
          "@context": {
            "globalLocationNumber": { "@id": "https://schema.org/globalLocationNumber" },
            "geo": { "@id": "https://schema.org/GeoCoordinates" },
            "address": { "@id": "https://schema.org/PostalAddress" },
            "unLocode": { "@id": "https://vocabulary.uncefact.org/Location" },
            "iataAirportCode": { "@id": "https://onerecord.iata.org/cargo/Location#code" },
            "locationName": { "@id": "https://schema.org/name" },
            "usPortCode": { "@id": "https://w3id.org/traceability#usPortCode" },
            "firmsCode": { "@id": "https://w3id.org/traceability#firmsCode" }
          }
        },
        "PlantSystemsInspection": {
          "@id": "https://w3id.org/traceability#PlantSystemsInspection",
          "@context": {
            "commonInfo": { "@id": "https://w3id.org/traceability#AgricultureInspectionCommonInfo" },
            "productsPacked": { "@id": "https://vocabulary.uncefact.org/specifiedProduct" },
            "summaryOfDeficiencies": { "@id": "https://schema.org/description" },
            "observationsImprovements": { "@id": "https://schema.org/description" },
            "questions": { "@id": "https://w3id.org/traceability#PlantSystemsQuestion" },
            "additionalViolations": { "@id": "https://schema.org/description" }
          }
        },
        "PlantSystemsQuestion": {
          "@id": "https://w3id.org/traceability#PlantSystemsQuestion",
          "@context": {
            "code": { "@id": "https://schema.org/identifier" },
            "pointsWorth": { "@id": "https://schema.org/ratingValue" },
            "pointsDeducted": { "@id": "https://schema.org/ratingValue" }
          }
        },
        "PostalAddress": {
          "@id": "https://schema.org/PostalAddress",
          "@context": {
            "name": { "@id": "https://schema.org/name" },
            "streetAddress": { "@id": "https://schema.org/streetAddress" },
            "addressLocality": { "@id": "https://schema.org/addressLocality" },
            "addressRegion": { "@id": "https://schema.org/addressRegion" },
            "addressCountry": { "@id": "https://schema.org/addressCountry" },
            "crossStreet": { "@id": "https://gs1.org/voc/crossStreet" },
            "countyCode": { "@id": "https://gs1.org/voc/countyCode" },
            "postalCode": { "@id": "https://schema.org/postalCode" },
            "postOfficeBoxNumber": { "@id": "https://schema.org/postOfficeBoxNumber" },
            "plantOrSiteName": { "@id": "https://vocabulary.uncefact.org/buildingName" }
          }
        },
        "PostmanCollection": {
          "@id": "https://w3id.org/traceability#PostmanCollection",
          "@context": {}
        },
        "PriceSpecification": {
          "@id": "https://schema.org/PriceSpecification",
          "@context": {
            "price": { "@id": "https://schema.org/price" },
            "priceCurrency": { "@id": "https://schema.org/priceCurrency" }
          }
        },
        "Product": {
          "@id": "https://schema.org/Product",
          "@context": {
            "gtin": { "@id": "https://schema.org/gtin" },
            "manufacturer": { "@id": "https://schema.org/manufacturer" },
            "countryOfOrigin": { "@id": "https://vocabulary.uncefact.org/originCountry" },
            "name": { "@id": "https://schema.org/name" },
            "description": { "@id": "https://schema.org/description" },
            "category": { "@id": "https://schema.org/category" },
            "weight": { "@id": "https://schema.org/weight" },
            "depth": { "@id": "https://schema.org/depth" },
            "width": { "@id": "https://schema.org/width" },
            "height": { "@id": "https://schema.org/height" },
            "productPrice": { "@id": "https://schema.org/priceSpecification" },
            "sku": { "@id": "https://schema.org/sku" },
            "batchNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BT" },
            "commodity": { "@id": "https://w3id.org/traceability#Commodity" },
            "seller": { "@id": "https://vocabulary.uncefact.org/sellerParty" },
            "images": { "@id": "https://schema.org/image" },
            "imageUrl": { "@id": "https://schema.org/url" },
            "imageHash": { "@id": "https://schema.org/sha256" },
            "htsCode": {
              "@id": "https://service.unece.org/trade/uncefact/vocabulary/uncefact/#applicableTax"
            }
          }
        },
        "Purchase": {
          "@id": "https://w3id.org/traceability#Purchase",
          "@context": {
            "customer": { "@id": "https://w3id.org/traceability#Entity" },
            "invoice": { "@id": "https://w3id.org/traceability#Invoice" },
            "invoiceNo": { "@id": "https://schema.org/identifier" },
            "internalCertificateNo": { "@id": "https://schema.org/identifier" },
            "purchaseOrderNo": { "@id": "https://schema.org/identifier" }
          }
        },
        "PurchaseOrder": {
          "@id": "https://vocabulary.uncefact.org/DocumentCodeList#105",
          "@context": {
            "purchaseOrderNo": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#AUJ" },
            "orderDate": { "@id": "https://vocabulary.uncefact.org/buyerOrderDateTime" },
            "buyer": { "@id": "https://vocabulary.uncefact.org/buyerParty" },
            "seller": { "@id": "https://vocabulary.uncefact.org/sellerParty" },
            "shipToParty": { "@id": "https://vocabulary.uncefact.org/shipToParty" },
            "itemsOrdered": { "@id": "https://vocabulary.uncefact.org/SupplyChainTradeLineItem" },
            "comments": { "@id": "https://schema.org/Comment" },
            "totalWeight": { "@id": "https://schema.org/weight" },
            "termsOfDelivery": { "@id": "https://vocabulary.uncefact.org/specifiedDeliveryTerms" },
            "termsOfPayment": { "@id": "https://vocabulary.uncefact.org/specifiedPaymentTerms" },
            "totalPaymentDue": { "@id": "https://schema.org/totalPaymentDue" },
            "discounts": { "@id": "https://vocabulary.uncefact.org/deductionAmount" },
            "tax": { "@id": "https://vocabulary.uncefact.org/taxTotalAmount" },
            "freightCost": { "@id": "https://schema.org/DeliveryChargeSpecification" },
            "insuranceCost": { "@id": "https://vocabulary.uncefact.org/insuranceChargeTotalAmount" },
            "totalOrderAmount": { "@id": "https://vocabulary.uncefact.org/grandTotalAmount" }
          }
        },
        "Qualification": {
          "@id": "https://schema.org/qualifications",
          "@context": {
            "qualificationCategory": { "@id": "https://schema.org/credentialCategory" },
            "qualificationValue": { "@id": "https://schema.org/hasCredential" }
          }
        },
        "QuantitativeValue": {
          "@id": "https://schema.org/QuantitativeValue",
          "@context": {
            "unitCode": { "@id": "https://schema.org/unitCode" },
            "value": { "@id": "https://schema.org/value" }
          }
        },
        "RawMaterial": {
          "@id": "https://w3id.org/traceability#RawMaterial",
          "@context": {
            "name": { "@id": "https://schema.org/name" },
            "inchiKey": { "@id": "https://w3id.org/traceability#inchiKey" }
          }
        },
        "RevocationList2020Status": {
          "@id": "https://w3id.org/traceability#RevocationList2020Status",
          "@context": {
            "revocationListIndex": { "@id": "https://schema.org/itemListElement" },
            "revocationListCredential": { "@id": "https://schema.org/LinkRole" }
          }
        },
        "RoutingInfo": {
          "@id": "https://w3id.org/traceability#RoutingInfo",
          "@context": {
            "code": { "@id": "https://w3id.org/traceability#routingInfoCode" },
            "value": { "@id": "https://w3id.org/traceability#routingInfoValue" }
          }
        },
        "SIMASteelImportLicense": {
          "@id": "https://w3id.org/traceability#SIMASteelImportLicense",
          "@context": {
            "licenseNumber": { "@id": "https://schema.org/identifier" },
            "licensedCompany": { "@id": "https://vocabulary.uncefact.org/grantedParty" },
            "customsEntryNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#AQM" },
            "importer": { "@id": "https://vocabulary.uncefact.org/importerParty" },
            "exporter": { "@id": "https://vocabulary.uncefact.org/exporterParty" },
            "manufacturer": { "@id": "https://vocabulary.uncefact.org/manufacturerParty" },
            "countryOfOrigin": { "@id": "https://vocabulary.uncefact.org/originCountry" },
            "countryOfExportation": { "@id": "https://vocabulary.uncefact.org/exportCountry" },
            "expectedPortOfEntry": {
              "@id": "https://vocabulary.uncefact.org/LocationFunctionCodeList#24"
            },
            "expectedDateOfExport": {
              "@id": "https://vocabulary.uncefact.org/DateTimePeriodFunctionCodeList#129"
            },
            "expectedDateOfImport": {
              "@id": "https://vocabulary.uncefact.org/DateTimePeriodFunctionCodeList#151"
            },
            "productInformation": { "@id": "https://w3id.org/traceability#productInformation" }
          }
        },
        "SIMASteelImportProductSpecifier": {
          "@id": "https://w3id.org/traceability#SIMASteelImportProductSpecifier",
          "@context": {
            "productCategory": { "@id": "https://w3id.org/traceability#ProductCategory" },
            "countryOfMeltAndPour": { "@id": "https://w3id.org/traceability#countryOfMeltAndPour" },
            "customsValue": { "@id": "https://vocabulary.uncefact.org/declaredValueForCustomsAmount" }
          }
        },
        "OssfScorecard": { "@id": "https://w3id.org/traceability#OssfScorecard", "@context": {} },
        "SeaCargoManifest": {
          "@id": "https://w3id.org/traceability#SeaCargoManifest",
          "@context": {
            "vesselName": { "@id": "https://vocabulary.uncefact.org/transportMeans" },
            "vesselNumber": { "@id": "https://schema.org/identifier" },
            "voyageNumber": { "@id": "https://vocabulary.uncefact.org/TransportMovement" },
            "registrationCountry": { "@id": "https://vocabulary.uncefact.org/registrationCountry" },
            "plannedDepartureDateTime": {
              "@id": "https://vocabulary.uncefact.org/scheduledDepartureRelatedDateTime"
            },
            "plannedArrivalDateTime": {
              "@id": "https://vocabulary.uncefact.org/scheduledArrivalRelatedDateTime"
            },
            "portOfDeparture": { "@id": "https://schema.org/Place" },
            "portOfArrival": { "@id": "https://schema.org/Place" },
            "netTonnage": { "@id": "https://vocabulary.uncefact.org/netWeightMeasure" },
            "grossTonnage": { "@id": "https://vocabulary.uncefact.org/grossWeightMeasure" },
            "totalNumberOfTransportDocuments": {
              "@id": "https://vocabulary.uncefact.org/loadingListQuantity"
            },
            "transportEquipmentQuantity": {
              "@id": "https://vocabulary.uncefact.org/transportEquipmentQuantity"
            },
            "totalNumberOfPackages": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "transportDocumentInformation": {
              "@id": "https://vocabulary.uncefact.org/transportContractDocument"
            }
          }
        },
        "Seal": {
          "@id": "https://vocabulary.uncefact.org/Seal",
          "@context": {
            "sealNumber": { "@id": "https://vocabulary.uncefact.org/identifier" },
            "sealSource": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/sealSource"
            },
            "sealType": { "@id": "https://vocabulary.uncefact.org/logisticsSealTypeCode" }
          }
        },
        "ServiceCharge": {
          "@id": "https://vocabulary.uncefact.org/ServiceCharge",
          "@context": {
            "chargeCode": { "@id": "https://vocabulary.uncefact.org/chargeCategoryCode" },
            "paymentTerm": { "@id": "https://vocabulary.uncefact.org/PaymentTerms" },
            "chargeText": { "@id": "https://schema.org/description" },
            "rate": { "@id": "https://vocabulary.uncefact.org/unitPrice" },
            "calculationBasis": { "@id": "https://vocabulary.uncefact.org/calculationBasis" },
            "appliedAmount": { "@id": "https://vocabulary.uncefact.org/appliedAmount" }
          }
        },
        "ShippingDetails": {
          "@id": "https://w3id.org/traceability#ShippingDetails",
          "@context": {
            "containerNumber": { "@id": "https://w3id.org/traceability#containerNumber" },
            "masterBillOfLadingNumber": { "@id": "https://vocabulary.uncefact.org/uncl1153#MB" },
            "manufacturerAddress": { "@id": "https://w3id.org/traceability#manufacturerAddress" },
            "customerAddress": { "@id": "https://w3id.org/traceability#customerAddress" }
          }
        },
        "ShippingInstructions": {
          "@id": "https://w3id.org/traceability#ShippingInstructions",
          "@context": {
            "billOfLadingNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#BM" },
            "bookingNumber": { "@id": "https://vocabulary.uncefact.org/carrierAssignedId" },
            "shippersReferences": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#FF" },
            "shipper": { "@id": "https://vocabulary.uncefact.org/consignorParty" },
            "consignee": { "@id": "https://vocabulary.uncefact.org/consigneeParty" },
            "notifyParty": { "@id": "https://vocabulary.uncefact.org/notifiedParty" },
            "preCarriageTransportMovement": {
              "@id": "https://vocabulary.uncefact.org/preCarriageTransportMovement"
            },
            "mainCarriageTransportMovement": {
              "@id": "https://vocabulary.uncefact.org/mainCarriageTransportMovement"
            },
            "onCarriageTransportMovement": {
              "@id": "https://vocabulary.uncefact.org/onCarriageTransportMovement"
            },
            "placeOfReceipt": { "@id": "https://schema.org/Place" },
            "portOfLoading": { "@id": "https://vocabulary.uncefact.org/transshipmentLocation" },
            "placeOfDelivery": { "@id": "https://schema.org/Place" },
            "portOfDischarge": { "@id": "https://vocabulary.uncefact.org/unloadingLocation" },
            "totalNumberOfPackages": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "transportEquipmentQuantity": {
              "@id": "https://vocabulary.uncefact.org/transportEquipmentQuantity"
            },
            "includedConsignmentItems": {
              "@id": "https://vocabulary.uncefact.org/includedConsignmentItem"
            },
            "utilizedTransportEquipment": {
              "@id": "https://vocabulary.uncefact.org/utilizedTransportEquipment"
            },
            "declaredValue": { "@id": "https://vocabulary.uncefact.org/declaredValueForCarriageAmount" }
          }
        },
        "SoftwareBillOfMaterials": {
          "@id": "https://w3id.org/traceability#SoftwareBillOfMaterials",
          "@context": {}
        },
        "SteelProduct": {
          "@id": "https://w3id.org/traceability#SteelProduct",
          "@context": {
            "heatNumber": { "@id": "https://w3id.org/traceabilit#heatNumber" },
            "specification": { "@id": "https://w3id.org/traceabilit#specification" },
            "grade": { "@id": "https://schema.org/Rating" },
            "weight": { "@id": "https://schema.org/weight" },
            "weightUnit": { "@id": "http://qudt.org/schema/qudt/Unit" },
            "originalCountryOfMeltAndPour": { "@id": "https://schema.org/addressCountry" },
            "commodity": { "@id": "https://w3id.org/traceability#Commodity" },
            "inspection": { "@id": "https://w3id.org/traceability#Inspection" }
          }
        },
        "TSCACertification": {
          "@id": "https://w3id.org/traceability/TSCACertification",
          "@context": {
            "certificationType": { "@id": "https://schema.org/DefinedTerm" },
            "certifierDetails": { "@id": "https://w3id.org/traceability#certifierDetails" }
          }
        },
        "Taxonomy": {
          "@id": "https://w3id.org/traceability#Taxonomy",
          "@context": {
            "kingdom": { "@id": "http://rs.tdwg.org/dwc/terms/kingdom" },
            "phylum": { "@id": "http://rs.tdwg.org/dwc/terms/phylum" },
            "class": { "@id": "http://rs.tdwg.org/dwc/terms/class" },
            "order": { "@id": "http://rs.tdwg.org/dwc/terms/order" },
            "family": { "@id": "http://rs.tdwg.org/dwc/terms/family" },
            "genus": { "@id": "http://rs.tdwg.org/dwc/terms/genus" },
            "species": { "@id": "http://rs.tdwg.org/dwc/terms/specificEpithet" },
            "subspecies": { "@id": "http://rs.tdwg.org/dwc/terms/infraspecificEpithet" },
            "variety": { "@id": "http://rs.tdwg.org/dwc/terms/cultivarEpithet" }
          }
        },
        "TemperatureReading": {
          "@id": "https://w3id.org/traceability#TemperatureReading",
          "@context": {
            "bulbNumber": { "@id": "https://vocabulary.uncefact.org/identification" },
            "tests": { "@id": "https://vocabulary.uncefact.org/actualMeasure" }
          }
        },
        "Template": {
          "@id": "https://w3id.org/traceability#Template",
          "@context": { "image": { "@id": "https://schema.org/image" } }
        },
        "Thing": { "@id": "https://schema.org/Thing", "@context": {} },
        "TraceabilityAPI": { "@id": "https://w3id.org/traceability#TraceabilityAPI", "@context": {} },
        "TradeLineItem": {
          "@id": "https://vocabulary.uncefact.org/SupplyChainTradeLineItem",
          "@context": {
            "name": { "@id": "https://schema.org/name" },
            "purchaseOrderNumber": { "@id": "https://schema.org/orderNumber" },
            "itemCount": { "@id": "https://vocabulary.uncefact.org/despatchedQuantity" },
            "description": { "@id": "https://schema.org/description" },
            "packageQuantity": { "@id": "https://vocabulary.uncefact.org/packageQuantity" },
            "product": { "@id": "https://schema.org/Product" },
            "countryOfOrigin": { "@id": "https://vocabulary.uncefact.org/originCountry" },
            "shipToParty": { "@id": "https://vocabulary.uncefact.org/shipToParty" },
            "netWeight": { "@id": "https://vocabulary.uncefact.org/netWeightMeasure" },
            "grossWeight": { "@id": "https://vocabulary.uncefact.org/grossWeightMeasure" },
            "priceSpecification": { "@id": "https://schema.org/priceSpecification" }
          }
        },
        "TransferEvent": {
          "@id": "https://w3id.org/traceability#TransferEvent",
          "@context": {
            "place": { "@id": "https://schema.org/Place" },
            "price": { "@id": "https://schema.org/price" },
            "products": { "@id": "https://schema.org/Product" },
            "organization": { "@id": "https://w3id.org/traceability#Organization" },
            "identifier": { "@id": "https://w3id.org/traceability#receiver" },
            "addressCountry": { "@id": "https://schema.org/addressCountry" }
          }
        },
        "TransformEvent": {
          "@id": "https://w3id.org/traceability#TransformEvent",
          "@context": {
            "place": { "@id": "https://schema.org/Place" },
            "organization": { "@id": "https://w3id.org/traceability#Organization" },
            "newProducts": { "@id": "https://w3c-ccg.github.io/hashlink/#hl-url-params" },
            "consumedProducts": { "@id": "https://w3c-ccg.github.io/hashlink/#hl-url-params" }
          }
        },
        "Transport": {
          "@id": "https://w3id.org/traceability#Transport",
          "@context": {
            "arrivalLocation": { "@id": "https://schema.org/toLocation" },
            "departureDate": { "@id": "https://schema.org/departureTime" },
            "arrivalDate": { "@id": "https://schema.org/arrivalTime" },
            "modeOfTransport": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/modeOfTransport"
            },
            "carrier": { "@id": "https://schema.org/carrier" },
            "vesselNumber": { "@id": "https://vocabulary.uncefact.org/identifier" },
            "voyageNumber": { "@id": "https://vocabulary.uncefact.org/identifier" },
            "path": { "@id": "https://schema.org/line" }
          }
        },
        "TransportDocument": {
          "@id": "https://w3id.org/traceability#TransportDocument",
          "@context": {}
        },
        "TransportEquipment": {
          "@id": "https://vocabulary.uncefact.org/LogisticsTransportEquipment",
          "@context": {
            "equipmentReference": { "@id": "https://vocabulary.uncefact.org/identification" },
            "ISOEquipmentCode": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/ISOEquipmentCode"
            },
            "tareWeight": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/tareWeight"
            },
            "tareWeightUnit": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/weightUnit"
            },
            "cargoGrossWeight": { "@id": "https://vocabulary.uncefact.org/grossWeightMeasure" },
            "cargoGrossWeightUnit": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/weightUnit"
            },
            "isShipperOwned": {
              "@id": "https://api.swaggerhub.com/domains/dcsaorg/DCSA_DOMAIN/1.0.1#/components/schemas/isShipperOwned"
            },
            "seals": { "@id": "https://vocabulary.uncefact.org/affixedSeal" }
          }
        },
        "TransportEvent": {
          "@id": "https://w3id.org/traceability#TransportEvent",
          "@context": {
            "place": { "@id": "https://schema.org/Place" },
            "organization": { "@id": "https://w3id.org/traceability#Organization" },
            "products": { "@id": "https://schema.org/Product" },
            "deliveryMethod": { "@id": "https://schema.org/DeliveryMethod" },
            "trackingNumber": { "@id": "https://schema.org/trackingNumber" }
          }
        },
        "USDAPPQ203ForeignSiteInspection": {
          "@id": "https://w3id.org/traceability#USDAPPQ203ForeignSiteInspection",
          "@context": {
            "certificateNumber": { "@id": "https://vocabulary.uncefact.org/identification" },
            "commonInfo": { "@id": "https://w3id.org/traceability#AgricultureInspectionCommonInfo" },
            "shipment": { "@id": "https://vocabulary.uncefact.org/transportPackage" },
            "signatureDate": { "@id": "https://www.gs1.org/voc/certificationAuditDate" },
            "inspectionType": { "@id": "https://www.gs1.org/voc/certificationType" },
            "observations": { "@id": "https://vocabulary.uncefact.org/relatedObservation" }
          }
        },
        "USDAPPQ309APestInterceptionRecord": {
          "@id": "https://w3id.org/traceability#USDAPPQ309APestInterceptionRecord",
          "@context": {
            "interceptionNumber": { "@id": "https://vocabulary.uncefact.org/identification" },
            "shippingStop": { "@id": "https://vocabulary.uncefact.org/itineraryStopEvent" },
            "forwardTo": { "@id": "https://vocabulary.uncefact.org/recipientAssignedId" },
            "priority": { "@id": "https://vocabulary.uncefact.org/priorityCode" },
            "interceptionDate": { "@id": "https://vocabulary.uncefact.org/actualOccurrenceDateTime" },
            "inspector": { "@id": "https://vocabulary.uncefact.org/inspectionParty" },
            "overtime": { "@id": "https://vocabulary.uncefact.org/information" },
            "pathway": { "@id": "https://vocabulary.uncefact.org/mode" },
            "modeOfTransportation": { "@id": "https://vocabulary.uncefact.org/mode" },
            "materialFor": { "@id": "https://vocabulary.uncefact.org/intendedUse" },
            "narp": { "@id": "https://vocabulary.uncefact.org/statementNote" },
            "importedAs": { "@id": "https://schema.org/description" },
            "shipment": { "@id": "https://vocabulary.uncefact.org/transportPackage" },
            "whereIntercepted": { "@id": "https://vocabulary.uncefact.org/AttachedTransportEquipment" },
            "PestSample": { "@id": "http://rs.tdwg.org/dwc/terms/materialSampleID" },
            "pestDeterminations": { "@id": "https://dwc.tdwg.org/list/#dwc_identificationID" },
            "quarantineStatus": { "@id": "https://vocabulary.uncefact.org/conditionCode" },
            "remarks": { "@id": "https://vocabulary.uncefact.org/remark" }
          }
        },
        "USDAPPQ368NoticeOfArrival": {
          "@id": "https://w3id.org/traceability#USDAPPQ368NoticeOfArrival",
          "@context": {
            "shipment": { "@id": "https://vocabulary.uncefact.org/transportPackage" },
            "arrivalDate": { "@id": "https://vocabulary.uncefact.org/actualArrivalRelatedDateTime" },
            "permitNumber": { "@id": "https://vocabulary.uncefact.org/identification" },
            "customsEntryNumber": { "@id": "https://vocabulary.uncefact.org/customsId" },
            "presentLocation": {
              "@id": "https://vocabulary.uncefact.org/consignmentDestinationSpecifiedLocation"
            },
            "locationGrown": { "@id": "https://vocabulary.uncefact.org/originLocation" },
            "ITNumber": { "@id": "https://vocabulary.uncefact.org/customsId" },
            "productDisposition": { "@id": "https://vocabulary.uncefact.org/dispositionDocument" },
            "ppqOfficial": { "@id": "https://vocabulary.uncefact.org/inspectionParty" },
            "signatureDate": { "@id": "https://vocabulary.uncefact.org/occurrenceDateTime" }
          }
        },
        "USDAPPQ391SpecimensForDetermination": {
          "@id": "https://w3id.org/traceability#USDAPPQ391SpecimensForDetermination",
          "@context": {
            "priority": { "@id": "https://vocabulary.uncefact.org/priorityCode" },
            "priorityExplanation": { "@id": "https://vocabulary.uncefact.org/remarks" },
            "collectionNumber": { "@id": "https://vocabulary.uncefact.org/identification" },
            "submissionDate": { "@id": "https://vocabulary.uncefact.org/reportSubmissionDateTime" },
            "collectionDate": { "@id": "https://vocabulary.uncefact.org/actualOccurrenceDateTime" },
            "submittingAgency": { "@id": "https://vocabulary.uncefact.org/agencyId" },
            "submitter": { "@id": "https://vocabulary.uncefact.org/PartyRoleCodeList#TB" },
            "collector": { "@id": "https://vocabulary.uncefact.org/inspectionParty" },
            "interceptionSite": { "@id": "https://vocabulary.uncefact.org/occurrenceLocation" },
            "identificationReason": { "@id": "https://vocabulary.uncefact.org/reasonCode" },
            "remarks": { "@id": "https://vocabulary.uncefact.org/remarks" },
            "tentativeDetermination": { "@id": "https://dwc.tdwg.org/list/#dwc_identificationID" },
            "finalDetermination": { "@id": "https://dwc.tdwg.org/list/#dwc_identificationID" },
            "sampleDisposition": { "@id": "https://dwc.tdwg.org/list/#dwc_disposition" },
            "signatureDate": { "@id": "https://vocabulary.uncefact.org/occurrenceDateTime" },
            "lab": { "@id": "https://vocabulary.uncefact.org/lodgementLocation" },
            "labConformationNumber": { "@id": "https://vocabulary.uncefact.org/identification" },
            "dateReceived": { "@id": "https://vocabulary.uncefact.org/acceptanceDateTime" }
          }
        },
        "USDAPPQ429FumigationRecord": {
          "@id": "https://w3id.org/traceability#USDAPPQ429FumigationRecord",
          "@context": {
            "tarpaulin": { "@id": "https://vocabulary.uncefact.org/value" },
            "stationReporting": { "@id": "https://vocabulary.uncefact.org/relevantLocation" },
            "pest": { "@id": "https://schema.org/description" },
            "interceptionRecord": {
              "@id": "https://w3id.org/traceability#USDAPPQ309APestInterceptionRecord.yml"
            },
            "shipment": { "@id": "https://vocabulary.uncefact.org/transportPackage" },
            "fumigationContractor": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "dateFumigationOrdered": { "@id": "https://vocabulary.uncefact.org/actualDateTime" },
            "fumigationSite": { "@id": "https://vocabulary.uncefact.org/occurrenceLocation" },
            "dateFumigated": { "@id": "https://vocabulary.uncefact.org/actualOccurrenceDateTime" },
            "fumigantAndTreatmentSchedule": { "@id": "https://vocabulary.uncefact.org/regulationName" },
            "temperatureOfSpace": {
              "@id": "https://vocabulary.uncefact.org/actualReportedMeasurement"
            },
            "temperatureOfCommodity": {
              "@id": "https://vocabulary.uncefact.org/actualReportedMeasurement"
            },
            "gasAnalyzer": { "@id": "https://schema.org/description" },
            "enclosure": { "@id": "https://schema.org/description" },
            "weatherConditions": { "@id": "https://schema.org/description" },
            "cubicCapacity": { "@id": "https://vocabulary.uncefact.org/actualReportedMeasurement" },
            "section18Exemption": { "@id": "https://vocabulary.uncefact.org/value" },
            "numberOfFans": { "@id": "https://vocabulary.uncefact.org/unitQuantity" },
            "totalCFMOfFans": { "@id": "https://vocabulary.uncefact.org/actualReportedMeasurement" },
            "timeFansOperated": { "@id": "https://vocabulary.uncefact.org/durationMeasure" },
            "foodOrFeedCommodity": { "@id": "https://vocabulary.uncefact.org/functionDescription" },
            "gasIntroductionStart": { "@id": "https://vocabulary.uncefact.org/startDateTime" },
            "gasIntroductionFinish": { "@id": "https://vocabulary.uncefact.org/endDateTime" },
            "totalGasIntroduced": {
              "@id": "https://vocabulary.uncefact.org/actualReportedMeasurement"
            },
            "residueSampleTaken": { "@id": "https://vocabulary.uncefact.org/value" },
            "residueSampleNumber": { "@id": "https://schema.org/description" },
            "gasConcentrations": { "@id": "https://vocabulary.uncefact.org/relatedObservation" },
            "detectorTubeReadings": { "@id": "https://vocabulary.uncefact.org/relatedObservation" },
            "remarks": { "@id": "https://vocabulary.uncefact.org/remark" },
            "inspector": { "@id": "https://vocabulary.uncefact.org/specifiedContactPerson" },
            "reviewer": { "@id": "https://vocabulary.uncefact.org/specifiedContactPerson" },
            "fumigatorMaterials": { "@id": "https://schema.org/description" },
            "ppqMaterials": { "@id": "https://schema.org/description" },
            "preparationProcedures": { "@id": "https://schema.org/description" }
          }
        },
        "USDAPPQ449RTemperatureCalibration": {
          "@id": "https://w3id.org/traceability#USDAPPQ449RTemperatureCalibration",
          "@context": {
            "vesselName": { "@id": "https://vocabulary.uncefact.org/name" },
            "ppqDutyStation": {
              "@id": "https://vocabulary.uncefact.org/transitCustomsOfficeSpecifiedLocation"
            },
            "inspectionDate": { "@id": "https://vocabulary.uncefact.org/inspectionDateTime" },
            "inspectionPoint": { "@id": "https://vocabulary.uncefact.org/transitLocation" },
            "hullNumberDockyard": { "@id": "https://vocabulary.uncefact.org/identification" },
            "imoNumber": { "@id": "https://vocabulary.uncefact.org/identification" },
            "flagCode": { "@id": "https://vocabulary.uncefact.org/identification" },
            "shipsOfficer": { "@id": "https://vocabulary.uncefact.org/specifiedContactPerson" },
            "ownerOperator": { "@id": "https://vocabulary.uncefact.org/specifiedContactPerson" },
            "instrument1MakeModel": {
              "@id": "https://vocabulary.uncefact.org/AttachedTransportEquipment"
            },
            "instrument2MakeModel": {
              "@id": "https://vocabulary.uncefact.org/AttachedTransportEquipment"
            },
            "locationsDiagramMatchSatisfactory": {
              "@id": "https://vocabulary.uncefact.org/DocumentCodeList#287"
            },
            "sensorsBoxesLabelingSatisfactory": {
              "@id": "https://vocabulary.uncefact.org/DocumentCodeList#287"
            },
            "cableLengthSatisfactory": {
              "@id": "https://vocabulary.uncefact.org/DocumentCodeList#287"
            },
            "reactionTimeSatisfactory": {
              "@id": "https://vocabulary.uncefact.org/DocumentCodeList#287"
            },
            "temperatureReadings": { "@id": "https://vocabulary.uncefact.org/transportTemperature" },
            "participatingOfficials": {
              "@id": "https://vocabulary.uncefact.org/specifiedContactPerson"
            },
            "remarks": { "@id": "https://vocabulary.uncefact.org/remarks" },
            "company": { "@id": "https://vocabulary.uncefact.org/specifiedOrganization" },
            "signatureDate": { "@id": "https://vocabulary.uncefact.org/performanceDateTime" }
          }
        },
        "USDAPPQ505PlantDeclaration": {
          "@id": "https://w3id.org/traceability#USDAPPQ505PlantDeclaration",
          "@context": {
            "shipment": { "@id": "https://vocabulary.uncefact.org/transportPackage" },
            "productDeclarations": {
              "@id": "https://w3id.org/traceability#LaceyActProductDeclaration"
            },
            "preparer": { "@id": "https://vocabulary.uncefact.org/declarantParty" },
            "date": { "@id": "https://vocabulary.uncefact.org/issueDateTime" }
          }
        },
        "USDAPPQ519ComplianceAgreement": {
          "@id": "https://w3id.org/traceability#USDAPPQ519ComplianceAgreement",
          "@context": {
            "person": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "firm": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "regulatedArticles": { "@id": "https://www.gs1.org/voc/regulatedProductName" },
            "quarantinesRegulations": {
              "@id": "https://vocabulary.uncefact.org/applicableRegulatoryProcedure"
            },
            "agreement": { "@id": "https://vocabulary.uncefact.org/guarantee" },
            "signatureDate": { "@id": "https://vocabulary.uncefact.org/issueDateTime" },
            "ppqCbpOfficial": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "usAgencyOfficial": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "agreementNumber": { "@id": "https://vocabulary.uncefact.org/ReferenceCodeList#AJS" },
            "agreementDate": { "@id": "https://vocabulary.uncefact.org/issueDateTime" }
          }
        },
        "USDAPPQ587PlantImportApplication": {
          "@id": "https://w3id.org/traceability#USDAPPQ587PlantImportApplication",
          "@context": {
            "applicant": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "shipment": { "@id": "https://vocabulary.uncefact.org/transportPackage" },
            "intendedUse": { "@id": "https://vocabulary.uncefact.org/intendedUse" },
            "signatureDate": { "@id": "https://vocabulary.uncefact.org/issueDateTime" }
          }
        },
        "USDASC6ExemptCommodityForm": {
          "@id": "https://w3id.org/traceability#USDASC6ExemptCommodityForm",
          "@context": {
            "serialNumber": { "@id": "https://w3id.org/traceability#serialNumber" },
            "customsEntryNumber": { "@id": "https://w3id.org/traceability#customsEntryNumber" },
            "tariffCodeNumber": { "@id": "https://w3id.org/traceability#tariffCodeNumber" },
            "carrierId": { "@id": "https://w3id.org/traceability#carrierId" },
            "lotId": { "@id": "https://w3id.org/traceability#lotId" },
            "dateOfEntry": { "@id": "https://w3id.org/traceability#dateOfEntry" },
            "signatureDate": { "@id": "https://w3id.org/traceability#signatureDate" },
            "facility": { "@id": "https://www.gs1.org/voc/Place" },
            "inspector": { "@id": "https://w3id.org/traceability#Inspector" },
            "shipment": { "@id": "https://w3id.org/traceability#AgricultureParcelDelivery" },
            "applicant": { "@id": "https://w3id.org/traceability#applicant" },
            "importerSignatureDate": { "@id": "https://w3id.org/traceability#importerSignatureDate" },
            "inspectionDate": { "@id": "https://vocabulary.uncefact.org/inspectionDateTime" },
            "intendedUse": { "@id": "https://w3id.org/traceability#intendedUse" },
            "intendedUseCert": { "@id": "https://w3id.org/traceability#intendedUseCert" }
          }
        },
        "USDASpecialtyCrops237AForm": {
          "@id": "https://w3id.org/traceability#USDASpecialtyCrops237AForm",
          "@context": {
            "requestDate": { "@id": "https://vocabulary.uncefact.org/reportSubmissionDateTime" },
            "anticipatedAuditDate": { "@id": "https://www.gs1.org/voc/certificationAuditDate" },
            "auditee": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "applicant": { "@id": "https://vocabulary.uncefact.org/associatedParty" },
            "billingAccountNumber": { "@id": "https://schema.org/accountId" },
            "locations": { "@id": "https://schema.org/location" },
            "totalArea": { "@id": "https://www.gs1.org/voc/grossArea" },
            "commoditiesCovered": { "@id": "https://www.gs1.org/voc/certificationSubject" },
            "auditProgramsRequested": { "@id": "https://www.gs1.org/voc/certificationType" },
            "countByInspector": { "@id": "https://vocabulary.uncefact.org/applicableSpecifiedAction" },
            "additionalRemarks": { "@id": "https://vocabulary.uncefact.org/remarks" }
          }
        },
        "USMCACertifier": {
          "@id": "https://w3id.org/traceability/USMCACertifier",
          "@context": {
            "role": { "@id": "https://w3id.org/traceability#certifierRole" },
            "certifierDetails": { "@id": "https://w3id.org/traceability#certifierDetails" }
          }
        },
        "USMCAClaims": {
          "@id": "https://w3id.org/traceability/USMCAClaims",
          "@context": {
            "producerDetails": { "@id": "https://schema.org/manufacturer" },
            "producerConfidential": { "@id": "https://w3id.org/traceability#producerConfidential" },
            "importerDetails": { "@id": "https://w3id.org/traceability#importerDetails" },
            "importerUnknown": { "@id": "https://w3id.org/traceability#importerUnknown" },
            "exporterDetails": { "@id": "https://w3id.org/traceability#exporterDetails" },
            "goods": { "@id": "https://schema.org/Product" }
          }
        },
        "USMCAProduct": {
          "@id": "https://w3id.org/traceability/USMCAProduct",
          "@context": {
            "commodityCode": { "@id": "https://w3id.org/traceability#commodityCode" },
            "commodityCodeType": { "@id": "https://w3id.org/traceability#commodityCodeType" },
            "originCriterion": { "@id": "https://w3id.org/traceability#originCriterion" },
            "countryOfOrigin": { "@id": "https://w3id.org/traceability#countryOfOrigin" }
          }
        },
        "WebLEI": {
          "@id": "https://w3id.org/traceability#WebLEI",
          "@context": {
            "lei": { "@id": "https://www.gleif.org/en/about-lei/iso-17442-the-lei-code-structure#" },
            "entity": { "@id": "https://w3id.org/traceability#LEIEntity" },
            "registration": { "@id": "https://w3id.org/traceability#LEIRegistration" }
          }
        },
        "ActivityPubActorCard": {
          "@id": "https://w3id.org/traceability#ActivityPubActorCard",
          "@context": {}
        },
        "AgricultureActivityCredential": {
          "@id": "https://w3id.org/traceability#AgricultureActivityCredential",
          "@context": {}
        },
        "AgricultureCanineCard": {
          "@id": "https://w3id.org/traceability#AgricultureCanineCard",
          "@context": {}
        },
        "BankAccountCredential": {
          "@id": "https://w3id.org/traceability#BankAccountCredential",
          "@context": {}
        },
        "BillOfLadingCredential": {
          "@id": "https://w3id.org/traceability#BillOfLadingCredential",
          "@context": {}
        },
        "CBP3461EntryCredential": {
          "@id": "https://w3id.org/traceability#CBP3461EntryCredential",
          "@context": {}
        },
        "CBP7501EntrySummaryCredential": {
          "@id": "https://w3id.org/traceability#CBP7501EntrySummaryCredential",
          "@context": {}
        },
        "CBPEntryType86Credential": {
          "@id": "https://w3id.org/traceability#CBPEntryType86Credential",
          "@context": {}
        },
        "CBPSection321DeMinimisDeMinimisCredential": {
          "@id": "https://w3id.org/traceability#CBPSection321DeMinimisCredential",
          "@context": {}
        },
        "CTPATCertificate": { "@id": "https://w3id.org/traceability#CTPATCertificate", "@context": {} },
        "CertificationOfOrigin": {
          "@id": "https://w3id.org/traceability#CertificationOfOrigin",
          "@context": {}
        },
        "CommercialInvoiceCredential": {
          "@id": "https://w3id.org/traceability#CommercialInvoiceCredential",
          "@context": {}
        },
        "DCSAShippingInstructionCredential": {
          "@id": "https://w3id.org/traceability#DCSAShippingInstructionCredential",
          "@context": {}
        },
        "DCSATransportDocumentCredential": {
          "@id": "https://w3id.org/traceability#DCSATransportDocumentCredential",
          "@context": {}
        },
        "DeliveryScheduleCredential": {
          "@id": "https://w3id.org/traceability#DeliveryScheduleCredential",
          "@context": {}
        },
        "DeliveryStatementCredential": {
          "@id": "https://w3id.org/traceability#DeliveryStatementCredential",
          "@context": {}
        },
        "DigitalProductPassportCredential": {
          "@id": "https://w3id.org/traceability#DigitalProductPassportCredential",
          "@context": {}
        },
        "DigitalProductPassportDataCarrierCredential": {
          "@id": "https://w3id.org/traceability#DigitalProductPassportDataCarrierCredential",
          "@context": {}
        },
        "EPA35401PesticidesCredential": {
          "@id": "https://w3id.org/traceability#EPA35401PesticidesCredential",
          "@context": {}
        },
        "EPA35401PesticidesPart2Credential": {
          "@id": "https://w3id.org/traceability#EPA35401PesticidesPart2Credential",
          "@context": {}
        },
        "EPA35401PesticidesPart3Credential": {
          "@id": "https://w3id.org/traceability#EPA35401PesticidesPart3Credential",
          "@context": {}
        },
        "EntryNumberCredential": {
          "@id": "https://w3id.org/traceability#EntryNumberCredential",
          "@context": {}
        },
        "EnvironmentalImpactCredential": {
          "@id": "https://w3id.org/traceability#EnvironmentalImpactCredential",
          "@context": {}
        },
        "FSMACreatingCTECredential": {
          "@id": "https://w3id.org/traceability#FSMACreatingCTECredential",
          "@context": {}
        },
        "FSMAFirstReceiverDataCredential": {
          "@id": "https://w3id.org/traceability#FSMAFirstReceiverDataCredential",
          "@context": {}
        },
        "FSMAGrowingCTECredential": {
          "@id": "https://w3id.org/traceability#FSMAGrowingCTECredential",
          "@context": {}
        },
        "FSMAReceivingCTECredential": {
          "@id": "https://w3id.org/traceability#FSMAReceivingCTECredential",
          "@context": {}
        },
        "FSMAShippingCTECredential": {
          "@id": "https://w3id.org/traceability#FSMAShippingCTECredential",
          "@context": {}
        },
        "FSMATransformingCTECredential": {
          "@id": "https://w3id.org/traceability#FSMATransformingCTECredential",
          "@context": {}
        },
        "FSVPImporterCredential": {
          "@id": "https://w3id.org/traceability#FSVPImporterCredential",
          "@context": {}
        },
        "FoodDefenseInspectionCredential": {
          "@id": "https://w3id.org/traceability#FoodDefenseInspectionCredential",
          "@context": {}
        },
        "FoodFacilityRegistrationCredential": {
          "@id": "https://w3id.org/traceability#FoodFacilityRegistrationCredential",
          "@context": {}
        },
        "FoodGradeInspectionCredential": {
          "@id": "https://w3id.org/traceability#FoodGradeInspectionCredential",
          "@context": {}
        },
        "FreightManifestCredential": {
          "@id": "https://w3id.org/traceability#FreightManifestCredential",
          "@context": {}
        },
        "GAPInspectionCredential": {
          "@id": "https://w3id.org/traceability#GAPInspectionCredential",
          "@context": {}
        },
        "GS18PrefixLicenseCredential": {
          "@id": "https://w3id.org/traceability#GS18PrefixLicenseCredential",
          "@context": {}
        },
        "GS1CompanyPrefixLicenseCredential": {
          "@id": "https://w3id.org/traceability#GS1CompanyPrefixLicenseCredential",
          "@context": {}
        },
        "GS1DataCredential": {
          "@id": "https://w3id.org/traceability#GS1DataCredential",
          "@context": {}
        },
        "GS1DelegationCredential": {
          "@id": "https://w3id.org/traceability#GS1DelegationCredential",
          "@context": {}
        },
        "GS1IdentificationKeyLicenseCredential": {
          "@id": "https://w3id.org/traceability#GS1IdentificationKeyLicenseCredential",
          "@context": {}
        },
        "GS1KeyCredential": { "@id": "https://w3id.org/traceability#GS1KeyCredential", "@context": {} },
        "GS1PrefixLicenseCredential": {
          "@id": "https://w3id.org/traceability#GS1PrefixLicenseCredential",
          "@context": {}
        },
        "HouseBillOfLadingCredential": {
          "@id": "https://w3id.org/traceability#HouseBillOfLadingCredential",
          "@context": {}
        },
        "IATAAirWaybillCredential": {
          "@id": "https://w3id.org/traceability#IATAAirWaybillCredential",
          "@context": {}
        },
        "ImporterSecurityFilingCredential": {
          "@id": "https://w3id.org/traceability#ImporterSecurityFilingCredential",
          "@context": {}
        },
        "IntellectualPropertyRightsCredential": {
          "@id": "https://w3id.org/traceability#IntellectualPropertyRightsCredential",
          "@context": {}
        },
        "IntellectualPropertyRightsLicenseCredential": {
          "@id": "https://w3id.org/traceability#IntellectualPropertyRightsLicenseCredential",
          "@context": {}
        },
        "IntentToImportCredential": {
          "@id": "https://w3id.org/traceability#IntentToImportCredential",
          "@context": {}
        },
        "InventoryRegistrationCredential": {
          "@id": "https://w3id.org/traceability#InventoryRegistrationCredential",
          "@context": {}
        },
        "MasterBillOfLadingCredential": {
          "@id": "https://w3id.org/traceability#MasterBillOfLadingCredential",
          "@context": {}
        },
        "MexicoEInvoiceCredential": {
          "@id": "https://w3id.org/traceability#MexicoEInvoiceCredential",
          "@context": {}
        },
        "MillTestReportCredential": {
          "@id": "https://w3id.org/traceability#MillTestReportCredential",
          "@context": {}
        },
        "MonthlyAdvanceManifestCredential": {
          "@id": "https://w3id.org/traceability#MonthlyAdvanceManifestCredential",
          "@context": {}
        },
        "MonthlyAggregateDeliveryStatementCredential": {
          "@id": "https://w3id.org/traceability#MonthlyAggregateDeliveryStatementCredential",
          "@context": {}
        },
        "MultiModalBillOfLadingCredential": {
          "@id": "https://w3id.org/traceability#MultiModalBillOfLadingCredential",
          "@context": {}
        },
        "NaturalGasProducerEnvironmentalPassportCredential": {
          "@id": "https://w3id.org/traceability#NaturalGasProducerEnvironmentalPassportCredential",
          "@context": {}
        },
        "OilAndGasDeliveryTicketCredential": {
          "@id": "https://w3id.org/traceability#OilAndGasDeliveryTicketCredential",
          "@context": {}
        },
        "OilAndGasProductCredential": {
          "@id": "https://w3id.org/traceability#OilAndGasProductCredential",
          "@context": {}
        },
        "OrderConfirmationCredential": {
          "@id": "https://w3id.org/traceability#OrderConfirmationCredential",
          "@context": {}
        },
        "OrganicCertificateCredential": {
          "@id": "https://w3id.org/traceability#OrganicCertificateCredential",
          "@context": {}
        },
        "PGAShipmentStatusCredential": {
          "@id": "https://w3id.org/traceability#PGAShipmentStatusCredential",
          "@context": {}
        },
        "PackingListCredential": {
          "@id": "https://w3id.org/traceability#PackingListCredential",
          "@context": {}
        },
        "PhytosanitaryCredential": {
          "@id": "https://w3id.org/traceability#PhytosanitaryCredential",
          "@context": {}
        },
        "PlantSystemsInspectionCredential": {
          "@id": "https://w3id.org/traceability#PlantSystemsInspectionCredential",
          "@context": {}
        },
        "PowerOfAttorneyCredential": {
          "@id": "https://spec.edmcouncil.org/fibo/ontology/BE/LegalEntities/LegalPersons/PowerOfAttorney",
          "@context": {}
        },
        "ProductRegistrationCredential": {
          "@id": "https://w3id.org/traceability#ProductRegistrationCredential",
          "@context": {}
        },
        "PurchaseOrderCredential": {
          "@id": "https://w3id.org/traceability#PurchaseOrderCredential",
          "@context": {}
        },
        "QualifiedWebLEIIssuerCredential": {
          "@id": "https://w3id.org/traceability#QualifiedWebLEIIssuerCredential",
          "@context": {}
        },
        "SIMASteelImportLicenseApplicationCredential": {
          "@id": "https://w3id.org/traceability#SIMASteelImportLicenseApplicationCredential",
          "@context": {}
        },
        "SIMASteelImportLicenseCredential": {
          "@id": "https://w3id.org/traceability#SIMASteelImportLicenseCredential",
          "@context": {}
        },
        "SeaCargoManifestCredential": {
          "@id": "https://w3id.org/traceability#SeaCargoManifestCredential",
          "@context": {}
        },
        "ShippingInstructionsCredential": {
          "@id": "https://w3id.org/traceability#ShippingInstructionsCredential",
          "@context": {}
        },
        "SoftwareBillofMaterialsCredential": {
          "@id": "https://w3id.org/traceability#SoftwareBillOfMaterialsCredential",
          "@context": {}
        },
        "TSCACertificationCredential": {
          "@id": "https://w3id.org/traceability#TSCACertificationCredential",
          "@context": {}
        },
        "ThingCredential": { "@id": "https://w3id.org/traceability#ThingCredential", "@context": {} },
        "USDAPPQ203ForeignSiteInspectionCredential": {
          "@id": "https://w3id.org/traceability#USDAPPQ203ForeignSiteInspectionCredential",
          "@context": {}
        },
        "USDAPermitToImportCredential": {
          "@id": "https://w3id.org/traceability#USDAPermitToImportCredential",
          "@context": {}
        },
        "USMCACertificationOfOrigin": {
          "@id": "https://w3id.org/traceability#USMCACertificationOfOrigin",
          "@context": {}
        },
        "VerifiableBusinessCard": {
          "@id": "https://w3id.org/traceability#VerifiableBusinessCard",
          "@context": {}
        },
        "VerifiablePostmanCollection": {
          "@id": "https://w3id.org/traceability#VerifiablePostmanCollection",
          "@context": {}
        },
        "VerifiableScorecard": {
          "@id": "https://w3id.org/traceability#VerifiableScorecard",
          "@context": {}
        },
        "WebLEICredential": { "@id": "https://w3id.org/traceability#WebLeiCredential", "@context": {} }
      }
    };
    businessEntityV1 = {
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "@vocab": "https://schema.org/",
        "schema": "https://schema.org/",
        "gleif": "https://www.gleif.org/ontology/Base/",
        "BusinessEntityCredential": "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/business-entity/v1#BusinessEntityCredential",
        "legalEntityIdentifier": "gleif:hasLegalEntityIdentifier",
        "legalName": "gleif:hasLegalName",
        "legalForm": "gleif:hasLegalForm",
        "legalJurisdiction": "gleif:hasLegalJurisdiction"
      }
    };
    electricityV1 = {
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "schema": "https://schema.org/",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "deg": "https://schema.beckn.io/deg#",
        "CustomerCredential": {
          "@id": "deg:CustomerCredential",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "id": "@id",
            "type": "@type"
          }
        },
        "customerProfile": {
          "@id": "deg:customerProfile",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "customerNumber": {
              "@id": "deg:customerNumber",
              "@type": "xsd:string"
            },
            "meterNumber": {
              "@id": "deg:meterNumber",
              "@type": "xsd:string"
            },
            "meterType": {
              "@id": "deg:meterType",
              "@type": "xsd:string"
            },
            "idRef": {
              "@id": "deg:idRef",
              "@type": "@id",
              "@context": {
                "issuedBy": {
                  "@id": "deg:issuedBy",
                  "@type": "@id"
                },
                "subjectId": {
                  "@id": "deg:subjectId",
                  "@type": "xsd:string"
                }
              }
            }
          }
        },
        "customerDetails": {
          "@id": "deg:customerDetails",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "fullName": {
              "@id": "schema:name",
              "@type": "xsd:string"
            },
            "serviceConnectionDate": {
              "@id": "deg:serviceConnectionDate",
              "@type": "xsd:dateTime"
            },
            "installationAddress": {
              "@id": "beckn:Location",
              "@type": "@id",
              "@context": {
                "beckn": "https://schema.beckn.io/",
                "descriptor": {
                  "@id": "beckn:descriptor",
                  "@type": "@id",
                  "@context": {
                    "name": {
                      "@id": "beckn:name",
                      "@type": "xsd:string"
                    },
                    "code": {
                      "@id": "beckn:code",
                      "@type": "xsd:string"
                    },
                    "short_desc": {
                      "@id": "beckn:short_desc",
                      "@type": "xsd:string"
                    },
                    "long_desc": {
                      "@id": "beckn:long_desc",
                      "@type": "xsd:string"
                    }
                  }
                },
                "map_url": {
                  "@id": "beckn:map_url",
                  "@type": "@id"
                },
                "gps": {
                  "@id": "beckn:gps",
                  "@type": "xsd:string"
                },
                "address": {
                  "@id": "beckn:address",
                  "@type": "xsd:string"
                },
                "city": {
                  "@id": "beckn:city",
                  "@type": "@id",
                  "@context": {
                    "name": {
                      "@id": "beckn:name",
                      "@type": "xsd:string"
                    },
                    "code": {
                      "@id": "beckn:code",
                      "@type": "xsd:string"
                    }
                  }
                },
                "district": {
                  "@id": "beckn:district",
                  "@type": "xsd:string"
                },
                "state": {
                  "@id": "beckn:state",
                  "@type": "@id",
                  "@context": {
                    "name": {
                      "@id": "beckn:name",
                      "@type": "xsd:string"
                    },
                    "code": {
                      "@id": "beckn:code",
                      "@type": "xsd:string"
                    }
                  }
                },
                "country": {
                  "@id": "beckn:country",
                  "@type": "@id",
                  "@context": {
                    "name": {
                      "@id": "beckn:name",
                      "@type": "xsd:string"
                    },
                    "code": {
                      "@id": "beckn:code",
                      "@type": "xsd:string"
                    }
                  }
                },
                "area_code": {
                  "@id": "beckn:area_code",
                  "@type": "xsd:string"
                },
                "circle": {
                  "@id": "beckn:circle",
                  "@type": "@id",
                  "@context": {
                    "gps": {
                      "@id": "beckn:gps",
                      "@type": "xsd:string"
                    },
                    "radius": {
                      "@id": "beckn:radius",
                      "@type": "@id"
                    }
                  }
                },
                "polygon": {
                  "@id": "beckn:polygon",
                  "@type": "xsd:string"
                },
                "3dspace": {
                  "@id": "beckn:3dspace",
                  "@type": "xsd:string"
                },
                "rating": {
                  "@id": "beckn:rating",
                  "@type": "xsd:string"
                },
                "openLocationCode": {
                  "@id": "deg:openLocationCode",
                  "@type": "xsd:string"
                }
              }
            }
          }
        },
        "consumptionProfile": {
          "@id": "deg:consumptionProfile",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "premisesType": {
              "@id": "deg:premisesType",
              "@type": "xsd:string"
            },
            "connectionType": {
              "@id": "deg:connectionType",
              "@type": "xsd:string"
            },
            "sanctionedLoadKW": {
              "@id": "deg:sanctionedLoadKW",
              "@type": "xsd:decimal"
            },
            "tariffCategoryCode": {
              "@id": "deg:tariffCategoryCode",
              "@type": "xsd:string"
            }
          }
        },
        "generationProfile": {
          "@id": "deg:generationProfile",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "assetId": {
              "@id": "deg:assetId",
              "@type": "xsd:string"
            },
            "generationType": {
              "@id": "deg:generationType",
              "@type": "xsd:string"
            },
            "capacityKW": {
              "@id": "deg:capacityKW",
              "@type": "xsd:decimal"
            },
            "commissioningDate": {
              "@id": "deg:commissioningDate",
              "@type": "xsd:dateTime"
            },
            "manufacturer": {
              "@id": "schema:manufacturer",
              "@type": "xsd:string"
            },
            "modelNumber": {
              "@id": "deg:modelNumber",
              "@type": "xsd:string"
            }
          }
        },
        "storageProfile": {
          "@id": "deg:storageProfile",
          "@type": "@id",
          "@context": {
            "@version": 1.1,
            "@protected": true,
            "assetId": {
              "@id": "deg:storageAssetId",
              "@type": "xsd:string"
            },
            "storageCapacityKWh": {
              "@id": "deg:storageCapacityKWh",
              "@type": "xsd:decimal"
            },
            "powerRatingKW": {
              "@id": "deg:powerRatingKW",
              "@type": "xsd:decimal"
            },
            "commissioningDate": {
              "@id": "deg:storageCommissioningDate",
              "@type": "xsd:dateTime"
            },
            "storageType": {
              "@id": "deg:storageType",
              "@type": "xsd:string"
            }
          }
        },
        "idRef": {
          "@id": "deg:idRef",
          "@type": "@id",
          "@context": {
            "issuedBy": {
              "@id": "deg:issuedBy",
              "@type": "@id"
            },
            "subjectId": {
              "@id": "deg:subjectId",
              "@type": "xsd:string"
            }
          }
        },
        "credentialStatus": {
          "@id": "deg:credentialStatus",
          "@type": "@id",
          "@context": {
            "statusPurpose": {
              "@id": "deg:statusPurpose",
              "@type": "xsd:string"
            },
            "statusListCredential": {
              "@id": "deg:statusListCredential",
              "@type": "@id"
            }
          }
        }
      }
    };
    employmentOfferLetterV1 = {
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "@vocab": "https://schema.org/",
        "schema": "https://schema.org/",
        "EmploymentOfferLetterCredential": "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/employment-offer-letter/v1#EmploymentOfferLetterCredential"
      }
    };
    functionalIdentityV1 = {
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "@vocab": "https://schema.org/",
        "schema": "https://schema.org/",
        "isco": "https://www.ilo.org/isco-08/",
        "FunctionalIdentityCredential": "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/functional-identity/v1#FunctionalIdentityCredential",
        "role": "schema:hasOccupation",
        "roleScheme": "schema:occupationalCategory",
        "affiliation": "schema:affiliation",
        "membershipId": "schema:memberOf"
      }
    };
    immunizationV1 = {
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "@vocab": "http://hl7.org/fhir/",
        "fhir": "http://hl7.org/fhir/",
        "snomed": "http://snomed.info/sct",
        "cvx": "http://hl7.org/fhir/sid/cvx",
        "ImmunizationCredential": "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/immunization/v1#ImmunizationCredential",
        "vaccineCode": "fhir:Immunization.vaccineCode",
        "patient": "fhir:Immunization.patient",
        "occurrenceDateTime": "fhir:Immunization.occurrenceDateTime",
        "lotNumber": "fhir:Immunization.lotNumber",
        "manufacturer": "fhir:Immunization.manufacturer",
        "performer": "fhir:Immunization.performer",
        "protocolApplied": "fhir:Immunization.protocolApplied",
        "site": "fhir:Immunization.site",
        "route": "fhir:Immunization.route",
        "doseQuantity": "fhir:Immunization.doseQuantity",
        "note": "fhir:Immunization.note"
      }
    };
    insurancePolicyV1 = {
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "@vocab": "https://schema.org/",
        "schema": "https://schema.org/",
        "InsurancePolicyCredential": "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/insurance-policy/v1#InsurancePolicyCredential"
      }
    };
    openBadgesV3 = {
      "@context": {
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "OpenBadgeCredential": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#OpenBadgeCredential"
        },
        "Achievement": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Achievement",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "achievementType": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#achievementType"
            },
            "alignment": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#alignment",
              "@container": "@set"
            },
            "creator": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#creator"
            },
            "creditsAvailable": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#creditsAvailable",
              "@type": "https://www.w3.org/2001/XMLSchema#float"
            },
            "criteria": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Criteria",
              "@type": "@id"
            },
            "fieldOfStudy": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#fieldOfStudy"
            },
            "humanCode": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#humanCode"
            },
            "image": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#image",
              "@type": "@id"
            },
            "otherIdentifier": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#otherIdentifier",
              "@container": "@set"
            },
            "related": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#related",
              "@container": "@set"
            },
            "resultDescription": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#resultDescription",
              "@container": "@set"
            },
            "specialization": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#specialization"
            },
            "tag": {
              "@id": "https://schema.org/keywords",
              "@container": "@set"
            },
            "version": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#version"
            },
            "inLanguage": {
              "@id": "https://schema.org/inLanguage"
            }
          }
        },
        "AchievementCredential": {
          "@id": "OpenBadgeCredential"
        },
        "AchievementSubject": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#AchievementSubject",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "achievement": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#achievement"
            },
            "activityEndDate": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#activityEndDate",
              "@type": "https://www.w3.org/2001/XMLSchema#date"
            },
            "activityStartDate": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#activityStartDate",
              "@type": "https://www.w3.org/2001/XMLSchema#date"
            },
            "creditsEarned": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#creditsEarned",
              "@type": "https://www.w3.org/2001/XMLSchema#float"
            },
            "identifier": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#identifier",
              "@container": "@set"
            },
            "image": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#image",
              "@type": "@id"
            },
            "licenseNumber": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#licenseNumber"
            },
            "result": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#result",
              "@container": "@set"
            },
            "role": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#role"
            },
            "source": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#source",
              "@type": "@id"
            },
            "term": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#term"
            }
          }
        },
        "Address": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Address",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "addressCountry": {
              "@id": "https://schema.org/addressCountry"
            },
            "addressCountryCode": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#CountryCode"
            },
            "addressLocality": {
              "@id": "https://schema.org/addressLocality"
            },
            "addressRegion": {
              "@id": "https://schema.org/addressRegion"
            },
            "geo": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#GeoCoordinates"
            },
            "postOfficeBoxNumber": {
              "@id": "https://schema.org/postOfficeBoxNumber"
            },
            "postalCode": {
              "@id": "https://schema.org/postalCode"
            },
            "streetAddress": {
              "@id": "https://schema.org/streetAddress"
            }
          }
        },
        "Alignment": {
          "@id": "https://schema.org/AlignmentObject",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "targetCode": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#targetCode"
            },
            "targetDescription": {
              "@id": "https://schema.org/targetDescription"
            },
            "targetFramework": {
              "@id": "https://schema.org/targetFramework"
            },
            "targetName": {
              "@id": "https://schema.org/targetName"
            },
            "targetType": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#targetType"
            },
            "targetUrl": {
              "@id": "https://schema.org/targetUrl",
              "@type": "https://www.w3.org/2001/XMLSchema#anyURI"
            }
          }
        },
        "Criteria": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Criteria"
        },
        "EndorsementCredential": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#EndorsementCredential"
        },
        "EndorsementSubject": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#EndorsementSubject",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "endorsementComment": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#endorsementComment"
            }
          }
        },
        "Evidence": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Evidence",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "audience": {
              "@id": "https://schema.org/audience"
            },
            "genre": {
              "@id": "https://schema.org/genre"
            }
          }
        },
        "GeoCoordinates": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#GeoCoordinates",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "latitude": {
              "@id": "https://schema.org/latitude"
            },
            "longitude": {
              "@id": "https://schema.org/longitude"
            }
          }
        },
        "IdentifierEntry": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#IdentifierEntry",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "identifier": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#identifier"
            },
            "identifierType": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#identifierType"
            }
          }
        },
        "IdentityObject": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#IdentityObject",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "hashed": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#hashed",
              "@type": "https://www.w3.org/2001/XMLSchema#boolean"
            },
            "identityHash": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#identityHash"
            },
            "identityType": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#identityType"
            },
            "salt": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#salt"
            }
          }
        },
        "Image": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Image",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "caption": {
              "@id": "https://schema.org/caption"
            }
          }
        },
        "Profile": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Profile",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "additionalName": {
              "@id": "https://schema.org/additionalName"
            },
            "address": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#address",
              "@type": "@id"
            },
            "dateOfBirth": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#dateOfBirth",
              "@type": "https://www.w3.org/2001/XMLSchema#date"
            },
            "email": {
              "@id": "https://schema.org/email"
            },
            "familyName": {
              "@id": "https://schema.org/familyName"
            },
            "familyNamePrefix": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#familyNamePrefix"
            },
            "givenName": {
              "@id": "https://schema.org/givenName"
            },
            "honorificPrefix": {
              "@id": "https://schema.org/honorificPrefix"
            },
            "honorificSuffix": {
              "@id": "https://schema.org/honorificSuffix"
            },
            "image": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#image",
              "@type": "@id"
            },
            "otherIdentifier": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#otherIdentifier",
              "@container": "@set"
            },
            "parentOrg": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#parentOrg",
              "@type": "@id"
            },
            "patronymicName": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#patronymicName"
            },
            "phone": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#phone"
            },
            "official": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#official"
            }
          }
        },
        "Related": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Related",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "version": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#version"
            },
            "inLanguage": {
              "@id": "https://schema.org/inLanguage"
            }
          }
        },
        "Result": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#Result",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "achievedLevel": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#achievedLevel",
              "@type": "https://www.w3.org/2001/XMLSchema#anyURI"
            },
            "resultDescription": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#resultDescription",
              "@type": "https://www.w3.org/2001/XMLSchema#anyURI"
            },
            "status": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#status"
            },
            "value": {
              "@id": "https://schema.org/value"
            }
          }
        },
        "ResultDescription": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#ResultDescription",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "allowedValue": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#allowedValue",
              "@container": "@list"
            },
            "requiredLevel": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#requiredLevel",
              "@type": "https://www.w3.org/2001/XMLSchema#anyURI"
            },
            "requiredValue": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#requiredValue"
            },
            "resultType": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#resultType"
            },
            "rubricCriterionLevel": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#rubricCriterionLevel",
              "@container": "@set"
            },
            "valueMax": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#valueMax"
            },
            "valueMin": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#valueMin"
            }
          }
        },
        "RubricCriterionLevel": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#RubricCriterionLevel",
          "@context": {
            "@protected": true,
            "id": "@id",
            "type": "@type",
            "level": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#level"
            },
            "points": {
              "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#points"
            }
          }
        },
        "alignment": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#alignment",
          "@container": "@set"
        },
        "description": {
          "@id": "https://schema.org/description"
        },
        "endorsement": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#endorsement",
          "@container": "@set"
        },
        "image": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#image",
          "@type": "@id"
        },
        "inLanguage": {
          "@id": "https://schema.org/inLanguage"
        },
        "name": {
          "@id": "https://schema.org/name"
        },
        "narrative": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#narrative"
        },
        "url": {
          "@id": "https://schema.org/url",
          "@type": "https://www.w3.org/2001/XMLSchema#anyURI"
        },
        "awardedDate": {
          "@id": "https://purl.imsglobal.org/spec/vc/ob/vocab.html#awardedDate",
          "@type": "xsd:dateTime"
        }
      }
    };
    prescriptionV1 = {
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "@vocab": "http://hl7.org/fhir/",
        "fhir": "http://hl7.org/fhir/",
        "rxnorm": "http://www.nlm.nih.gov/research/umls/rxnorm",
        "PrescriptionCredential": "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/prescription/v1#PrescriptionCredential"
      }
    };
    testResultV1 = {
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "@vocab": "http://hl7.org/fhir/",
        "fhir": "http://hl7.org/fhir/",
        "loinc": "http://loinc.org",
        "TestResultCredential": "https://raw.githubusercontent.com/nfh-trust-labs/opencred-vc-schemas/main/schemas/test-result/v1#TestResultCredential"
      }
    };
  }
});

// ../vc-core/dist/document-loader.js
function createDocumentLoader(extraResolver) {
  return function documentLoader(url) {
    const bundled = BUNDLED_CONTEXTS.get(url);
    if (bundled) {
      return {
        contextUrl: null,
        documentUrl: url,
        document: bundled
      };
    }
    const resolver = defaultExtraResolver;
    if (resolver) {
      const extra = resolver(url);
      if (extra) {
        return {
          contextUrl: null,
          documentUrl: url,
          document: extra
        };
      }
    }
    throw new ContextNotFoundError(url);
  };
}
var BUNDLED_CONTEXTS, defaultExtraResolver;
var init_document_loader = __esm({
  "../vc-core/dist/document-loader.js"() {
    init_context_errors();
    init_types();
    init_context_data();
    BUNDLED_CONTEXTS = /* @__PURE__ */ new Map([
      // W3C + OpenCred base contexts
      [W3C_CREDENTIALS_V2_CONTEXT, credentialsV2],
      [DATA_INTEGRITY_V1_CONTEXT, dataIntegrityV1],
      // Referenced upstream contexts bundled at build time
      [TRACEABILITY_V1_CONTEXT, traceabilityV1],
      [OPEN_BADGES_V3_CONTEXT, openBadgesV3],
      // OpenCred-defined credential contexts (SHA-pinned to schema-sources.json)
      [OPENCRED_ELECTRICITY_V1_CONTEXT, electricityV1],
      [OPENCRED_IMMUNIZATION_V1_CONTEXT, immunizationV1],
      [OPENCRED_PRESCRIPTION_V1_CONTEXT, prescriptionV1],
      [OPENCRED_TEST_RESULT_V1_CONTEXT, testResultV1],
      [OPENCRED_INSURANCE_POLICY_V1_CONTEXT, insurancePolicyV1],
      [OPENCRED_FUNCTIONAL_IDENTITY_V1_CONTEXT, functionalIdentityV1],
      [OPENCRED_EMPLOYMENT_OFFER_LETTER_V1_CONTEXT, employmentOfferLetterV1],
      [OPENCRED_BUSINESS_ENTITY_V1_CONTEXT, businessEntityV1]
    ]);
    defaultExtraResolver = null;
  }
});

// ../vc-core/dist/index.js
var init_dist2 = __esm({
  "../vc-core/dist/index.js"() {
    init_types();
    init_context_generator();
    init_credential_builder();
    init_context_errors();
    init_document_loader();
  }
});
function sha256(data) {
  return new Uint8Array(createHash("sha256").update(data).digest());
}
function sha256Hex(data) {
  return createHash("sha256").update(data).digest("hex");
}
function sha384(data) {
  return new Uint8Array(createHash("sha384").update(data).digest());
}
var init_hash = __esm({
  "../crypto/dist/hash.js"() {
  }
});
function createJsonLdDocumentLoader() {
  const bundledLoader = createDocumentLoader();
  const loader = async (url) => {
    const result = bundledLoader(url);
    return {
      contextUrl: result.contextUrl ?? void 0,
      documentUrl: result.documentUrl,
      document: result.document
    };
  };
  return loader;
}
async function canonicalize(document, options) {
  const result = await jsonld.canonize(document, {
    algorithm: "URDNA2015",
    format: "application/n-quads",
    documentLoader: createJsonLdDocumentLoader(),
    safe: options?.strict ?? true
  });
  return result;
}
async function computeSigningInput(document, proofConfig, hashAlgorithm = "sha256", strict = true) {
  const hash = hashAlgorithm === "sha384" ? sha384 : sha256;
  const canonicalProofConfig = await canonicalize(proofConfig, { strict });
  const proofConfigHash = hash(canonicalProofConfig);
  const canonicalDocument = await canonicalize(document, { strict });
  const documentHash = hash(canonicalDocument);
  const result = new Uint8Array(proofConfigHash.length + documentHash.length);
  result.set(proofConfigHash, 0);
  result.set(documentHash, proofConfigHash.length);
  return result;
}
function multibaseDecode(encoded) {
  if (!encoded.startsWith("z")) {
    throw new CryptoError("Invalid multibase encoding: expected base58btc prefix 'z'");
  }
  const base58str = encoded.slice(1);
  const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = BigInt(0);
  for (const char of base58str) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) {
      throw new CryptoError("Invalid base58btc character");
    }
    num = num * 58n + BigInt(index);
  }
  const hex = num.toString(16);
  const paddedHex = hex.length % 2 ? "0" + hex : hex;
  const bytes = [];
  for (let i = 0; i < paddedHex.length; i += 2) {
    bytes.push(parseInt(paddedHex.slice(i, i + 2), 16));
  }
  let leadingZeros = 0;
  for (const char of base58str) {
    if (char === "1") {
      leadingZeros++;
    } else {
      break;
    }
  }
  const result = new Uint8Array(leadingZeros + bytes.length);
  result.set(bytes, leadingZeros);
  return result;
}
async function verifyProof(credential, options) {
  try {
    const { proof } = credential;
    if (!proof) {
      return { verified: false, error: "Credential has no proof" };
    }
    if (proof.type !== PROOF_TYPE) {
      return {
        verified: false,
        error: `Unsupported proof type: ${proof.type}`
      };
    }
    if (proof.cryptosuite !== CRYPTOSUITE) {
      return {
        verified: false,
        error: `Unsupported cryptosuite: ${proof.cryptosuite}`
      };
    }
    if (!proof.proofValue) {
      return { verified: false, error: "Proof has no proofValue" };
    }
    const signatureBytes = multibaseDecode(proof.proofValue);
    if (signatureBytes.length !== 64 && signatureBytes.length !== 96) {
      return {
        verified: false,
        error: "Invalid signature length: expected 64 (P-256) or 96 (P-384) bytes"
      };
    }
    const isP384 = signatureBytes.length === 96;
    const hashAlg = isP384 ? "sha384" : "sha256";
    const signAlg = isP384 ? "SHA384" : "SHA256";
    const publicKey = resolvePublicKey(credential, options);
    if (!publicKey) {
      return {
        verified: false,
        error: "Unable to resolve public key from verificationMethod"
      };
    }
    const { proof: _proof, ...unsignedDoc } = credential;
    const proofConfig = {
      "@context": credential["@context"],
      type: proof.type,
      cryptosuite: proof.cryptosuite,
      created: proof.created,
      verificationMethod: proof.verificationMethod,
      proofPurpose: proof.proofPurpose
    };
    if (proof.domain) {
      proofConfig.domain = proof.domain;
    }
    if (proof.challenge) {
      proofConfig.challenge = proof.challenge;
    }
    const dataToVerify = await computeSigningInput(unsignedDoc, proofConfig, hashAlg);
    const verifier = createVerify(signAlg);
    verifier.update(dataToVerify);
    const verified = verifier.verify({ key: publicKey, dsaEncoding: "ieee-p1363" }, signatureBytes);
    return verified ? { verified: true } : { verified: false, error: "Signature verification failed" };
  } catch (error) {
    if (error instanceof TypeError || error instanceof ReferenceError || error instanceof SyntaxError || error instanceof RangeError) {
      throw error;
    }
    return {
      verified: false,
      error: `Verification error: ${error instanceof Error ? error.message : "unknown error"}`
    };
  }
}
function resolvePublicKey(_credential, options) {
  if (options?.publicKey) {
    return options.publicKey;
  }
  return void 0;
}
var jsonld, CRYPTOSUITE, PROOF_TYPE;
var init_data_integrity = __esm({
  "../crypto/dist/data-integrity.js"() {
    init_dist();
    init_dist2();
    init_hash();
    jsonld = _jsonldNs.default ?? _jsonldNs;
    CRYPTOSUITE = "ecdsa-rdfc-2019";
    PROOF_TYPE = "DataIntegrityProof";
  }
});
async function verifyEdDsaProof(credential, options) {
  try {
    const { proof } = credential;
    if (!proof) {
      return { verified: false, error: "Credential has no proof" };
    }
    if (proof.type !== "DataIntegrityProof") {
      return { verified: false, error: `Unsupported proof type: ${proof.type}` };
    }
    if (proof.cryptosuite !== EDDSA_CRYPTOSUITE) {
      return { verified: false, error: `Unsupported cryptosuite: ${proof.cryptosuite}` };
    }
    if (!proof.proofValue) {
      return { verified: false, error: "Proof has no proofValue" };
    }
    const signatureBytes = multibaseDecode(proof.proofValue);
    if (signatureBytes.length !== ED25519_SIGNATURE_LENGTH) {
      return {
        verified: false,
        error: `Invalid Ed25519 signature length: expected ${ED25519_SIGNATURE_LENGTH} bytes, got ${signatureBytes.length}`
      };
    }
    const publicKey = resolvePublicKey2(options);
    if (!publicKey) {
      return {
        verified: false,
        error: "Unable to resolve public key from verificationMethod"
      };
    }
    const { proof: _proof, ...unsignedDoc } = credential;
    const proofConfig = {
      "@context": credential["@context"],
      type: proof.type,
      cryptosuite: proof.cryptosuite,
      created: proof.created,
      verificationMethod: proof.verificationMethod,
      proofPurpose: proof.proofPurpose
    };
    if (proof.domain) {
      proofConfig.domain = proof.domain;
    }
    if (proof.challenge) {
      proofConfig.challenge = proof.challenge;
    }
    const dataToVerify = await computeSigningInput(unsignedDoc, proofConfig, "sha256");
    const verified = verify(null, dataToVerify, publicKey, signatureBytes);
    return verified ? { verified: true } : { verified: false, error: "Signature verification failed" };
  } catch (error) {
    if (error instanceof TypeError || error instanceof ReferenceError || error instanceof SyntaxError || error instanceof RangeError) {
      throw error;
    }
    return {
      verified: false,
      error: `Verification error: ${error instanceof Error ? error.message : "unknown error"}`
    };
  }
}
function resolvePublicKey2(options) {
  if (options?.publicKey) {
    return options.publicKey;
  }
  return void 0;
}
var EDDSA_CRYPTOSUITE, ED25519_SIGNATURE_LENGTH;
var init_eddsa_data_integrity = __esm({
  "../crypto/dist/eddsa-data-integrity.js"() {
    init_data_integrity();
    EDDSA_CRYPTOSUITE = "eddsa-rdfc-2022";
    ED25519_SIGNATURE_LENGTH = 64;
  }
});

// ../crypto/dist/alg-mapping.js
var init_alg_mapping = __esm({
  "../crypto/dist/alg-mapping.js"() {
  }
});
var init_sd_jwt_vc_signing = __esm({
  "../crypto/dist/sd-jwt-vc-signing.js"() {
    init_alg_mapping();
  }
});
var init_vc_jwt_signing = __esm({
  "../crypto/dist/vc-jwt-signing.js"() {
    init_alg_mapping();
  }
});

// ../verification/dist/verifier.js
init_dist();

// ../crypto/dist/index.js
init_data_integrity();
init_eddsa_data_integrity();
init_hash();
init_alg_mapping();

// ../crypto/dist/jcs.js
init_hash();
function computeRevocationHash(credential) {
  const canonical = canonicalize$1(credential);
  return sha256Hex(canonical);
}
function extractRevocationHashFromStatusId(credential) {
  if (typeof credential !== "object" || credential === null)
    return null;
  const status = credential["credentialStatus"];
  if (typeof status !== "object" || status === null)
    return null;
  const rawId = status["id"];
  if (typeof rawId !== "string" || rawId.length === 0)
    return null;
  let parsed;
  try {
    parsed = new URL(rawId);
  } catch {
    return null;
  }
  const segments = parsed.pathname.split("/").filter((s) => s.length > 0);
  const last = segments[segments.length - 1];
  if (!last)
    return null;
  if (!/^[a-f0-9]{64}$/.test(last))
    return null;
  return last;
}
function resolveRevocationHash(credential) {
  const embedded = extractRevocationHashFromStatusId(credential);
  if (embedded !== null)
    return embedded;
  return computeRevocationHash(credential);
}

// ../crypto/dist/index.js
init_alg_mapping();

// ../crypto/dist/index.js
init_sd_jwt_vc_signing();
init_vc_jwt_signing();

// ../did/dist/did-key.js
init_dist();

// ../did/dist/multibase.js
var BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
var ALPHABET_MAP = /* @__PURE__ */ new Map();
for (let i = 0; i < BASE58_ALPHABET.length; i++) {
  ALPHABET_MAP.set(BASE58_ALPHABET[i], i);
}
function decodeBase58btc(encoded) {
  if (encoded.length === 0) {
    return new Uint8Array(0);
  }
  let leadingZeros = 0;
  for (const char of encoded) {
    if (char === "1")
      leadingZeros++;
    else
      break;
  }
  const size = Math.ceil(encoded.length * (Math.log(58) / Math.log(256)));
  const bytes = new Uint8Array(size);
  for (const char of encoded) {
    const value = ALPHABET_MAP.get(char);
    if (value === void 0) {
      throw new Error(`Invalid base58 character: ${char}`);
    }
    let carry = value;
    for (let j = size - 1; j >= 0; j--) {
      carry += 58 * bytes[j];
      bytes[j] = carry % 256;
      carry = Math.floor(carry / 256);
    }
  }
  let firstNonZero = 0;
  while (firstNonZero < bytes.length && bytes[firstNonZero] === 0) {
    firstNonZero++;
  }
  const result = new Uint8Array(leadingZeros + (bytes.length - firstNonZero));
  result.set(bytes.subarray(firstNonZero), leadingZeros);
  return result;
}

// ../did/dist/did-key.js
var P256_MULTICODEC_PREFIX = new Uint8Array([128, 36]);
var P384_MULTICODEC_PREFIX = new Uint8Array([129, 36]);
var ED25519_MULTICODEC_PREFIX = new Uint8Array([237, 1]);
var P256_COMPRESSED_KEY_LENGTH = 33;
var P384_COMPRESSED_KEY_LENGTH = 49;
var ED25519_PUBLIC_KEY_LENGTH = 32;
var DIDKeyResolver = class {
  async resolve(did) {
    if (!did || typeof did !== "string") {
      throw new DIDResolutionError("DID must be a non-empty string");
    }
    const parts = did.split(":");
    if (parts.length !== 3 || parts[0] !== "did") {
      throw new DIDResolutionError(`Invalid DID format: expected did:<method>:<id>`);
    }
    if (parts[1] !== "key") {
      throw new DIDResolutionError(`Unsupported DID method: ${parts[1]}`);
    }
    const multibaseKey = parts[2];
    if (!multibaseKey || !multibaseKey.startsWith("z")) {
      throw new DIDResolutionError("Only base58btc (z prefix) multibase encoding is supported");
    }
    let decoded;
    try {
      decoded = decodeBase58btc(multibaseKey.slice(1));
    } catch {
      throw new DIDResolutionError("Failed to decode multibase key");
    }
    if (decoded.length < 2) {
      throw new DIDResolutionError("Decoded key too short");
    }
    let expectedKeyLength;
    let isEd25519 = false;
    if (decoded[0] === P256_MULTICODEC_PREFIX[0] && decoded[1] === P256_MULTICODEC_PREFIX[1]) {
      expectedKeyLength = P256_COMPRESSED_KEY_LENGTH;
    } else if (decoded[0] === P384_MULTICODEC_PREFIX[0] && decoded[1] === P384_MULTICODEC_PREFIX[1]) {
      expectedKeyLength = P384_COMPRESSED_KEY_LENGTH;
    } else if (decoded[0] === ED25519_MULTICODEC_PREFIX[0] && decoded[1] === ED25519_MULTICODEC_PREFIX[1]) {
      expectedKeyLength = ED25519_PUBLIC_KEY_LENGTH;
      isEd25519 = true;
    } else {
      throw new DIDResolutionError("Unsupported key type: only P-256, P-384, and Ed25519 keys are supported");
    }
    const publicKeyBytes = decoded.slice(2);
    if (publicKeyBytes.length !== expectedKeyLength) {
      throw new DIDResolutionError(`Invalid key length: expected ${expectedKeyLength} bytes, got ${publicKeyBytes.length}`);
    }
    if (!isEd25519 && publicKeyBytes[0] !== 2 && publicKeyBytes[0] !== 3) {
      throw new DIDResolutionError("Invalid compressed key: must start with 0x02 or 0x03");
    }
    const verificationMethodId = `${did}#${multibaseKey}`;
    const verificationMethod = {
      id: verificationMethodId,
      type: "Multikey",
      controller: did,
      publicKeyMultibase: multibaseKey
    };
    const didDocument = {
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
      id: did,
      verificationMethod: [verificationMethod],
      authentication: [verificationMethodId],
      assertionMethod: [verificationMethodId],
      capabilityInvocation: [verificationMethodId],
      capabilityDelegation: [verificationMethodId]
    };
    return {
      didDocument,
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocumentMetadata: {}
    };
  }
};

// ../did/dist/did-jwk.js
init_dist();
var DIDJwkResolver = class {
  async resolve(did) {
    if (!did || typeof did !== "string") {
      throw new DIDResolutionError("DID must be a non-empty string");
    }
    const parts = did.split(":");
    if (parts.length !== 3 || parts[0] !== "did") {
      throw new DIDResolutionError("Invalid DID format: expected did:<method>:<id>");
    }
    if (parts[1] !== "jwk") {
      throw new DIDResolutionError(`Unsupported DID method: ${parts[1]}`);
    }
    const encoded = parts[2];
    if (!encoded) {
      throw new DIDResolutionError("Missing JWK data in did:jwk");
    }
    let jwk;
    try {
      const json = Buffer.from(encoded, "base64url").toString("utf-8");
      jwk = JSON.parse(json);
    } catch {
      throw new DIDResolutionError("Failed to decode JWK from did:jwk");
    }
    if (!jwk.kty) {
      throw new DIDResolutionError("Decoded JWK missing required 'kty' field");
    }
    const verificationMethodId = `${did}#0`;
    const verificationMethod = {
      id: verificationMethodId,
      type: "JsonWebKey",
      controller: did,
      publicKeyJwk: jwk
    };
    const didDocument = {
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
      id: did,
      verificationMethod: [verificationMethod],
      authentication: [verificationMethodId],
      assertionMethod: [verificationMethodId],
      capabilityInvocation: [verificationMethodId],
      capabilityDelegation: [verificationMethodId]
    };
    return {
      didDocument,
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocumentMetadata: {}
    };
  }
};

// ../did/dist/did-web.js
init_dist();
var FETCH_TIMEOUT_MS = 1e4;
function didWebToUrl(did) {
  if (!did || typeof did !== "string") {
    throw new DIDResolutionError("DID must be a non-empty string");
  }
  const parts = did.split(":");
  if (parts.length < 3 || parts[0] !== "did" || parts[1] !== "web") {
    throw new DIDResolutionError("Invalid did:web format");
  }
  const domain = parts[2].replace(/%3A/gi, ":");
  const pathSegments = parts.slice(3);
  if (pathSegments.length > 0) {
    return `https://${domain}/${pathSegments.join("/")}/did.json`;
  }
  return `https://${domain}/.well-known/did.json`;
}
var DIDWebResolver = class {
  fallback;
  constructor(fallback) {
    this.fallback = fallback;
  }
  async resolve(did) {
    if (!did || typeof did !== "string") {
      throw new DIDResolutionError("DID must be a non-empty string");
    }
    const parts = did.split(":");
    if (parts.length < 3 || parts[0] !== "did") {
      throw new DIDResolutionError("Invalid DID format: expected did:<method>:<id>");
    }
    if (parts[1] !== "web") {
      throw new DIDResolutionError(`Unsupported DID method: ${parts[1]}`);
    }
    const url = didWebToUrl(did);
    try {
      return await this.resolveViaHttps(did, url);
    } catch (httpError) {
      const isSsrf = httpError instanceof DIDResolutionError && httpError.message.includes("SSRF protection");
      if (isSsrf || !this.fallback) {
        throw httpError;
      }
      try {
        const fallbackResult = await this.fallback(did);
        if (fallbackResult)
          return fallbackResult;
      } catch {
      }
      throw httpError;
    }
  }
  async resolveViaHttps(did, url) {
    const parsedUrl = new URL(url);
    const hostname = parsedUrl.hostname;
    const [v4Result, v6Result] = await Promise.allSettled([
      promises.resolve4(hostname),
      promises.resolve6(hostname)
    ]);
    const addresses = [
      ...v4Result.status === "fulfilled" ? v4Result.value : [],
      ...v6Result.status === "fulfilled" ? v6Result.value : []
    ];
    if (addresses.length === 0) {
      throw new DIDResolutionError(`Failed to resolve hostname: ${hostname}`);
    }
    for (const ip of addresses) {
      if (isPrivateIP(ip)) {
        throw new DIDResolutionError("SSRF protection: DID document host resolves to a private IP");
      }
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let response;
    try {
      response = await fetch(url, {
        signal: controller.signal,
        redirect: "error",
        headers: {
          Accept: "application/did+ld+json, application/json"
        }
      });
    } catch (err) {
      if (err instanceof Error && err.name === "AbortError") {
        throw new DIDResolutionError(`Timeout fetching DID document from: ${url}`);
      }
      throw new DIDResolutionError(`Failed to fetch DID document from: ${url}`);
    } finally {
      clearTimeout(timeout);
    }
    if (!response.ok) {
      throw new DIDResolutionError(`HTTP ${String(response.status)} fetching DID document from: ${url}`);
    }
    let didDocument;
    try {
      didDocument = await response.json();
    } catch {
      throw new DIDResolutionError("Failed to parse DID document as JSON");
    }
    if (didDocument.id !== did) {
      throw new DIDResolutionError(`DID document ID mismatch: expected ${did}, got ${String(didDocument.id)}`);
    }
    return {
      didDocument,
      didResolutionMetadata: { contentType: "application/did+ld+json" },
      didDocumentMetadata: {}
    };
  }
};

// ../did/dist/composite-resolver.js
init_dist();
var CompositeDIDResolver = class {
  resolvers;
  constructor(resolvers) {
    this.resolvers = resolvers;
  }
  async resolve(did) {
    if (!did || typeof did !== "string") {
      throw new DIDResolutionError("DID must be a non-empty string");
    }
    const parts = did.split(":");
    if (parts.length < 3 || parts[0] !== "did") {
      throw new DIDResolutionError("Invalid DID format: expected did:<method>:<id>");
    }
    const method = parts[1];
    const resolver = this.resolvers.get(method);
    if (!resolver) {
      throw new DIDResolutionError(`No resolver registered for DID method: ${method}`);
    }
    return resolver.resolve(did);
  }
};

// ../verification/dist/data-integrity.js
init_dist2();
function publicKeyFromMultibase(multibaseKey) {
  try {
    const decoded = multibaseDecode(multibaseKey);
    if (decoded.length < 2) {
      return null;
    }
    if (decoded[0] === 237 && decoded[1] === 1) {
      const rawKey = decoded.slice(2);
      if (rawKey.length !== 32) {
        return null;
      }
      return publicKeyFromRawEd25519(rawKey);
    }
    if (decoded[0] === 128 && decoded[1] === 36) {
      const compressedKey = decoded.slice(2);
      if (compressedKey.length !== 33) {
        return null;
      }
      return publicKeyFromCompressedP256(compressedKey);
    }
    if (decoded[0] === 129 && decoded[1] === 36) {
      const compressedKey = decoded.slice(2);
      if (compressedKey.length !== 49) {
        return null;
      }
      return publicKeyFromCompressedP384(compressedKey);
    }
    return null;
  } catch {
    return null;
  }
}
function publicKeyFromRawEd25519(rawKey) {
  const ed25519SpkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  const spki = Buffer.concat([ed25519SpkiPrefix, rawKey]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}
function publicKeyFromCompressedP256(compressedKey) {
  const ecPublicKeyOid = Buffer.from([6, 7, 42, 134, 72, 206, 61, 2, 1]);
  const p256Oid = Buffer.from([6, 8, 42, 134, 72, 206, 61, 3, 1, 7]);
  const algSequence = Buffer.concat([
    Buffer.from([48, ecPublicKeyOid.length + p256Oid.length]),
    ecPublicKeyOid,
    p256Oid
  ]);
  const bitString = Buffer.concat([
    Buffer.from([3, compressedKey.length + 1, 0]),
    compressedKey
  ]);
  const spki = Buffer.concat([
    Buffer.from([48, algSequence.length + bitString.length]),
    algSequence,
    bitString
  ]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}
function publicKeyFromCompressedP384(compressedKey) {
  const ecPublicKeyOid = Buffer.from([6, 7, 42, 134, 72, 206, 61, 2, 1]);
  const p384Oid = Buffer.from([6, 5, 43, 129, 4, 0, 34]);
  const algSequence = Buffer.concat([
    Buffer.from([48, ecPublicKeyOid.length + p384Oid.length]),
    ecPublicKeyOid,
    p384Oid
  ]);
  const bitString = Buffer.concat([
    Buffer.from([3, compressedKey.length + 1, 0]),
    compressedKey
  ]);
  const spki = Buffer.concat([
    Buffer.from([48, algSequence.length + bitString.length]),
    algSequence,
    bitString
  ]);
  return createPublicKey({ key: spki, format: "der", type: "spki" });
}

// ../verification/dist/data-integrity.js
var SUPPORTED_CRYPTOSUITES = ["ecdsa-rdfc-2019", "eddsa-rdfc-2022"];
async function verifyDataIntegrity(credential, didResolver) {
  const proof = credential.proof;
  if (!proof) {
    return { name: "signature", passed: false, detail: "No proof found on credential" };
  }
  if (proof.type !== "DataIntegrityProof") {
    return { name: "signature", passed: false, detail: `Unsupported proof type: ${proof.type}` };
  }
  const cryptosuite = proof.cryptosuite;
  if (!SUPPORTED_CRYPTOSUITES.includes(cryptosuite)) {
    return {
      name: "signature",
      passed: false,
      detail: `Unsupported cryptosuite: ${String(proof.cryptosuite)}`
    };
  }
  const publicKey = await resolvePublicKeyFromVerificationMethod(proof.verificationMethod, didResolver);
  if (!publicKey) {
    return {
      name: "signature",
      passed: false,
      detail: "Unable to resolve public key from verificationMethod"
    };
  }
  const verifyFn = cryptosuite === "eddsa-rdfc-2022" ? verifyEdDsaProof : verifyProof;
  try {
    const result = await verifyFn(credential, { publicKey });
    if (result.verified) {
      return { name: "signature", passed: true };
    }
    return {
      name: "signature",
      passed: false,
      detail: result.error ?? "Signature verification failed"
    };
  } catch (error) {
    if (error instanceof ContextNotFoundError) {
      return {
        name: "signature",
        passed: false,
        detail: `Missing JSON-LD context: ${error.contextUrl}. Import this context before verifying, or ask the issuer to use VC-JWT format.`
      };
    }
    throw error;
  }
}
async function resolvePublicKeyFromVerificationMethod(verificationMethod, didResolver) {
  if (!didResolver) {
    return void 0;
  }
  if (typeof verificationMethod !== "string" || verificationMethod.length === 0) {
    return void 0;
  }
  const did = verificationMethod.split("#")[0];
  if (!did) {
    return void 0;
  }
  let resolution;
  try {
    resolution = await didResolver.resolve(did);
  } catch {
    return void 0;
  }
  if (!resolution.didDocument?.verificationMethod?.length) {
    return void 0;
  }
  const fragmentId = verificationMethod.includes("#") ? `#${verificationMethod.split("#").slice(1).join("#")}` : void 0;
  const vm = resolution.didDocument.verificationMethod.find((m) => m.id === verificationMethod || fragmentId !== void 0 && m.id === fragmentId);
  if (!vm) {
    return void 0;
  }
  if (vm.publicKeyMultibase) {
    const key = publicKeyFromMultibase(vm.publicKeyMultibase);
    return key ?? void 0;
  }
  if (vm.publicKeyJwk) {
    try {
      return createPublicKey({ key: vm.publicKeyJwk, format: "jwk" });
    } catch {
      return void 0;
    }
  }
  return void 0;
}
init_dist();
var ALLOWED_JWS_ALGORITHMS = ["ES256", "ES384", "PS256", "EdDSA"];
async function verifyJwsProof(jwsString, didResolver) {
  assertJwtSize(jwsString);
  const parts = jwsString.split(".");
  if (parts.length !== 3) {
    return {
      name: "signature",
      passed: false,
      detail: "Invalid JWS: expected 3 dot-separated parts"
    };
  }
  let header;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
  } catch {
    return { name: "signature", passed: false, detail: "Failed to decode JWS protected header" };
  }
  const kid = header.kid;
  if (!kid) {
    return { name: "signature", passed: false, detail: "JWS header missing 'kid'" };
  }
  const alg = header.alg;
  if (!alg) {
    return { name: "signature", passed: false, detail: "JWS header missing 'alg'" };
  }
  if (!ALLOWED_JWS_ALGORITHMS.includes(alg)) {
    return {
      name: "signature",
      passed: false,
      detail: `JWS 'alg' not permitted: ${alg}. Allowed: ${ALLOWED_JWS_ALGORITHMS.join(", ")}`
    };
  }
  const did = kid.split("#")[0];
  const resolver = didResolver ?? new DIDJwkResolver();
  let resolution;
  try {
    resolution = await resolver.resolve(did);
  } catch {
    return { name: "signature", passed: false, detail: "Failed to resolve DID from kid" };
  }
  if (!resolution.didDocument) {
    return { name: "signature", passed: false, detail: "Failed to resolve DID document" };
  }
  const vm = resolution.didDocument.verificationMethod?.find((m) => m.id === kid || m.id === `#${kid.split("#")[1]}`);
  if (!vm?.publicKeyJwk) {
    return {
      name: "signature",
      passed: false,
      detail: "Verification method not found or missing JWK"
    };
  }
  let publicKey;
  try {
    publicKey = await importJWK(vm.publicKeyJwk, alg);
  } catch {
    return { name: "signature", passed: false, detail: "Failed to import public key from JWK" };
  }
  try {
    await compactVerify(jwsString, publicKey, {
      algorithms: ALLOWED_JWS_ALGORITHMS
    });
    return { name: "signature", passed: true };
  } catch {
    return { name: "signature", passed: false, detail: "JWS signature verification failed" };
  }
}

// ../verification/dist/vc-jwt.js
init_dist();
var ALLOWED_ALGORITHMS = ["ES256", "ES384", "ES512", "EdDSA"];
async function verifyVcJwt(jwt, didResolver) {
  try {
    assertJwtSize(jwt);
    const header = jose2.decodeProtectedHeader(jwt);
    if (!header.alg) {
      return {
        check: { name: "signature", passed: false, detail: "JWT missing 'alg' header" },
        payload: null
      };
    }
    const payload = jose2.decodeJwt(jwt);
    if (!payload.iss) {
      return {
        check: { name: "signature", passed: false, detail: "JWT missing 'iss' claim" },
        payload: null
      };
    }
    const publicKey = await resolveIssuerKey(payload.iss, header, didResolver);
    if (!publicKey) {
      return {
        check: {
          name: "signature",
          passed: false,
          detail: `Unable to resolve public key for issuer: ${payload.iss}`
        },
        payload
      };
    }
    await jose2.jwtVerify(jwt, publicKey, {
      algorithms: ALLOWED_ALGORITHMS
    });
    return {
      check: { name: "signature", passed: true },
      payload
    };
  } catch (error) {
    if (error instanceof VerificationError) {
      return {
        check: { name: "signature", passed: false, detail: error.message },
        payload: null
      };
    }
    const detail = error instanceof Error ? error.message : "JWT verification failed";
    return {
      check: { name: "signature", passed: false, detail },
      payload: null
    };
  }
}
function extractVcJwtCredentialFields(payload) {
  const isDm11 = payload.vc !== void 0;
  const source = isDm11 ? payload.vc : payload;
  const validFrom = payload.nbf ? new Date(payload.nbf * 1e3).toISOString() : source["validFrom"];
  const validUntil = payload.exp ? new Date(payload.exp * 1e3).toISOString() : source["validUntil"];
  const credentialStatus = source["credentialStatus"];
  return {
    validFrom,
    validUntil,
    credentialStatus,
    issuer: payload.iss,
    credential: isDm11 ? payload.vc : payload
  };
}
function crossValidateVcJwtClaims(payload) {
  const errors = [];
  if (!payload.vc) {
    return errors;
  }
  const vcId = payload.vc["id"];
  if (payload.jti && vcId && payload.jti !== vcId) {
    errors.push(`JWT jti claim "${payload.jti}" does not match vc.id "${vcId}"`);
  }
  const credentialSubject = payload.vc["credentialSubject"];
  const subjectId = credentialSubject?.["id"];
  if (payload.sub && subjectId && payload.sub !== subjectId) {
    errors.push(`JWT sub claim "${payload.sub}" does not match vc.credentialSubject.id "${subjectId}"`);
  }
  return errors;
}
async function resolveIssuerKey(issuer, header, didResolver) {
  if (!didResolver || !issuer.startsWith("did:")) {
    return null;
  }
  try {
    const resolution = await didResolver.resolve(issuer);
    if (!resolution.didDocument?.verificationMethod?.length) {
      return null;
    }
    const vms = resolution.didDocument.verificationMethod;
    const targetId = header.kid;
    const vm = targetId ? vms.find((m) => m.id === targetId) : vms[0];
    if (!vm) {
      return null;
    }
    if (vm.publicKeyJwk) {
      return createPublicKey({ key: vm.publicKeyJwk, format: "jwk" });
    }
    if (vm.publicKeyMultibase) {
      return publicKeyFromMultibase(vm.publicKeyMultibase);
    }
    return null;
  } catch {
    return null;
  }
}

// ../verification/dist/sd-jwt-vc.js
init_dist();
var ALLOWED_ALGORITHMS2 = ["ES256", "ES384", "ES512", "EdDSA"];
function parseSdJwtVc(sdJwtVc) {
  assertJwtSize(sdJwtVc);
  const parts = sdJwtVc.split("~");
  if (parts.length < 2) {
    throw new Error("Invalid SD-JWT VC format: must contain at least issuer JWT and one separator");
  }
  const issuerJwt = parts[0];
  const disclosures = [];
  let keyBindingJwt;
  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    if (part === "") {
      continue;
    }
    if (i === parts.length - 1 && part.split(".").length === 3) {
      keyBindingJwt = part;
    } else {
      disclosures.push(part);
    }
  }
  return { issuerJwt, disclosures, keyBindingJwt };
}
function decodeDisclosure(disclosure) {
  const json = Buffer.from(disclosure, "base64url").toString("utf-8");
  const parsed = JSON.parse(json);
  if (!Array.isArray(parsed) || parsed.length !== 2 && parsed.length !== 3) {
    throw new Error("Invalid disclosure format: expected [salt, name, value] or [salt, value]");
  }
  if (parsed.length === 3) {
    return [String(parsed[0]), String(parsed[1]), parsed[2]];
  }
  return [String(parsed[0]), parsed[1]];
}
async function processDisclosures(payload, disclosures) {
  const algorithm = payload["_sd_alg"];
  const disclosureMap = /* @__PURE__ */ new Map();
  for (const d of disclosures) {
    const hash = await computeDisclosureDigest(d, algorithm);
    disclosureMap.set(hash, decodeDisclosure(d));
  }
  const used = /* @__PURE__ */ new Set();
  const walk = (value) => {
    if (Array.isArray(value)) {
      const next = [];
      for (const item of value) {
        if (typeof item === "object" && item !== null && !Array.isArray(item) && Object.keys(item).length === 1 && typeof item["..."] === "string") {
          const digest = item["..."];
          const d = disclosureMap.get(digest);
          if (d && d.length === 2) {
            used.add(digest);
            next.push(walk(d[1]));
          }
          continue;
        }
        next.push(walk(item));
      }
      return next;
    }
    if (typeof value === "object" && value !== null) {
      const obj = value;
      const out = {};
      for (const [k, v] of Object.entries(obj)) {
        if (k === "_sd" || k === "_sd_alg")
          continue;
        out[k] = walk(v);
      }
      const sdDigests = obj["_sd"] ?? [];
      for (const digest of sdDigests) {
        const d = disclosureMap.get(digest);
        if (!d)
          continue;
        if (d.length !== 3)
          continue;
        const [, name, disclosedValue] = d;
        used.add(digest);
        out[name] = walk(disclosedValue);
      }
      return out;
    }
    return value;
  };
  const result = walk(payload);
  if (used.size < disclosureMap.size) {
    const unused = disclosureMap.size - used.size;
    throw new Error(`SD-JWT VC verification rejected: ${unused} supplied disclosure(s) are not referenced by any _sd digest`);
  }
  return result;
}
async function computeDisclosureDigest(disclosure, algorithm) {
  const alg = algorithm ?? "sha-256";
  const encoder = new TextEncoder();
  const data = encoder.encode(disclosure);
  const hashBuffer = await globalThis.crypto.subtle.digest(alg === "sha-256" ? "SHA-256" : alg.toUpperCase(), data);
  return Buffer.from(new Uint8Array(hashBuffer)).toString("base64url");
}
async function verifySdJwtVc(sdJwtVc, didResolver, options) {
  try {
    const { issuerJwt, disclosures, keyBindingJwt } = parseSdJwtVc(sdJwtVc);
    const header = jose2.decodeProtectedHeader(issuerJwt);
    if (!header.alg) {
      return {
        check: { name: "signature", passed: false, detail: "SD-JWT missing 'alg' header" },
        payload: null,
        resolvedClaims: null
      };
    }
    const payload = jose2.decodeJwt(issuerJwt);
    if (!payload.iss) {
      return {
        check: { name: "signature", passed: false, detail: "SD-JWT missing 'iss' claim" },
        payload: null,
        resolvedClaims: null
      };
    }
    const vctCheck = validateVctClaim(payload, options?.expectedVct);
    if (!vctCheck.passed) {
      return {
        check: vctCheck,
        payload,
        resolvedClaims: null
      };
    }
    const publicKey = await resolveIssuerKeyForSdJwt(payload.iss, header, didResolver);
    if (!publicKey) {
      return {
        check: {
          name: "signature",
          passed: false,
          detail: `Unable to resolve public key for issuer: ${payload.iss}`
        },
        payload,
        resolvedClaims: null
      };
    }
    await jose2.jwtVerify(issuerJwt, publicKey, {
      algorithms: ALLOWED_ALGORITHMS2
    });
    if (keyBindingJwt) {
      const kbCheck = await verifyKeyBindingJwt(keyBindingJwt, payload, sdJwtVc, options);
      if (!kbCheck.passed) {
        return {
          check: kbCheck,
          payload,
          resolvedClaims: null
        };
      }
    }
    const resolvedClaims = await processDisclosures(payload, disclosures);
    return {
      check: { name: "signature", passed: true },
      payload,
      resolvedClaims
    };
  } catch (error) {
    const detail = error instanceof Error ? error.message : "SD-JWT VC verification failed";
    return {
      check: { name: "signature", passed: false, detail },
      payload: null,
      resolvedClaims: null
    };
  }
}
function validateVctClaim(payload, expectedVct) {
  if (!payload.vct || typeof payload.vct !== "string") {
    return {
      name: "vct",
      passed: false,
      detail: "SD-JWT VC missing required 'vct' claim"
    };
  }
  if (expectedVct !== void 0) {
    const expected = Array.isArray(expectedVct) ? expectedVct : [expectedVct];
    if (!expected.includes(payload.vct)) {
      return {
        name: "vct",
        passed: false,
        detail: `SD-JWT VC 'vct' claim '${payload.vct}' does not match expected type(s): ${expected.join(", ")}`
      };
    }
  }
  return { name: "vct", passed: true };
}
async function verifyKeyBindingJwt(keyBindingJwt, issuerPayload, fullSdJwtVc, options) {
  try {
    const cnf = issuerPayload["cnf"];
    if (!cnf?.jwk) {
      return {
        name: "key_binding",
        passed: false,
        detail: "SD-JWT VC missing 'cnf' claim with holder public key for Key Binding verification"
      };
    }
    const kbHeader = jose2.decodeProtectedHeader(keyBindingJwt);
    if (kbHeader.typ !== "kb+jwt") {
      return {
        name: "key_binding",
        passed: false,
        detail: `Key Binding JWT 'typ' header must be 'kb+jwt', got '${kbHeader.typ ?? "undefined"}'`
      };
    }
    const holderKey = await jose2.importJWK(cnf.jwk, kbHeader.alg);
    const { payload: kbPayload } = await jose2.jwtVerify(keyBindingJwt, holderKey, {
      algorithms: ALLOWED_ALGORITHMS2
    });
    const sdJwtWithoutKb = fullSdJwtVc.substring(0, fullSdJwtVc.lastIndexOf(keyBindingJwt));
    const sdAlg = issuerPayload["_sd_alg"];
    const expectedSdHash = computeSdHash(sdJwtWithoutKb, sdAlg);
    if (kbPayload["sd_hash"] !== expectedSdHash) {
      return {
        name: "key_binding",
        passed: false,
        detail: "Key Binding JWT 'sd_hash' does not match the SD-JWT content"
      };
    }
    if (options?.expectedAudience) {
      const aud = kbPayload.aud;
      const audMatch = Array.isArray(aud) ? aud.includes(options.expectedAudience) : aud === options.expectedAudience;
      if (!audMatch) {
        return {
          name: "key_binding",
          passed: false,
          detail: `Key Binding JWT 'aud' does not match expected audience '${options.expectedAudience}'`
        };
      }
    }
    if (options?.expectedNonce && kbPayload["nonce"] !== options.expectedNonce) {
      return {
        name: "key_binding",
        passed: false,
        detail: "Key Binding JWT 'nonce' does not match expected nonce"
      };
    }
    return { name: "key_binding", passed: true };
  } catch (error) {
    const detail = error instanceof Error ? `Key Binding JWT verification failed: ${error.message}` : "Key Binding JWT verification failed";
    return { name: "key_binding", passed: false, detail };
  }
}
function computeSdHash(sdJwtWithoutKb, algorithm) {
  const alg = algorithm ?? "sha-256";
  const nodeAlg = alg === "sha-256" ? "sha256" : alg.replace(/-/g, "");
  const hash = createHash(nodeAlg).update(sdJwtWithoutKb, "ascii").digest();
  return Buffer.from(hash).toString("base64url");
}
function extractSdJwtVcCredentialFields(payload, resolvedClaims) {
  const validFrom = payload.nbf ? new Date(payload.nbf * 1e3).toISOString() : resolvedClaims["validFrom"];
  const validUntil = payload.exp ? new Date(payload.exp * 1e3).toISOString() : resolvedClaims["validUntil"];
  const credentialStatus = resolvedClaims["credentialStatus"] ?? payload["status"];
  return {
    validFrom,
    validUntil,
    credentialStatus,
    issuer: payload.iss
  };
}
async function resolveIssuerKeyForSdJwt(issuer, header, didResolver) {
  if (!didResolver || !issuer.startsWith("did:")) {
    return null;
  }
  try {
    const resolution = await didResolver.resolve(issuer);
    if (!resolution.didDocument?.verificationMethod?.length) {
      return null;
    }
    const vms = resolution.didDocument.verificationMethod;
    const targetId = header.kid;
    const vm = targetId ? vms.find((m) => m.id === targetId) : vms[0];
    if (!vm) {
      return null;
    }
    if (vm.publicKeyJwk) {
      return createPublicKey({ key: vm.publicKeyJwk, format: "jwk" });
    }
    if (vm.publicKeyMultibase) {
      return publicKeyFromMultibase(vm.publicKeyMultibase);
    }
    return null;
  } catch {
    return null;
  }
}
init_dist();
var gunzip = promisify(gunzip$1);
var MAX_COMPRESSED_SIZE = 1048576;
function checkDates(validFrom, validUntil, now = /* @__PURE__ */ new Date()) {
  if (validFrom) {
    const from = new Date(validFrom);
    if (isNaN(from.getTime())) {
      return { name: "date", passed: false, detail: "Invalid validFrom date" };
    }
    if (now < from) {
      return {
        name: "date",
        passed: false,
        detail: `Credential not yet valid (validFrom: ${validFrom})`
      };
    }
  }
  if (validUntil) {
    const until = new Date(validUntil);
    if (isNaN(until.getTime())) {
      return { name: "date", passed: false, detail: "Invalid validUntil date" };
    }
    if (now > until) {
      return {
        name: "date",
        passed: false,
        detail: `Credential expired (validUntil: ${validUntil})`
      };
    }
  }
  return { name: "date", passed: true };
}
async function checkRevocation(credential, dediClient) {
  try {
    const hash = resolveRevocationHash(credential);
    const record = await dediClient.queryRevocationHash(hash);
    if (record.revoked) {
      return {
        name: "revocation",
        passed: false,
        detail: `Credential revoked${record.revokedAt ? ` at ${record.revokedAt}` : ""}`
      };
    }
    return { name: "revocation", passed: true };
  } catch {
    return {
      name: "revocation",
      passed: false,
      detail: "Unable to check revocation status: DeDi service unavailable"
    };
  }
}
var PRIVATE_HOSTNAMES = /* @__PURE__ */ new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "[::1]"
]);
function validateStatusListUrl(raw, allowedDomains) {
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { valid: false, detail: "Invalid status list URL" };
  }
  if (parsed.protocol !== "https:") {
    return { valid: false, detail: "Status list URL must use HTTPS" };
  }
  const hostname = parsed.hostname.toLowerCase();
  if (PRIVATE_HOSTNAMES.has(hostname)) {
    return { valid: false, detail: "Status list URL points to a private/loopback host" };
  }
  const isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  const isIPv6 = hostname.startsWith("[") || hostname.includes(":");
  if (isIPv4 || isIPv6) {
    const bare = hostname.replace(/^\[|\]$/g, "");
    if (isPrivateIP(bare)) {
      return { valid: false, detail: "Status list URL points to a private/reserved IP" };
    }
  }
  if (allowedDomains && allowedDomains.length > 0) {
    const allowed = allowedDomains.some((d) => hostname === d.toLowerCase() || hostname.endsWith(`.${d.toLowerCase()}`));
    if (!allowed) {
      return { valid: false, detail: "Status list URL domain is not on the allowlist" };
    }
  }
  return { valid: true, url: parsed.toString(), hostname };
}
async function resolveAndValidateIp(hostname) {
  let addresses = [];
  let family = 4;
  try {
    addresses = await resolve4(hostname);
  } catch {
  }
  if (addresses.length === 0) {
    try {
      addresses = await resolve6(hostname);
      family = 6;
    } catch {
      throw new Error(`DNS resolution failed for ${hostname}`);
    }
  }
  if (addresses.length === 0) {
    throw new Error(`DNS resolution failed for ${hostname}`);
  }
  for (const addr of addresses) {
    if (isPrivateIP(addr)) {
      throw new Error(`DNS resolved to private/reserved IP for ${hostname}`);
    }
  }
  return { address: addresses[0], family };
}
async function checkBitstringStatusList(credentialStatus, options = {}) {
  try {
    const statusListIndex = credentialStatus["statusListIndex"];
    const statusListCredential = credentialStatus["statusListCredential"];
    if (statusListIndex === void 0 || statusListCredential === void 0) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: "Missing statusListIndex or statusListCredential in credentialStatus"
      };
    }
    const index = Number(statusListIndex);
    if (!Number.isInteger(index) || index < 0) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `Invalid statusListIndex: ${String(statusListIndex)}`
      };
    }
    const urlValidation = validateStatusListUrl(String(statusListCredential), options.allowedDomains);
    if (!urlValidation.valid) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: urlValidation.detail
      };
    }
    let fetchUrl = urlValidation.url;
    const fetchHeaders = {};
    const parsedUrl = new URL(urlValidation.url);
    const hostname = parsedUrl.hostname;
    if (!isIP(hostname)) {
      const resolved = await resolveAndValidateIp(hostname);
      const pinnedUrl = new URL(urlValidation.url);
      if (resolved.family === 6) {
        pinnedUrl.hostname = `[${resolved.address}]`;
      } else {
        pinnedUrl.hostname = resolved.address;
      }
      fetchUrl = pinnedUrl.toString();
      fetchHeaders["Host"] = hostname;
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1e4);
    let statusListVC;
    try {
      const response = await globalThis.fetch(fetchUrl, {
        redirect: "error",
        // Prevent redirect-based SSRF
        headers: fetchHeaders,
        signal: controller.signal
      });
      if (!response.ok) {
        return {
          name: "bitstringStatus",
          passed: false,
          detail: `Failed to fetch status list: HTTP ${response.status}`
        };
      }
      statusListVC = await response.json();
    } finally {
      clearTimeout(timer);
    }
    if (options.didResolver) {
      const proofCheck = await verifyDataIntegrity(statusListVC, options.didResolver);
      if (!proofCheck.passed) {
        return {
          name: "bitstringStatus",
          passed: false,
          detail: `Status list credential proof invalid: ${proofCheck.detail ?? "verification failed"}`
        };
      }
    }
    const subject = statusListVC["credentialSubject"];
    if (!subject) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: "Status list credential missing credentialSubject"
      };
    }
    const encodedList = subject["encodedList"];
    if (!encodedList) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: "Status list credential missing encodedList"
      };
    }
    const compressed = Buffer.from(encodedList, "base64");
    if (compressed.length > MAX_COMPRESSED_SIZE) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `Compressed encodedList exceeds maximum size (${MAX_COMPRESSED_SIZE} bytes)`
      };
    }
    const bitstring = await gunzip(compressed);
    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;
    if (byteIndex >= bitstring.length) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `statusListIndex ${index} out of range`
      };
    }
    const isRevoked = (bitstring[byteIndex] & 128 >> bitIndex) !== 0;
    if (isRevoked) {
      return {
        name: "bitstringStatus",
        passed: false,
        detail: `Credential revoked (statusListIndex: ${index})`
      };
    }
    return { name: "bitstringStatus", passed: true };
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unable to check BitstringStatusList";
    return {
      name: "bitstringStatus",
      passed: false,
      detail: message
    };
  }
}
function spkiFingerprint(key) {
  const der = key.export({ format: "der", type: "spki" });
  return createHash("sha256").update(der).digest("hex");
}
async function resolveDidPublicKey(verificationMethod, resolver) {
  if (!resolver || typeof verificationMethod !== "string" || verificationMethod.length === 0) {
    return null;
  }
  const did = verificationMethod.split("#")[0];
  if (!did) {
    return null;
  }
  let result;
  try {
    result = await resolver.resolve(did);
  } catch {
    return null;
  }
  const doc = result.didDocument;
  if (!doc || !doc.verificationMethod || doc.verificationMethod.length === 0) {
    return null;
  }
  const fragmentId = verificationMethod.includes("#") ? `#${verificationMethod.split("#").slice(1).join("#")}` : void 0;
  const vm = doc.verificationMethod.find((v) => v.id === verificationMethod || fragmentId !== void 0 && v.id === fragmentId);
  if (!vm) {
    return null;
  }
  if (vm.publicKeyMultibase) {
    return publicKeyFromMultibase(vm.publicKeyMultibase) ?? null;
  }
  if (vm.publicKeyJwk) {
    try {
      return createPublicKey({ key: vm.publicKeyJwk, format: "jwk" });
    } catch {
      return null;
    }
  }
  return null;
}
function parseX5cCert(base64Der) {
  const pem = `-----BEGIN CERTIFICATE-----
${base64Der}
-----END CERTIFICATE-----`;
  return new X509Certificate(pem);
}
function checkLeafKeyUsage(cert) {
  const raw = cert.raw;
  const keyUsageOid = Buffer.from([85, 29, 15]);
  const oidIdx = raw.indexOf(keyUsageOid);
  if (oidIdx === -1) {
    return null;
  }
  const searchStart = oidIdx + 3;
  const searchEnd = Math.min(searchStart + 20, raw.length);
  for (let i = searchStart; i < searchEnd - 2; i++) {
    if (raw[i] === 3 && raw[i + 1] >= 2 && raw[i + 1] <= 4) {
      const usageByte = raw[i + 3];
      if (usageByte === void 0) {
        return null;
      }
      return (usageByte & 128) !== 0;
    }
  }
  return null;
}
function checkKeyBinding(leafCert, didPublicKey) {
  try {
    return spkiFingerprint(leafCert.publicKey) === spkiFingerprint(didPublicKey);
  } catch {
    return false;
  }
}
function checkChainTemporal(certs, proofTime) {
  for (let i = 0; i < certs.length; i++) {
    const cert = certs[i];
    const notBefore = new Date(cert.validFrom);
    const notAfter = new Date(cert.validTo);
    const label = i === 0 ? "Leaf (DSC)" : `Chain certificate [${i}]`;
    if (proofTime < notBefore) {
      return `${label} was not yet valid at credential signing time (notBefore: ${cert.validFrom})`;
    }
    if (proofTime > notAfter) {
      return `${label} had expired at credential signing time (notAfter: ${cert.validTo})`;
    }
  }
  return null;
}
function checkChainSignatures(certs) {
  for (let i = 0; i < certs.length - 1; i++) {
    const child = certs[i];
    const parent = certs[i + 1];
    if (!child.checkIssued(parent)) {
      return `Certificate [${i}] was not issued by certificate [${i + 1}] (issuer/subject mismatch)`;
    }
    try {
      if (!child.verify(parent.publicKey)) {
        return `Certificate [${i}] signature does not verify against certificate [${i + 1}]`;
      }
    } catch {
      return `Certificate [${i}] signature verification failed against certificate [${i + 1}]`;
    }
  }
  return null;
}
function findAnchor(chain, trustAnchors) {
  if (chain.length === 0 || trustAnchors.length === 0) {
    return null;
  }
  const topOfChain = chain[chain.length - 1];
  for (const anchor of trustAnchors) {
    if (anchor.subject === topOfChain.subject && anchor.fingerprint256 === topOfChain.fingerprint256) {
      return anchor;
    }
  }
  for (const anchor of trustAnchors) {
    try {
      if (topOfChain.checkIssued(anchor) && topOfChain.verify(anchor.publicKey)) {
        return anchor;
      }
    } catch {
    }
  }
  return null;
}
async function checkX509Chain(credential, options = {}) {
  const proof = credential["proof"];
  if (!proof) {
    return { name: "x509-chain", passed: true, detail: "No proof \u2014 X.509 chain check skipped" };
  }
  const x5c = proof["x5c"];
  if (!x5c || !Array.isArray(x5c) || x5c.length === 0) {
    return {
      name: "x509-chain",
      passed: true,
      detail: "No x5c certificate chain \u2014 not a DSC-backed credential"
    };
  }
  let certs;
  try {
    certs = x5c.map(parseX5cCert);
  } catch (err) {
    return {
      name: "x509-chain",
      passed: false,
      detail: `Failed to parse x5c certificates: ${err instanceof Error ? err.message : "unknown error"}`
    };
  }
  if (certs.length === 0) {
    return {
      name: "x509-chain",
      passed: false,
      detail: "x5c chain is empty"
    };
  }
  const leafKeyUsage = checkLeafKeyUsage(certs[0]);
  if (leafKeyUsage === false) {
    return {
      name: "x509-chain",
      passed: false,
      detail: "Leaf certificate keyUsage does not include digitalSignature"
    };
  }
  const verificationMethod = proof["verificationMethod"];
  if (!verificationMethod) {
    return {
      name: "x509-chain",
      passed: false,
      detail: "Credential has x5c but no proof.verificationMethod \u2014 cannot bind certificate to issuer"
    };
  }
  const didPubKey = await resolveDidPublicKey(verificationMethod, options.didResolver);
  if (!didPubKey) {
    return {
      name: "x509-chain",
      passed: false,
      detail: "Unable to confirm leaf certificate matches credential issuer (DID could not be resolved or has no matching verification method)"
    };
  }
  if (!checkKeyBinding(certs[0], didPubKey)) {
    return {
      name: "x509-chain",
      passed: false,
      detail: "X.509 chain invalid: leaf certificate public key does not match the signing DID's public key"
    };
  }
  if (certs.length > 1) {
    const chainError = checkChainSignatures(certs);
    if (chainError) {
      return {
        name: "x509-chain",
        passed: false,
        detail: `X.509 chain invalid: ${chainError}`
      };
    }
  }
  const trustAnchorPems = options.trustAnchors ?? [];
  if (trustAnchorPems.length === 0) {
    return {
      name: "x509-chain",
      passed: false,
      detail: "X.509 chain check requires a configured trust anchor (set OPENCRED_CSCA_TRUST_STORE_PATH or pass trustAnchors to the verifier)"
    };
  }
  let trustAnchorCerts;
  try {
    trustAnchorCerts = trustAnchorPems.map((pem) => new X509Certificate(pem));
  } catch (err) {
    return {
      name: "x509-chain",
      passed: false,
      detail: `Failed to parse configured trust anchors: ${err instanceof Error ? err.message : "unknown error"}`
    };
  }
  const anchor = findAnchor(certs, trustAnchorCerts);
  if (!anchor) {
    return {
      name: "x509-chain",
      passed: false,
      detail: "X.509 chain invalid: chain does not terminate at a configured trust anchor"
    };
  }
  const proofCreated = proof["created"];
  if (proofCreated) {
    const proofTime = new Date(proofCreated);
    if (!isNaN(proofTime.getTime())) {
      const temporalError = checkChainTemporal([...certs, anchor], proofTime);
      if (temporalError) {
        return {
          name: "x509-chain",
          passed: false,
          detail: `X.509 chain invalid: ${temporalError}`
        };
      }
    }
  }
  const leaf = certs[0];
  return {
    name: "x509-chain",
    passed: true,
    detail: `DSC verified (${leaf.subject}), chain depth: ${certs.length}, anchored to ${anchor.subject}`
  };
}

// ../verification/dist/verifier.js
function detectFormat(input) {
  if (typeof input === "object" && input !== null) {
    if ("proof" in input) {
      return "data-integrity";
    }
    throw new VerificationError("Object input must have a 'proof' property for Data Integrity verification");
  }
  if (typeof input === "string") {
    assertJwtSize(input);
    if (input.includes("~")) {
      return "sd-jwt-vc";
    }
    const dotParts = input.split(".");
    if (dotParts.length === 3) {
      try {
        const payload = JSON.parse(Buffer.from(dotParts[1], "base64url").toString());
        if (payload.vc && typeof payload.vc === "object") {
          return "vc-jwt";
        }
        if (payload["@context"] || payload.credentialSubject) {
          return "jws";
        }
      } catch {
      }
      try {
        const header = JSON.parse(Buffer.from(dotParts[0], "base64url").toString());
        if (header.typ === "JWT") {
          return "vc-jwt";
        }
      } catch {
      }
      return "jws";
    }
    throw new VerificationError("String input is not a valid VC-JWT or SD-JWT VC");
  }
  throw new VerificationError("Input must be an object (Data Integrity) or string (VC-JWT / SD-JWT VC)");
}
async function verifyCredential(input, config = {}) {
  const format = detectFormat(input);
  const checks = [];
  let validFrom;
  let validUntil;
  let credentialStatus;
  let credentialForRevocationHash;
  if (format === "data-integrity") {
    const credential = input;
    const signatureCheck = await verifyDataIntegrity(credential, config.didResolver);
    checks.push(signatureCheck);
    if (!signatureCheck.passed) {
      return buildResult(checks, signatureCheck);
    }
    validFrom = credential.validFrom;
    validUntil = credential.validUntil;
    credentialStatus = credential.credentialStatus;
    credentialForRevocationHash = credential;
  } else if (format === "jws") {
    const signatureCheck = await verifyJwsProof(input, config.didResolver);
    checks.push(signatureCheck);
    if (!signatureCheck.passed) {
      return buildResult(checks, signatureCheck);
    }
    try {
      const payloadB64 = input.split(".")[1];
      const vcPayload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
      validFrom = vcPayload.validFrom;
      validUntil = vcPayload.validUntil;
      credentialStatus = vcPayload.credentialStatus;
      credentialForRevocationHash = vcPayload;
    } catch {
    }
  } else if (format === "vc-jwt") {
    const { check, payload } = await verifyVcJwt(input, config.didResolver);
    checks.push(check);
    if (!check.passed || !payload) {
      return buildResult(checks, check);
    }
    const crossErrors = crossValidateVcJwtClaims(payload);
    if (crossErrors.length > 0) {
      const crossCheck = {
        name: "vc-jwt-claims",
        passed: false,
        detail: crossErrors.join("; ")
      };
      checks.push(crossCheck);
      return buildResult(checks, crossCheck);
    }
    checks.push({ name: "vc-jwt-claims", passed: true });
    const fields = extractVcJwtCredentialFields(payload);
    validFrom = fields.validFrom;
    validUntil = fields.validUntil;
    credentialStatus = fields.credentialStatus;
    credentialForRevocationHash = payload.vc ?? payload;
  } else {
    const { check, payload, resolvedClaims } = await verifySdJwtVc(input, config.didResolver, config.sdJwtVc);
    checks.push(check);
    if (!check.passed || !payload || !resolvedClaims) {
      return buildResult(checks, check);
    }
    const fields = extractSdJwtVcCredentialFields(payload, resolvedClaims);
    validFrom = fields.validFrom;
    validUntil = fields.validUntil;
    credentialStatus = fields.credentialStatus;
    credentialForRevocationHash = resolvedClaims;
  }
  const dateCheck = checkDates(validFrom, validUntil);
  checks.push(dateCheck);
  if (!dateCheck.passed) {
    const isExpired = dateCheck.detail?.includes("expired") || dateCheck.detail?.includes("validUntil");
    return {
      code: isExpired ? "EXPIRED" : "INVALID",
      verified: false,
      checks
    };
  }
  if (config.dediClient && credentialForRevocationHash) {
    const revocationCheck = await checkRevocation(credentialForRevocationHash, config.dediClient);
    checks.push(revocationCheck);
    if (!revocationCheck.passed) {
      if (revocationCheck.detail?.includes("revoked")) {
        return { code: "REVOKED", verified: false, checks };
      }
      return { code: "UNRESOLVABLE", verified: false, checks };
    }
  }
  if (credentialStatus && credentialStatus["type"] === "BitstringStatusListEntry") {
    const bslCheck = await checkBitstringStatusList(credentialStatus, {
      didResolver: config.didResolver
    });
    checks.push(bslCheck);
    if (!bslCheck.passed) {
      if (bslCheck.detail?.includes("revoked")) {
        return { code: "REVOKED", verified: false, checks };
      }
      return { code: "UNRESOLVABLE", verified: false, checks };
    }
  }
  if (format === "data-integrity") {
    const x509Check = await checkX509Chain(input, {
      didResolver: config.didResolver,
      trustAnchors: config.trustAnchors
    });
    checks.push(x509Check);
    if (!x509Check.passed) {
      return { code: "INVALID", verified: false, checks };
    }
  }
  return { code: "VALID", verified: true, checks };
}
function buildResult(checks, failedCheck) {
  const isUnresolvable = failedCheck.detail?.includes("Unable to resolve");
  const isContextMissing = failedCheck.detail?.includes("Missing JSON-LD context");
  return {
    code: isContextMissing ? "CONTEXT_MISSING" : isUnresolvable ? "UNRESOLVABLE" : "INVALID",
    verified: false,
    checks
  };
}

// ../verification/dist/pdf-verifier.js
init_dist();
var require2 = createRequire(import.meta.url);
var pixelpass = require2("@mosip/pixelpass");
var OPENCRED_PIXELPASS_HEADER = "OPENCRED1:";
function decodePixelPass(data) {
  const body = data.startsWith(OPENCRED_PIXELPASS_HEADER) ? data.slice(OPENCRED_PIXELPASS_HEADER.length) : data;
  return pixelpass.decode(body);
}

// ../verification/dist/pdf-verifier.js
var PDF_CREDENTIAL_INFO_KEY = "OpenCredCredential";
async function verifyPdf(pdfBytes, config = {}) {
  let extracted;
  try {
    extracted = await extractEmbeddedCredential(pdfBytes);
  } catch (err) {
    return {
      verified: false,
      code: "INVALID",
      checks: [
        {
          name: "pdf-parse",
          passed: false,
          detail: `Failed to parse PDF: ${err instanceof Error ? err.message : String(err)}`
        }
      ]
    };
  }
  if (extracted.kind === "encrypted") {
    return {
      verified: false,
      code: "INVALID",
      checks: [
        {
          name: "pdf-encrypted",
          passed: false,
          detail: "PDF is encrypted; OpenCred cannot read its info dictionary. Decrypt the file first, or scan the printed QR code on the certificate page."
        }
      ]
    };
  }
  if (extracted.kind === "missing") {
    return {
      verified: false,
      code: "INVALID",
      checks: [
        {
          name: "pdf-embedded-credential",
          passed: false,
          detail: "PDF does not contain an embedded OpenCred credential. This may be a PDF issued before the OpenCredCredential info-dict embedding shipped, or a PDF not produced by OpenCred at all. To verify it, scan its printed QR code with the desktop app or extract the embedded JSON manually."
        }
      ]
    };
  }
  const embedded = extracted.value;
  const format = detectCredentialInputFormat(embedded);
  let credentialForVerify;
  try {
    switch (format) {
      case "pixelpass":
        credentialForVerify = JSON.parse(decodePixelPass(embedded));
        break;
      case "json":
        credentialForVerify = JSON.parse(embedded);
        break;
      case "jwt-compact":
        credentialForVerify = embedded;
        break;
      case "unknown":
        return {
          verified: false,
          code: "INVALID",
          checks: [
            {
              name: "pdf-embedded-credential",
              passed: false,
              detail: "PDF carries an embedded credential value but its format could not be recognized. Expected PixelPass (`OPENCRED1:`), JSON, or a compact JWT/SD-JWT token."
            }
          ]
        };
    }
  } catch (err) {
    return {
      verified: false,
      code: "INVALID",
      checks: [
        {
          name: "pdf-credential-decode",
          passed: false,
          detail: `Embedded credential could not be decoded: ${err instanceof Error ? err.message : String(err)}`
        }
      ]
    };
  }
  return verifyCredential(credentialForVerify, config);
}
async function extractEmbeddedCredential(pdfBytes) {
  const doc = await PDFDocument.load(pdfBytes, {
    updateMetadata: false,
    ignoreEncryption: true
  });
  if (doc.isEncrypted) {
    return { kind: "encrypted" };
  }
  const infoRef = doc.context.trailerInfo.Info;
  if (!infoRef)
    return { kind: "missing" };
  const infoDict = doc.context.lookup(infoRef, PDFDict);
  if (!infoDict)
    return { kind: "missing" };
  const raw = infoDict.lookup(PDFName.of(PDF_CREDENTIAL_INFO_KEY));
  if (!raw)
    return { kind: "missing" };
  if (raw instanceof PDFString)
    return { kind: "present", value: raw.asString() };
  if (raw instanceof PDFHexString)
    return { kind: "present", value: raw.decodeText() };
  return { kind: "missing" };
}

// ../dedi-client/dist/adapter/client.js
init_dist();

// ../dedi-client/dist/api/api-client.js
init_dist();

// ../dedi-client/dist/circuit-breaker.js
init_dist();

// ../dedi-client/dist/logger.js
var noopLogger = {
  info() {
  },
  debug() {
  },
  warn() {
  },
  error() {
  }
};

// ../dedi-client/dist/circuit-breaker.js
var CircuitBreakerState;
(function(CircuitBreakerState2) {
  CircuitBreakerState2["CLOSED"] = "CLOSED";
  CircuitBreakerState2["OPEN"] = "OPEN";
  CircuitBreakerState2["HALF_OPEN"] = "HALF_OPEN";
})(CircuitBreakerState || (CircuitBreakerState = {}));
var DEFAULT_OPTIONS = {
  threshold: 5,
  resetTimeoutMs: 3e4,
  logger: noopLogger,
  countAuthFailures: false
};
var CircuitBreaker = class {
  state = CircuitBreakerState.CLOSED;
  failureCount = 0;
  lastFailureTime = 0;
  options;
  constructor(options) {
    this.options = { ...DEFAULT_OPTIONS, ...options };
  }
  getState() {
    return this.state;
  }
  async execute(fn) {
    if (this.state === CircuitBreakerState.OPEN) {
      if (Date.now() - this.lastFailureTime >= this.options.resetTimeoutMs) {
        this.options.logger.debug("Circuit breaker transitioning from OPEN to HALF_OPEN");
        this.state = CircuitBreakerState.HALF_OPEN;
      } else {
        throw new DeDiClientError("Circuit breaker is open \u2014 request rejected", 503);
      }
    }
    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (error) {
      if (error instanceof DeDiClientError && error.statusCode < 500) {
        if (this.options.countAuthFailures && (error.statusCode === 401 || error.statusCode === 403)) {
          this.onFailure();
        }
        throw error;
      }
      this.onFailure();
      throw error;
    }
  }
  onSuccess() {
    if (this.state === CircuitBreakerState.HALF_OPEN) {
      this.options.logger.debug("Circuit breaker transitioning from HALF_OPEN to CLOSED");
    }
    this.failureCount = 0;
    this.state = CircuitBreakerState.CLOSED;
  }
  onFailure() {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    if (this.state === CircuitBreakerState.HALF_OPEN) {
      this.options.logger.warn("Circuit breaker opened after HALF_OPEN failure");
      this.state = CircuitBreakerState.OPEN;
    } else if (this.failureCount >= this.options.threshold) {
      this.options.logger.warn(`Circuit breaker opened after ${this.failureCount} failures`);
      this.state = CircuitBreakerState.OPEN;
    }
  }
};

// ../dedi-client/dist/retry.js
init_dist();
var DEFAULT_OPTIONS2 = {
  maxRetries: 3,
  baseDelayMs: 200
};
var TRANSIENT_NETWORK_CODES = /* @__PURE__ */ new Set([
  "ECONNREFUSED",
  "ECONNRESET",
  "ETIMEDOUT",
  "ENOTFOUND",
  "EAI_AGAIN",
  "EPIPE",
  "EHOSTUNREACH",
  "ENETUNREACH"
]);
function hasTransientNetworkCode(error) {
  if (typeof error !== "object" || error === null)
    return false;
  const code = error.code;
  if (code && TRANSIENT_NETWORK_CODES.has(code))
    return true;
  const cause = error.cause;
  if (cause)
    return hasTransientNetworkCode(cause);
  return false;
}
function isTransientError(error) {
  if (error instanceof DeDiClientError) {
    return error.statusCode >= 500;
  }
  if (error instanceof TypeError && error.message.includes("fetch")) {
    return true;
  }
  if (error instanceof DOMException && error.name === "AbortError") {
    return true;
  }
  if (hasTransientNetworkCode(error)) {
    return true;
  }
  return false;
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
async function withRetry(fn, options) {
  const opts = { ...DEFAULT_OPTIONS2, ...options };
  let lastError;
  for (let attempt = 0; attempt <= opts.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt >= opts.maxRetries || !isTransientError(error)) {
        if (attempt >= opts.maxRetries && opts.maxRetries > 0) {
          opts.logger?.error(`All ${opts.maxRetries} retry attempts exhausted`);
        }
        throw error;
      }
      opts.logger?.debug(`Retrying request, attempt ${attempt + 1} of ${opts.maxRetries}`);
      const delay = opts.baseDelayMs * Math.pow(2, attempt);
      await sleep(delay);
    }
  }
  throw lastError;
}

// ../dedi-client/dist/api/auth.js
init_dist();
var DEFAULT_REFRESH_BUFFER_MS = 6e4;
var DeDiTokenManager = class {
  config;
  refreshBufferMs;
  logger;
  accessToken = "";
  refreshToken = "";
  expiresAt = 0;
  // milliseconds since epoch
  pendingPromise = null;
  constructor(config) {
    this.config = config;
    this.logger = config.logger ?? noopLogger;
    this.refreshBufferMs = config.auth.type === "bearer" ? config.auth.refreshBufferMs ?? DEFAULT_REFRESH_BUFFER_MS : DEFAULT_REFRESH_BUFFER_MS;
  }
  async getToken() {
    if (this.config.auth.type === "api-key") {
      return this.config.auth.apiKey;
    }
    if (this.accessToken && !this.isExpiringSoon()) {
      return this.accessToken;
    }
    if (this.pendingPromise) {
      return this.pendingPromise;
    }
    this.pendingPromise = this.acquireToken();
    try {
      const token = await this.pendingPromise;
      return token;
    } finally {
      this.pendingPromise = null;
    }
  }
  async login() {
    await this.performLogin();
  }
  async refresh() {
    await this.performRefresh();
  }
  async acquireToken() {
    if (this.accessToken && this.refreshToken) {
      try {
        await this.performRefresh();
        return this.accessToken;
      } catch (error) {
        if (error instanceof DeDiClientError && (error.statusCode === 401 || error.statusCode === 403)) ; else {
          throw error;
        }
      }
    }
    await this.performLogin();
    return this.accessToken;
  }
  async performLogin() {
    if (this.config.auth.type !== "bearer") {
      throw new DeDiClientError("Login requires bearer auth config", 400);
    }
    const url = `${this.config.baseUrl}/dedi/register`;
    const response = await globalThis.fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: this.config.auth.email,
        password: this.config.auth.password,
        action: "login"
      })
    });
    if (!response.ok) {
      this.logger.error(`DeDi authentication failed with status ${response.status}`);
      throw new DeDiClientError(`DeDi authentication failed: ${response.status}`, response.status);
    }
    let body;
    try {
      body = await response.json();
    } catch {
      throw new DeDiClientError("DeDi auth endpoint returned non-JSON response", 502);
    }
    if (typeof body !== "object" || body === null || typeof body.access_token !== "string" || typeof body.refresh_token !== "string") {
      throw new DeDiClientError("DeDi API returned an unexpected auth response format", 502);
    }
    const tokens = body;
    this.setTokens(tokens);
    this.logger.debug("DeDi login successful");
  }
  async performRefresh() {
    const url = `${this.config.baseUrl}/dedi/token/refresh`;
    const response = await globalThis.fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: this.refreshToken })
    });
    if (!response.ok) {
      throw new DeDiClientError(`DeDi token refresh failed: ${response.status}`, response.status);
    }
    let body;
    try {
      body = await response.json();
    } catch {
      throw new DeDiClientError("DeDi auth endpoint returned non-JSON response", 502);
    }
    if (typeof body !== "object" || body === null || typeof body.access_token !== "string" || typeof body.refresh_token !== "string") {
      throw new DeDiClientError("DeDi API returned an unexpected auth response format", 502);
    }
    const tokens = body;
    this.setTokens(tokens);
    this.logger.debug("DeDi token refresh successful");
  }
  setTokens(tokens) {
    const newExpiresAt = this.decodeExp(tokens.access_token);
    this.accessToken = tokens.access_token;
    this.refreshToken = tokens.refresh_token;
    this.expiresAt = newExpiresAt;
  }
  isExpiringSoon() {
    return Date.now() >= this.expiresAt - this.refreshBufferMs;
  }
  decodeExp(jwt) {
    assertJwtSize(jwt);
    const parts = jwt.split(".");
    if (parts.length < 2) {
      throw new DeDiClientError("DeDi API returned a malformed JWT", 502);
    }
    try {
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      if (payload.exp === void 0) {
        throw new DeDiClientError("DeDi API returned a JWT without an exp claim", 502);
      }
      return payload.exp * 1e3;
    } catch (error) {
      if (error instanceof DeDiClientError)
        throw error;
      throw new DeDiClientError("DeDi API returned a JWT with an undecodable payload", 502);
    }
  }
};

// ../dedi-client/dist/api/api-client.js
var MAX_REQUEST_TIMEOUT_MS = 1e4;
var DNS_CACHE_TTL_MS = 3e4;
var DeDiApiClient = class {
  config;
  tokenManager;
  circuitBreaker;
  logger;
  effectiveTimeoutMs;
  // Per-hostname cache of resolved addresses. Protects against DNS
  // rebinding the same way the uncached path did (every request still
  // runs `isPrivateIP` on the cached addresses), but avoids two DNS
  // lookups per request for static operator-configured hostnames.
  dnsCache = /* @__PURE__ */ new Map();
  constructor(config) {
    if (config.timeoutMs <= 0) {
      throw new DeDiClientError("timeoutMs must be positive", 400);
    }
    if (config.maxRetries < 0) {
      throw new DeDiClientError("maxRetries must be non-negative", 400);
    }
    if (config.circuitBreakerThreshold <= 0) {
      throw new DeDiClientError("circuitBreakerThreshold must be positive", 400);
    }
    let parsedUrl;
    try {
      parsedUrl = new URL(config.baseUrl);
    } catch {
      throw new DeDiClientError("DeDi baseUrl is not a valid URL", 400);
    }
    if (parsedUrl.protocol !== "https:") {
      throw new DeDiClientError("DeDi baseUrl must use HTTPS", 400);
    }
    const hostname = stripIpv6Brackets(parsedUrl.hostname);
    if (isIP(hostname) !== 0 && isPrivateIP(hostname)) {
      throw new DeDiClientError("DeDi baseUrl must not target a private, loopback, or link-local IP", 400);
    }
    this.config = config;
    this.effectiveTimeoutMs = Math.min(config.timeoutMs, MAX_REQUEST_TIMEOUT_MS);
    this.logger = config.logger ?? noopLogger;
    this.tokenManager = new DeDiTokenManager({
      baseUrl: config.baseUrl,
      auth: config.auth,
      logger: this.logger
    });
    this.circuitBreaker = new CircuitBreaker({
      threshold: config.circuitBreakerThreshold,
      logger: this.logger
    });
  }
  // ── Namespace ────────────────────────────────────────────────────
  async createNamespace(name, description) {
    return this.request("/dedi/create-namespace", {
      method: "POST",
      body: JSON.stringify({ name, description, meta: {} })
    });
  }
  async lookupNamespace(ns) {
    return this.request(`/dedi/lookup/${enc(ns)}`);
  }
  // ── Registry ─────────────────────────────────────────────────────
  async createRegistry(ns, name, schema, tag) {
    return this.request(`/dedi/${enc(ns)}/create-registry`, {
      method: "POST",
      body: JSON.stringify({
        registry_name: name,
        description: `OpenCred ${name} registry`,
        // DeDi API: either schema OR tag, not both
        ...tag ? { tag } : {
          schema: Object.keys(schema).length > 0 ? schema : {
            $schema: "http://json-schema.org/draft-07/schema#",
            type: "object",
            properties: {}
          }
        },
        meta: {}
      })
    });
  }
  async lookupRegistry(ns, reg) {
    return this.request(`/dedi/lookup/${enc(ns)}/${enc(reg)}`);
  }
  async revokeRegistry(ns, reg) {
    await this.requestVoid(`/dedi/${enc(ns)}/${enc(reg)}/revoke-registry`, {
      method: "POST"
    });
  }
  // ── Record CRUD ──────────────────────────────────────────────────
  async publishRecord(ns, reg, name, details) {
    const record = await this.request(`/dedi/${enc(ns)}/${enc(reg)}/save-record-as-draft?publish=true`, {
      method: "POST",
      body: JSON.stringify({
        record_name: name,
        description: `OpenCred record: ${name}`,
        details,
        meta: {}
      })
    });
    return record;
  }
  async lookupRecord(ns, reg, recordName) {
    return this.request(`/dedi/lookup/${enc(ns)}/${enc(reg)}/${enc(recordName)}`);
  }
  async revokeRecord(ns, reg, recordName) {
    await this.changeRecordState(ns, reg, recordName, "revoked");
  }
  async changeRecordState(ns, reg, recordName, state) {
    const action = state === "revoked" ? "revoke-record" : state === "suspended" ? "suspend-record" : state === "live" ? "reinstate-record" : null;
    if (!action)
      return;
    await this.requestVoid(`/dedi/${enc(ns)}/${enc(reg)}/${enc(recordName)}/${action}`, {
      method: "POST"
    });
  }
  // ── Query & Search ───────────────────────────────────────────────
  async queryRecords(ns, reg, params) {
    const qs = params ? toQueryString(params) : "";
    return this.request(`/dedi/query/${enc(ns)}/${enc(reg)}${qs}`);
  }
  async search(ns, params) {
    const qs = toQueryString(params);
    return this.request(`/dedi/search/${enc(ns)}${qs}`);
  }
  // ── Domain verification ──────────────────────────────────────────
  async generateTxt(ns, domain) {
    return this.request(`/dedi/generate-dns-txt/${enc(ns)}/${enc(domain)}`);
  }
  async verifyDomain(ns) {
    await this.requestVoid(`/dedi/verify-domain`, {
      method: "POST",
      body: JSON.stringify({ namespace_id: ns })
    });
  }
  async checkVerification(ns) {
    return this.request(`/dedi/check-verification/${enc(ns)}`);
  }
  // ── Verification ─────────────────────────────────────────────────
  async verifyRecordLookup(response) {
    await this.requestVoid("/dedi/verify-record-lookup", {
      method: "POST",
      body: JSON.stringify({ record_lookup_response: response })
    });
  }
  // ── Delegation (DeDi user delegation) ────────────────────────────
  async addDelegate(ns, reg, email) {
    await this.requestVoid(`/dedi/${enc(ns)}/${enc(reg)}/add-delegate`, {
      method: "POST",
      body: JSON.stringify({ email })
    });
  }
  async removeDelegate(ns, reg, email) {
    await this.requestVoid(`/dedi/${enc(ns)}/${enc(reg)}/remove-registry-delegate`, {
      method: "POST",
      body: JSON.stringify({ email })
    });
  }
  // ── Bulk ─────────────────────────────────────────────────────────
  async bulkUpload(_ns, _reg, file) {
    return this.circuitBreaker.execute(() => withRetry(async () => {
      const formData = new FormData();
      formData.append("file", file);
      const response = await this.doFetch("/dedi/bulk-upload", {
        method: "POST",
        body: formData
      });
      if (!response.ok) {
        let errBody = "";
        try {
          errBody = await response.text();
        } catch {
        }
        this.logger.error(`DeDi API ${response.status} /dedi/bulk-upload`, {
          body: errBody.slice(0, 500)
        });
        throw new DeDiClientError(`DeDi API error: ${response.status}`, response.status >= 500 ? 502 : response.status);
      }
      let parsed;
      try {
        parsed = await response.json();
      } catch {
        throw new DeDiClientError("DeDi API returned non-JSON response", 502);
      }
      assertBulkUploadResultShape(parsed);
      return parsed;
    }, { maxRetries: this.config.maxRetries, logger: this.logger }));
  }
  async getJobStatus(jobId) {
    return this.request(`/dedi/bulk-upload/status/${enc(jobId)}`);
  }
  // ── Watch ────────────────────────────────────────────────────────
  async createWatch(params) {
    return this.request("/dedi/subscribe", {
      method: "POST",
      body: JSON.stringify(params)
    });
  }
  async deleteWatch(subId) {
    await this.requestVoid("/dedi/unsubscribe", {
      method: "POST",
      body: JSON.stringify({ id: subId })
    });
  }
  async listWatchSubscriptions() {
    return this.request("/dedi/subscriptions");
  }
  // ── Stats (public) ──────────────────────────────────────────────
  async getStats() {
    return this.request("/dedi/stats");
  }
  // ── Internal HTTP plumbing ───────────────────────────────────────
  async request(path3, init) {
    return this.circuitBreaker.execute(() => withRetry(() => this.fetchJson(path3, init), {
      maxRetries: this.config.maxRetries,
      logger: this.logger
    }));
  }
  async requestVoid(path3, init) {
    await this.circuitBreaker.execute(() => withRetry(() => this.fetchVoid(path3, init), {
      maxRetries: this.config.maxRetries,
      logger: this.logger
    }));
  }
  async fetchJson(path3, init) {
    const response = await this.doFetch(path3, init);
    if (!response.ok) {
      let body = "";
      try {
        body = await response.text();
      } catch {
      }
      this.logger.error(`DeDi API ${response.status} ${path3}`, { body: body.slice(0, 500) });
      throw new DeDiClientError(`DeDi API error: ${response.status}`, response.status >= 500 ? 502 : response.status);
    }
    try {
      return await response.json();
    } catch {
      throw new DeDiClientError(`DeDi API returned non-JSON response`, 502);
    }
  }
  async fetchVoid(path3, init) {
    const response = await this.doFetch(path3, init);
    if (!response.ok) {
      let body = "";
      try {
        body = await response.text();
      } catch {
      }
      this.logger.error(`DeDi API ${response.status} ${path3}`, { body: body.slice(0, 500) });
      throw new DeDiClientError(`DeDi API error: ${response.status}`, response.status >= 500 ? 502 : response.status);
    }
  }
  async doFetch(path3, init) {
    const method = init?.method ?? "GET";
    const url = `${this.config.baseUrl}${path3}`;
    await this.assertHostIsPublic(url);
    const token = await this.tokenManager.getToken();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.effectiveTimeoutMs);
    this.logger.info(`DeDi request`, { method, path: path3 });
    const start = Date.now();
    try {
      const isFormData = typeof FormData !== "undefined" && init?.body instanceof FormData;
      const response = await globalThis.fetch(url, {
        ...init,
        signal: controller.signal,
        redirect: "error",
        headers: {
          ...init?.body && !isFormData ? { "Content-Type": "application/json" } : {},
          Accept: "application/json",
          Authorization: `Bearer ${token}`,
          ...init?.headers
        }
      });
      this.logger.info(`DeDi response`, {
        method,
        path: path3,
        status: response.status,
        durationMs: Date.now() - start
      });
      return response;
    } catch (error) {
      const durationMs = Date.now() - start;
      if (error instanceof DeDiClientError) {
        this.logger.error(`DeDi request failed`, {
          method,
          path: path3,
          durationMs,
          error: error.message
        });
        throw error;
      }
      if (error instanceof DOMException && error.name === "AbortError") {
        this.logger.error(`DeDi request timed out`, { method, path: path3, durationMs });
        throw new DeDiClientError(`DeDi API request timed out after ${this.effectiveTimeoutMs}ms`, 504);
      }
      this.logger.error(`DeDi network error`, {
        method,
        path: path3,
        durationMs,
        error: error instanceof Error ? error.message : "unknown"
      });
      throw new DeDiClientError(`DeDi API network error: ${error instanceof Error ? error.message : "unknown"}`, 502);
    } finally {
      clearTimeout(timeoutId);
    }
  }
  /**
   * SSRF guard: resolve the hostname of the fully-qualified request
   * URL and refuse to proceed if any returned address is private,
   * loopback, or link-local. Run on every request (not just at
   * construction) so that DNS rebinding between calls cannot sneak
   * traffic into internal networks.
   */
  async assertHostIsPublic(requestUrl) {
    let parsed;
    try {
      parsed = new URL(requestUrl);
    } catch {
      throw new DeDiClientError("DeDi request URL is malformed", 400);
    }
    const hostname = stripIpv6Brackets(parsed.hostname);
    if (isIP(hostname) !== 0) {
      if (isPrivateIP(hostname)) {
        throw new DeDiClientError("DeDi baseUrl must not target a private, loopback, or link-local IP", 400);
      }
      return;
    }
    const cached = this.dnsCache.get(hostname);
    let addresses;
    if (cached && Date.now() - cached.resolvedAt < DNS_CACHE_TTL_MS) {
      addresses = cached.addresses;
    } else {
      const [v4Result, v6Result] = await Promise.allSettled([
        promises.resolve4(hostname),
        promises.resolve6(hostname)
      ]);
      addresses = [
        ...v4Result.status === "fulfilled" ? v4Result.value : [],
        ...v6Result.status === "fulfilled" ? v6Result.value : []
      ];
      if (addresses.length === 0) {
        throw new DeDiClientError(`DeDi host did not resolve: ${hostname}`, 502);
      }
      this.dnsCache.set(hostname, { addresses, resolvedAt: Date.now() });
    }
    for (const ip of addresses) {
      if (isPrivateIP(ip)) {
        throw new DeDiClientError("DeDi baseUrl must not target a private, loopback, or link-local IP", 400);
      }
    }
  }
};
function stripIpv6Brackets(hostname) {
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    return hostname.slice(1, -1);
  }
  return hostname;
}
function enc(value) {
  return encodeURIComponent(value);
}
function assertBulkUploadResultShape(value) {
  if (value == null || typeof value !== "object") {
    throw new DeDiClientError("DeDi API bulk upload response is missing or not an object", 502);
  }
  const rec = value;
  if (typeof rec["job_id"] !== "string") {
    throw new DeDiClientError("DeDi API bulk upload response missing required field: job_id", 502);
  }
}
function toQueryString(params) {
  const entries = Object.entries(params).filter(([, v]) => v !== void 0 && v !== null);
  if (entries.length === 0)
    return "";
  const qs = entries.map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`).join("&");
  return `?${qs}`;
}

// ../dedi-client/dist/adapter/registry-names.js
var REVOCATION_REGISTRY = "vc-revocation-registry";
var PUBLIC_KEY_REGISTRY = "public_key_registry";
var SCHEMA_REGISTRY = "schema_registry";
var CONTEXT_REGISTRY = "context_registry";
function schemaToRecordName(schemaId, version) {
  const slug = schemaId.replace(/\//g, "-");
  const suffix = `-v${version}`;
  return slug.endsWith(suffix) ? slug : `${slug}${suffix}`;
}
function contextToRecordName(schemaId, version) {
  const slug = schemaId.replace(/\//g, "-");
  const suffix = `-v${version}`;
  const base = slug.endsWith(suffix) ? slug.slice(0, -suffix.length) : slug;
  return `${base}-ctx-v${version}`;
}

// ../dedi-client/dist/adapter/client.js
function assertRevocationHashShape(detail) {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError("Revocation hash detail is missing or not an object", 502);
  }
  const rec = detail;
  if (typeof rec["hash"] !== "string") {
    throw new DeDiClientError("Revocation hash detail missing required field: hash", 502);
  }
  if (typeof rec["revoked"] !== "boolean") {
    throw new DeDiClientError("Revocation hash detail missing required field: revoked", 502);
  }
  if (rec["revoked"] === true && typeof rec["revokedAt"] !== "string") {
    throw new DeDiClientError("Revocation hash detail missing required field: revokedAt", 502);
  }
}
function assertDIDRecordShape(detail) {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError("DID record detail is missing or not an object", 502);
  }
  const rec = detail;
  if (typeof rec["did"] !== "string") {
    throw new DeDiClientError("DID record detail missing required field: did", 502);
  }
  if (!("document" in rec)) {
    throw new DeDiClientError("DID record detail missing required field: document", 502);
  }
  if (typeof rec["resolvedAt"] !== "string") {
    throw new DeDiClientError("DID record detail missing required field: resolvedAt", 502);
  }
}
var SCHEMA_RECORD_KEYS = ["schemaId", "version", "schema", "checksum", "publishedAt"];
function assertSchemaRecordShape(detail) {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError("Schema record detail is missing or not an object", 502);
  }
  const rec = detail;
  for (const key of SCHEMA_RECORD_KEYS) {
    if (!(key in rec)) {
      throw new DeDiClientError(`Schema record detail missing required field: ${key}`, 502);
    }
  }
  if (typeof rec["schemaId"] !== "string") {
    throw new DeDiClientError("Schema record field 'schemaId' must be a string", 502);
  }
  if (typeof rec["version"] !== "string") {
    throw new DeDiClientError("Schema record field 'version' must be a string", 502);
  }
  if (rec["schema"] == null || typeof rec["schema"] !== "object") {
    throw new DeDiClientError("Schema record field 'schema' must be an object", 502);
  }
  if (typeof rec["checksum"] !== "string") {
    throw new DeDiClientError("Schema record field 'checksum' must be a string", 502);
  }
  if (typeof rec["publishedAt"] !== "string") {
    throw new DeDiClientError("Schema record field 'publishedAt' must be a string", 502);
  }
}
var CONTEXT_RECORD_KEYS = ["schemaId", "version", "context", "publishedAt"];
function assertContextRecordShape(detail) {
  if (detail == null || typeof detail !== "object") {
    throw new DeDiClientError("Context record detail is missing or not an object", 502);
  }
  const rec = detail;
  for (const key of CONTEXT_RECORD_KEYS) {
    if (!(key in rec)) {
      throw new DeDiClientError(`Context record detail missing required field: ${key}`, 502);
    }
  }
  if (typeof rec["schemaId"] !== "string") {
    throw new DeDiClientError("Context record field 'schemaId' must be a string", 502);
  }
  if (typeof rec["version"] !== "string") {
    throw new DeDiClientError("Context record field 'version' must be a string", 502);
  }
  if (rec["context"] == null || typeof rec["context"] !== "object") {
    throw new DeDiClientError("Context record field 'context' must be an object", 502);
  }
  if (typeof rec["publishedAt"] !== "string") {
    throw new DeDiClientError("Context record field 'publishedAt' must be a string", 502);
  }
}
function assertDeDiRecordShape(value, label) {
  if (value == null || typeof value !== "object") {
    throw new DeDiClientError(`DeDi API ${label} response is missing or not an object`, 502);
  }
  const rec = value;
  if (typeof rec["name"] !== "string") {
    throw new DeDiClientError(`DeDi API ${label} response missing required field: name`, 502);
  }
  if (!("detail" in rec)) {
    throw new DeDiClientError(`DeDi API ${label} response missing required field: detail`, 502);
  }
}
function assertSearchResultShape(value) {
  if (value == null || typeof value !== "object") {
    throw new DeDiClientError("DeDi API search response is missing or not an object", 502);
  }
  const rec = value;
  if (!Array.isArray(rec["records"])) {
    throw new DeDiClientError("DeDi API search response field 'records' must be an array", 502);
  }
}
var DeDiClient = class {
  api;
  defaultNamespace;
  logger;
  constructor(config) {
    this.api = new DeDiApiClient(config);
    this.defaultNamespace = config.defaultNamespace;
    this.logger = config.logger ?? noopLogger;
  }
  get apiClient() {
    return this.api;
  }
  async publishRevocationHash(hash, namespace) {
    const ns = this.resolveNamespace(namespace);
    const revokedAt = (/* @__PURE__ */ new Date()).toISOString();
    const record = await this.api.publishRecord(ns, REVOCATION_REGISTRY, hash, {
      hash,
      revoked: true,
      revokedAt
    });
    assertDeDiRecordShape(record, "publishRecord");
    assertRevocationHashShape(record.detail);
    return record.detail;
  }
  async queryRevocationHash(hash, namespace) {
    const ns = this.resolveNamespace(namespace);
    const result = await this.api.search(ns, {
      registry_name: REVOCATION_REGISTRY,
      "detail.hash": hash
    });
    assertSearchResultShape(result);
    if (result.records.length === 0) {
      return { hash, revoked: false };
    }
    assertDeDiRecordShape(result.records[0], "search record");
    const detail = result.records[0].detail;
    assertRevocationHashShape(detail);
    return detail;
  }
  async publishDID(did, document, namespace) {
    const ns = this.resolveNamespace(namespace);
    const recordName = didToRecordName(did);
    const detail = {
      did,
      document,
      resolvedAt: (/* @__PURE__ */ new Date()).toISOString()
    };
    await this.api.publishRecord(ns, PUBLIC_KEY_REGISTRY, recordName, detail);
    return { published: true, recordName, namespace: ns };
  }
  async resolveDID(did, namespace) {
    const ns = this.resolveNamespace(namespace);
    const recordName = didToRecordName(did);
    const record = await this.api.lookupRecord(ns, PUBLIC_KEY_REGISTRY, recordName);
    assertDeDiRecordShape(record, "lookupRecord");
    assertDIDRecordShape(record.detail);
    return record.detail;
  }
  async publishSchema(schema, namespace) {
    const ns = this.resolveNamespace(namespace);
    const recordName = schemaToRecordName(schema.schemaId, schema.version);
    await this.api.publishRecord(ns, SCHEMA_REGISTRY, recordName, schema);
    return { published: true, recordName, namespace: ns };
  }
  async resolveSchema(schemaId, version, namespace) {
    const ns = this.resolveNamespace(namespace);
    const recordName = schemaToRecordName(schemaId, version);
    const record = await this.api.lookupRecord(ns, SCHEMA_REGISTRY, recordName);
    assertDeDiRecordShape(record, "lookupRecord");
    assertSchemaRecordShape(record.detail);
    return record.detail;
  }
  async publishContext(record, namespace) {
    const ns = this.resolveNamespace(namespace);
    const recordName = contextToRecordName(record.schemaId, record.version);
    await this.api.publishRecord(ns, CONTEXT_REGISTRY, recordName, record);
    return { published: true, recordName, namespace: ns };
  }
  async resolveContext(schemaId, version, namespace) {
    const ns = this.resolveNamespace(namespace);
    const recordName = contextToRecordName(schemaId, version);
    const record = await this.api.lookupRecord(ns, CONTEXT_REGISTRY, recordName);
    assertDeDiRecordShape(record, "lookupRecord");
    assertContextRecordShape(record.detail);
    return record.detail;
  }
  async ensureRegistries(namespace) {
    try {
      const nsResult = await this.api.createNamespace(namespace, "OpenCred namespace");
      this.logger.debug("Namespace created", {
        namespace,
        result: JSON.stringify(nsResult).slice(0, 200)
      });
    } catch (nsErr) {
      const code = nsErr instanceof DeDiClientError ? nsErr.statusCode : 0;
      this.logger.error("Namespace creation failed", {
        namespace,
        code,
        error: nsErr instanceof Error ? nsErr.message : String(nsErr)
      });
      if (code !== 409)
        throw nsErr;
    }
    await Promise.all([
      ignoreConflict(() => this.api.createRegistry(namespace, REVOCATION_REGISTRY, {
        $schema: "http://json-schema.org/draft-07/schema#",
        type: "object",
        description: "OpenCred revocation list",
        properties: {
          hash: { type: "string" },
          revoked: { type: "boolean" },
          revokedAt: { type: "string" }
        },
        required: ["hash", "revoked"]
      })),
      ignoreConflict(() => this.api.createRegistry(namespace, PUBLIC_KEY_REGISTRY, {
        $schema: "http://json-schema.org/draft-07/schema#",
        type: "object",
        description: "OpenCred public key registry",
        properties: {
          did: { type: "string" },
          document: { type: "object" },
          resolvedAt: { type: "string" }
        },
        required: ["did", "document"]
      })),
      ignoreConflict(() => this.api.createRegistry(namespace, SCHEMA_REGISTRY, {
        $schema: "http://json-schema.org/draft-07/schema#",
        type: "object",
        description: "OpenCred credential schema catalog",
        properties: {
          schemaId: { type: "string" },
          version: { type: "string" },
          schema: { type: "object" },
          checksum: { type: "string" },
          publishedAt: { type: "string" }
        },
        required: ["schemaId", "version", "schema"]
      })),
      // CONTEXT_REGISTRY uses "custom" tag (no JSON schema) because JSON-LD
      // context documents are dynamic and don't fit a fixed schema.
      ignoreConflict(() => this.api.createRegistry(namespace, CONTEXT_REGISTRY, {}, "custom"))
    ]);
  }
  resolveNamespace(explicit) {
    const ns = explicit ?? this.defaultNamespace;
    if (!ns) {
      throw new DeDiClientError("No namespace provided and no defaultNamespace configured", 400);
    }
    return ns;
  }
};
function didToRecordName(did) {
  return did.replace(/:/g, "-");
}
async function ignoreConflict(fn) {
  try {
    await fn();
  } catch (error) {
    if (error instanceof DeDiClientError && error.statusCode === 409) {
      return;
    }
    throw error;
  }
}

// ../dedi-client/dist/adapter/did-web-fallback.js
function createDeDiDIDWebFallback(client) {
  return async (did) => {
    try {
      const record = await client.resolveDID(did);
      if (!record.document || typeof record.document !== "object") {
        return null;
      }
      return {
        didDocument: record.document,
        didResolutionMetadata: { contentType: "application/did+json" },
        didDocumentMetadata: { resolvedAt: record.resolvedAt }
      };
    } catch {
      return null;
    }
  };
}

// src/index.ts
var noopLogger2 = {
  debug: () => {
  },
  info: () => {
  },
  warn: () => {
  },
  error: () => {
  }
};
function createVerifier(options = {}) {
  const logger = options.logger ?? noopLogger2;
  const dediClient = options.dedi ? new DeDiClient({ ...options.dedi, logger }) : null;
  const didResolver = options.didResolver ?? new CompositeDIDResolver(
    /* @__PURE__ */ new Map([
      ["key", new DIDKeyResolver()],
      ["jwk", new DIDJwkResolver()],
      ["web", new DIDWebResolver(dediClient ? createDeDiDIDWebFallback(dediClient) : void 0)]
    ])
  );
  const verifierConfig = {
    didResolver,
    trustAnchors: options.trustAnchors,
    dediClient: dediClient ?? void 0
  };
  const fn = async (input) => verifyCredential(input, verifierConfig);
  fn.pdf = async (pdfBytes) => verifyPdf(pdfBytes, verifierConfig);
  return fn;
}
async function verifyCredential2(input, options = {}) {
  return createVerifier(options)(input);
}
async function verifyPdf2(pdfBytes, options = {}) {
  return createVerifier(options).pdf(pdfBytes);
}
function detectFormat2(input) {
  return detectFormat(input);
}

export { createVerifier, detectFormat2 as detectFormat, verifyCredential2 as verifyCredential, verifyPdf2 as verifyPdf };
