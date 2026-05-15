import { VerificationInput, CredentialVerificationResult, CredentialFormat } from '@opencred/verification';
export { CredentialFormat, CredentialVerificationResult, VerificationCheck, VerificationInput, VerificationResultCode } from '@opencred/verification';
import { DIDResolver } from '@opencred/did';
import { DeDiClientConfig } from '@opencred/dedi-client';

/**
 * @opencred/verify — public SDK for verifying OpenCred-issued credentials.
 *
 * This is a curated, single-install facade over the internal verification
 * engine (`@opencred/verification`) that powers the OpenCred Docker image
 * and Desktop Client. It exposes a minimal, ergonomic API for use in
 * third-party verifier services without exposing the internal package
 * structure or workspace deps.
 *
 * Usage:
 *
 * ```ts
 * import { createVerifier } from "@opencred/verify";
 *
 * const verify = createVerifier({
 *   // Optional: DeDi config for revocation checks + did:web fallback.
 *   // Omit to verify did:key / did:jwk credentials with zero infra.
 *   dedi: {
 *     baseUrl: "https://your-dedi-instance.example.org",
 *     namespace: "your-namespace",
 *     auth: { type: "api-key", apiKey: process.env.DEDI_API_KEY! },
 *   },
 *
 *   // Optional: PEM-encoded CSCA roots, for verifying DSC-signed credentials.
 *   trustAnchors: [process.env.CSCA_PEM!],
 * });
 *
 * const result = await verify(jwtCompactStringOrJsonLdVcObject);
 * if (result.verified) {
 *   // proceed
 * } else {
 *   console.log(result.code, result.checks);
 * }
 * ```
 *
 * For PDF inputs, use the `verifyPdf` helper:
 *
 * ```ts
 * import { createVerifier } from "@opencred/verify";
 * const verify = createVerifier();
 * const result = await verify.pdf(uint8ArrayOfPdfBytes);
 * ```
 */

/**
 * Configuration passed to {@link createVerifier}. Every field is optional —
 * with no config, the SDK verifies any `did:key` / `did:jwk` credential
 * fully offline.
 */
interface VerifySdkOptions {
    /**
     * DeDi (Decentralized Directory) configuration. When present:
     *
     *  - The verifier checks revocation status for credentials with
     *    `credentialStatus` by querying the `vc-revocation-registry` registry.
     *  - `did:web` resolution falls back to DeDi's `public_key_registry`
     *    when canonical HTTPS resolution fails.
     *
     * Omit for a pure offline verifier. Note that without DeDi, the
     * revocation check is silently skipped — credentials carrying a
     * `credentialStatus` block will verify as VALID even if they've been
     * revoked, because there's no way to query the registry.
     */
    dedi?: DeDiClientConfig;
    /**
     * PEM-encoded CSCA root certificates as an array of strings, used to
     * validate DSC chains (the `x5c` chain attached to credentials signed
     * by a Document Signer Certificate). Omit if you don't expect to
     * verify DSC-signed credentials.
     */
    trustAnchors?: string[];
    /**
     * Custom DID resolver. By default the SDK builds a CompositeDIDResolver
     * with `did:key`, `did:jwk`, and `did:web` (HTTPS, plus DeDi fallback if
     * `dedi` is configured). Override only if you need an exotic DID method
     * or want to disable HTTPS network access entirely.
     */
    didResolver?: DIDResolver;
    /**
     * Logger sink for DeDi operations (circuit-breaker events, retry warnings,
     * etc.). Defaults to a no-op.
     */
    logger?: {
        debug: (msg: string, ctx?: Record<string, unknown>) => void;
        info: (msg: string, ctx?: Record<string, unknown>) => void;
        warn: (msg: string, ctx?: Record<string, unknown>) => void;
        error: (msg: string, ctx?: Record<string, unknown>) => void;
    };
}
/**
 * The verifier function returned by {@link createVerifier}.
 *
 * Calling it with a JWT compact string, JSON-LD VC object, sd-jwt-vc string,
 * or OPENCRED1 PixelPass string returns a `CredentialVerificationResult`.
 *
 * Use the `.pdf` method for binary PDF input.
 */
interface Verifier {
    (input: VerificationInput): Promise<CredentialVerificationResult>;
    /**
     * Verify a credential embedded in an OpenCred-issued PDF. The credential
     * is read from the PDF's info-dictionary under the `OpenCredCredential`
     * key and verified end-to-end.
     */
    pdf(pdfBytes: Uint8Array): Promise<CredentialVerificationResult>;
}
/**
 * Build a verifier with the given configuration. The returned function and
 * its `.pdf` method are safe to call concurrently and can be reused across
 * many verifications.
 *
 * @example Zero-config verifier (handles did:key / did:jwk fully offline)
 * ```ts
 * const verify = createVerifier();
 * const result = await verify(jwt);
 * ```
 *
 * @example DeDi-backed verifier (revocation + did:web fallback)
 * ```ts
 * const verify = createVerifier({
 *   dedi: {
 *     baseUrl: "https://your-dedi.example.org",
 *     namespace: "your-namespace",
 *     auth: { type: "api-key", apiKey: process.env.DEDI_API_KEY! },
 *   },
 * });
 * ```
 */
declare function createVerifier(options?: VerifySdkOptions): Verifier;
/**
 * One-shot verification helper. Equivalent to
 * `createVerifier(options)(input)`, but discards the verifier after the
 * call. Use {@link createVerifier} instead when verifying many credentials
 * — it avoids rebuilding the DID resolver and DeDi client every time.
 */
declare function verifyCredential(input: VerificationInput, options?: VerifySdkOptions): Promise<CredentialVerificationResult>;
/**
 * One-shot PDF verification helper. Equivalent to
 * `createVerifier(options).pdf(pdfBytes)`.
 */
declare function verifyPdf(pdfBytes: Uint8Array, options?: VerifySdkOptions): Promise<CredentialVerificationResult>;
/**
 * Inspect the wire format of an input string without verifying it.
 * Useful when you want to route by format (e.g. show different UI for a
 * JWT vs. a PDF reference) before calling the verifier.
 */
declare function detectFormat(input: VerificationInput): CredentialFormat;

export { type Verifier, type VerifySdkOptions, createVerifier, detectFormat, verifyCredential, verifyPdf };
