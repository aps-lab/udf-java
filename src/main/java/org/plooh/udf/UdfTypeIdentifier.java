package org.plooh.udf;

import java.util.Arrays;

public enum UdfTypeIdentifier {
    /** Undefined type */
    Unknown(-1),
    /** Authenticator HMAC_SHA_2_512 */
    Authenticator_HMAC_SHA_2_512(0),
    /** Authenticator HMAC_SHA_3_512 */
    Authenticator_HMAC_SHA_3_512(1),
    /** Encryption HKDF_AES_512 */
    Encryption_HKDF_AES_512(32),
    /** EncryptionSignature HKDF_AES_512 */
    EncryptionSignature_HKDF_AES_512(33),
    /** Digest SHA_3_512 */
    Digest_SHA_3_512(80),
    /** Digest SHA_3_512 (20 bits compressed) */
    Digest_SHA_3_512_20(81),
    /** Digest SHA_3_512 (30 bits compressed) */
    Digest_SHA_3_512_30(82),
    /** Digest SHA_3_512 (40 bits compressed) */
    Digest_SHA_3_512_40(83),
    /** Digest SHA_3_512 (50 bits compressed) */
    Digest_SHA_3_512_50(84),
    /** Digest SHA_2_512 */
    Digest_SHA_2_512(96),
    /** Digest SHA_2_512 (20 bits compressed) */
    Digest_SHA_2_512_20(97),
    /** Digest SHA_2_512 (30 bits compressed) */
    Digest_SHA_2_512_30(98),
    /** Digest SHA_2_512 (40 bits compressed) */
    Digest_SHA_2_512_40(99),
    /** Digest SHA_2_512 (50 bits compressed) */
    Digest_SHA_2_512_50(100),
    /** Nonce Data */
    Nonce(104),
    /** OID distinguished sequence (DER encoded) */
    OID(112),
    /** Shamir Secret Share */
    ShamirSecret(144),
    /** Secret seed */
    DerivedKey(200);

    public final int code;

    private UdfTypeIdentifier(int code) {
        this.code = code;
    }

    public static UdfTypeIdentifier getTypeIdentifier(DigestAlgorithm digestAlgorithm, int compression) {
        switch (digestAlgorithm) {
            case SHA2_512:
                switch (compression) {
                    case 1:
                        return Digest_SHA_2_512_20;
                    case 2:
                        return Digest_SHA_2_512_30;
                    case 3:
                        return Digest_SHA_2_512_40;
                    case 4:
                        return Digest_SHA_2_512_50;
                    default:
                        return Digest_SHA_2_512;
                }
            case SHA3_512:
                switch (compression) {
                    case 1:
                        return Digest_SHA_3_512_20;
                    case 2:
                        return Digest_SHA_3_512_30;
                    case 3:
                        return Digest_SHA_3_512_40;
                    case 4:
                        return Digest_SHA_3_512_50;
                    default:
                        return Digest_SHA_3_512;
                }
            default:
                throw new IllegalStateException("Unexpected algorithm: " + digestAlgorithm);
        }
    }

    public static UdfTypeIdentifier valueOf(int value) {
        return Arrays.stream(values()).filter(tid -> tid.code == value).findFirst()
                .orElseThrow(() -> new IllegalStateException("Unexpected UdfTypeIdentifier code: " + value));
    }
}