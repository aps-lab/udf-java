package org.plooh.udf;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

import com.hierynomus.sshj.transport.mac.Macs;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import net.schmizz.sshj.transport.mac.BaseMAC;

public class UDF {

    public static final Base32 base32 = new Base32(-1, null, false);

    /**
     * Default number of UDF bits (usually 140)
     */
    public static final int DefaultBits = 140;

    /**
     * Minimum precision (usually 128)
     */
    public static final int MinimumBits = 128;

    /**
     * Maximum precision (usually 440)
     */
    public static final int MaximumBits = 440;

    public static final byte TAG_SEPARATOR_BYTE = (byte) ':';

    final byte[] buffer;

    /**
     * Convert a digest value and content type to a UDF buffer.
     * 
     * See http://www.iana.org/assignments/media-types/media-types.xhtml forlist.
     * 
     * SHA2-512 (UTF8(ContentType) + ":" + SHA2512(Data))
     * 
     * @param dataDigest      Digest of the data to be fingerprinted.
     * @param contentType     MIME media type of data being fingerprinted.
     * @param precision       Precision, must be a multiple of 25 bits.
     * @param digestAlgorithm The cryptographic digest to use to compute the hash
     *                        value.
     * @param key             Optional key used to create a keyed fingerprint.
     */
    private static UDF createBuffer(byte[] dataDigest, String contentType, int precision,
            DigestAlgorithm digestAlgorithm, String key) {

        // this.dataDigest = dataDigest;
        // this.digestAlgorithm = digestAlgorithm;
        // this.key = key;
        // this.precision = precision;

        // <Content-ID> + ':' + H(<Data>)
        byte[] content_H_Data = udfDataBuffer(dataDigest, contentType);

        // H(<Content-ID> + ':' + H(<Data>))
        byte[] digest;
        switch (digestAlgorithm) {
            case SHA2_512:
                digest = DigestUtils.sha512(content_H_Data);
                break;
            case SHA3_512:
                digest = DigestUtils.sha3_512(content_H_Data);
                break;
            default:
                throw new IllegalStateException("Unexpected algorithm: " + digestAlgorithm);
        }

        return bufferDigestToUDF(digest, precision, digestAlgorithm, key);
    }

    public String presentationBase32() {
        return presentationBase32(buffer, 4, "-", -1);
    }

    public String presentationBase32(int bits) {
        return presentationBase32(buffer, 4, "-", bits);
    }

    private UDF(final byte[] buffer) {
        this.buffer = buffer;
    }

    /**
     * Returns the compression level as determined by the number of trailing zero
     * bits of buffer.
     * 
     * @param digest The buffer to compress (MUST have at least 7 bytes)
     * @return The compression level, 3 if there are 50 leading zeros, 2 if there
     *         are 40 leading zeros, 1 if there are 20 and 0 otherwise.
     */
    static int getCompression(byte[] digest) {
        // byte[] buffer = digest;
        // Assert.AssertTrue(buffer.Length == 64, CryptographicException.Throw);
        assert digest.length == 64 : "CryptographicException: wrong buffer length";

        // Check for less than 20 trailing zeros
        if (digest[63] != 0 | digest[62] != 0 | ((digest[61] & 0b0000_1111) != 0)) {
            return 0;
        }

        // Check for less than 30 trailing zeros
        if (digest[61] != 0 | ((digest[60] & 0b0011_1111) != 0)) {
            return 1;
        }

        // Check for less than 40 trailing zeros
        if (digest[60] != 0 | digest[59] != 0 | digest[58] != 0) {
            return 2;
        }

        // Check for less than 50 trailing zeros
        if (digest[57] != 0 | ((digest[56] & 0b0000_0011) == 0)) {
            return 3;
        }
        return 4;
    }

    /**
     * @return The binary UDF fingerprint.
     */
    static UDF bufferDigestToUDF(byte[] digest, int precision, DigestAlgorithm digestAlgorithm, String key) {
        if (key == null) {
            // Data UDF
            int compression = getCompression(digest);
            UdfTypeIdentifier typeIdentifier = UdfTypeIdentifier.getTypeIdentifier(digestAlgorithm, compression);
            return typeBDSToBinary(typeIdentifier, digest, precision, 0);
        } else {
            // Digest algorithm was applied in the costructor.
            switch (digestAlgorithm) {
                case SHA2_512: {
                    BaseMAC hmac = Macs.HMACSHA2512().create();
                    hmac.init(key.getBytes(StandardCharsets.UTF_8));
                    byte[] udfData = hmac.doFinal(digest);
                    return typeBDSToBinary(UdfTypeIdentifier.Authenticator_HMAC_SHA_2_512, udfData, precision, 0);
                }
                default: {
                    throw new IllegalStateException("Unexpected algorithm: " + digestAlgorithm);
                }
            }

        }
    }

    /**
     * Convert a Type Identifier and binary data sequence to a UDF binary buffer
     * ready for presentation.
     * 
     * @param typeID The type identifier.
     * @param source The input buffer.
     * @param bits   The number of bits precision of the final output. If 0, the
     *               value of the property DefaultBits is used.
     * @param offset Offset in source
     * 
     * @return The resulting binary buffer.
     */
    static UDF typeBDSToBinary(UdfTypeIdentifier typeIdentifier, byte[] source, int bits, int offset) {
        // Constraints the number of bits to an integer multiple of 20 bits between
        // DefaultBits and MaximumBits.
        bits = bits <= 0 ? DefaultBits : bits;
        bits = Math.min(bits, source.length * 8);

        // Calculate the number of bytes
        int bytes = (bits + 7) / 8;

        byte[] buffer = new byte[bytes];
        buffer[0] = (byte) typeIdentifier.code;
        System.arraycopy(source, offset, buffer, 1, bytes - 1);
        return new UDF(buffer);
    }

    /**
     * Conversions to binary UDF value
     * 
     * Calculate a UDF fingerprint from the content data with specified precision.
     * 
     * @param data            Data to be fingerprinted.
     * @param contentType     MIME media type of data being fingerprinted.
     * @param bits            Precision, must be a multiple of 20 bits.
     * @param digestAlgorithm The cryptographic digest to use to compute the hash
     *                        value.
     * @param key             Optional key used to create a keyed fingerprint.
     * @return The binary UDF fingerprint.
     */
    static UDF dataToUDFBinary(byte[] data, String contentType, int bits, DigestAlgorithm digestAlgorithm, String key) {
        digestAlgorithm = digestAlgorithm == null ? DigestAlgorithm.SHA2_512 : digestAlgorithm;

        byte[] digest = null;
        switch (digestAlgorithm) {
            case SHA2_512:
                digest = DigestUtils.sha512(data);
                break;
            case SHA3_512:
                digest = DigestUtils.sha3_512(data);
                break;
            default:
                throw new IllegalStateException("Unexpected algorithm: " + digestAlgorithm);
        }
        return createBuffer(digest, contentType, bits, digestAlgorithm, key);
    }

    /**
     * Calculate a UDF fingerprint from the content digest with specified
     * 
     * @param digest          Digest of the data to be fingerprinted
     * @param contentType     MIME media type of data being fingerprinted
     * @param bits            Precision, must be a multiple of 25 bits
     * @param digestAlgorithm The cryptographic digest to use to compute the hash
     *                        value
     * @param keyOptional     key used to create a keyed fingerprint
     * @return The binary UDF fingerprint
     */
    public static UDF digestToUDFBinary(byte[] digest, String contentType, int bits, DigestAlgorithm digestAlgorithm,
            String key) {
        return createBuffer(digest, contentType, bits, digestAlgorithm, key);
    }

    /**
     * Calculate a UDF fingerprint from an OpenPGP key with specified precision.
     * 
     * @param data            Data to be fingerprinted
     * @param contentType     MIME media type of data being fingerprinted
     * @param bits            Precision, must be a multiple of 25 bits
     * @param digestAlgorithm The cryptographic digest to use to compute the hash
     *                        value
     * @param key             Optional key used to create a keyed fingerprint
     * @return The binary UDF fingerprint
     */
    public static String contentDigestOfDataString(byte[] data, String contentType, int bits,
            DigestAlgorithm digestAlgorithm, String key) {
        digestAlgorithm = digestAlgorithm == null ? DigestAlgorithm.SHA2_512 : digestAlgorithm;
        UDF buffer = dataToUDFBinary(data, contentType, bits, digestAlgorithm, key);
        return buffer.presentationBase32();
    }

    /**
     * Calculate a UDF fingerprint from an OpenPGP key with specified precision.
     * 
     * @param data            Data to be fingerprinted
     * @param contentType     MIME media type of data being fingerprinted
     * @param bits            Precision, must be a multiple of 20 bits
     * @param digestAlgorithm The cryptographic digest to use to compute the hash
     *                        value
     * @param key             Optional key used to create a keyed fingerprint
     * @return The binary UDF fingerprint
     */
    public static String contentDigestOfDigestString(byte[] data, String contentType, int bits,
            DigestAlgorithm digestAlgorithm, String key) {
        digestAlgorithm = digestAlgorithm == null ? DigestAlgorithm.SHA2_512 : digestAlgorithm;
        UDF buffer = digestToUDFBinary(data, contentType, bits, digestAlgorithm, key);
        return buffer.presentationBase32();
    }

    /**
     * Calculate the UDF fingerprint identifier of a fingerprint identifier.
     * 
     * @param data
     * @param bits            Precision, must be a multiple of 20 bits
     * @param digestAlgorithm The cryptographic digest to use to compute the hash
     *                        value
     * @return The Base32 presentation of the UDF value truncated to precision
     */
    static String contentDigestOfUDF(String data, int bits, DigestAlgorithm digestAlgorithm) {
        digestAlgorithm = digestAlgorithm == null ? DigestAlgorithm.SHA2_512 : digestAlgorithm;
        bits = bits == 0 ? DefaultBits * 2 : bits;

        //// Calculate the output precision, this is twice the input precision to a
        //// maximum od MaximumBits.
        // var bits = 10 * ((data.Length + 1) / 4);
        // bits = bits > MaximumBits ? MaximumBits : bits;

        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        UDF buffer = digestToUDFBinary(bytes, UDFConstants.UDFEncryption, bits, digestAlgorithm, null);
        return buffer.presentationBase32();
    }

    static String presentationBase32(byte[] bytes, int chunkSize, String delimiter, int bits) {
        String s = StringUtils.substringBefore(base32.encodeToString(bytes), "=");
        String[] chunks = chunk(s, chunkSize);
        // String join = String.join(delimiter, chunks);
        int bl = (bits + 19) / 20;
        int min = Math.min(bl, chunks.length);
        int blocks = bits <= 0 ? chunks.length : min;
        return StringUtils.join(chunks, delimiter, 0, blocks);
    }

    static String[] chunk(String string, int chunkSize) {
        List<String> chunks = new ArrayList<>();
        for (int start = 0; start < string.length(); start += chunkSize) {
            chunks.add(string.substring(start, Math.min(string.length(), start + chunkSize)));
        }
        return chunks.toArray(new String[chunks.size()]);
    }

    /**
     * <Content-ID> + ':' + H(<Data>)
     * 
     * @param digest
     * @param contentType
     * @return
     */
    static byte[] udfDataBuffer(byte[] digest, String contentType) {
        byte[] contentTypeBytes = contentType.getBytes(StandardCharsets.UTF_8);
        int length = contentTypeBytes.length + 1 + digest.length;
        byte[] resultBuffer = new byte[length];

        // Set conttent bytes
        System.arraycopy(contentTypeBytes, 0, resultBuffer, 0, contentTypeBytes.length);
        // Set separator byte
        resultBuffer[contentTypeBytes.length] = TAG_SEPARATOR_BYTE;
        // set digest bytes
        System.arraycopy(digest, 0, resultBuffer, contentTypeBytes.length + 1, digest.length);

        return resultBuffer;
    }

    static String typeBDSToString(UdfTypeIdentifier typeID, byte[] source, int bits, int offset) {
        UDF udf = typeBDSToBinary(typeID, source, bits, offset);
        return presentationBase32(udf.buffer, 4, "-", -1);
    }

    /**
     * Return a random sequence as a UDF
     * 
     * @param bits Number of random bits in the string
     * @return A randomly generated UDF string
     */
    public static String nonce(int bits) {
        bits = bits <= 0 ? DefaultBits - 8 : bits;
        byte[] data = randomBits(bits);
        return nonce(data, bits);
    }

    static String nonce(byte[] data, int bits) {
        return typeBDSToString(UdfTypeIdentifier.Nonce, data, bits + 8, 0);
    }

    private static byte[] randomBits(int bits) {
        byte[] data = new byte[bits / 8];
        new Random().nextBytes(data);
        return data;
    }

    /**
     * Return a random sequence as a UDF
     * 
     * @param udfTypeIdentifier g=the key type
     * @param bits              Number of random bits in the string
     * @return A randomly generated UDF string.
     */
    public static String symmetricKey(UdfTypeIdentifier udfTypeIdentifier, int bits) {
        bits = bits <= 0 ? DefaultBits - 8 : bits;
        byte[] data = randomBits(bits);
        return typeBDSToString(udfTypeIdentifier, data, bits + 8, 0);
    }

    /**
     * Return the key value #data in UDF form
     * 
     * @param udfTypeIdentifier A randomly generated UDF string.
     * @param data              The data to convert to key form
     * @return
     */
    public static String symmetricKey(UdfTypeIdentifier udfTypeIdentifier, byte[] data) {
        int bits = data.length * 8;
        return typeBDSToString(udfTypeIdentifier, data, bits + 8, 0);
    }

    /**
     * Return a random sequence as a UDF
     * 
     * @param bits Number of random bits in the string
     * @return A randomly generated UDF string.
     */
    public static String authenticationKey(int bits) {
        return symmetricKey(UdfTypeIdentifier.Authenticator_HMAC_SHA_2_512, bits);
    }

    /**
     * Return a random sequence as a UDF
     * 
     * @param data The data to convert to key form
     * @return A randomly generated UDF string
     */
    public static String authenticationKey(byte[] data) {
        return symmetricKey(UdfTypeIdentifier.Authenticator_HMAC_SHA_2_512, data);
    }

    /**
     * Return a random sequence as a UDF
     * 
     * @param bits Number of random bits in the string
     * @return A randomly generated UDF string
     */
    public static String encryptionKey(int bits) {
        return symmetricKey(UdfTypeIdentifier.Encryption_HKDF_AES_512, bits);
    }

    /**
     * Return the key value #data in UDF form
     * 
     * @param data The data to convert to key form
     * @return A randomly generated UDF string
     */
    public static String encryptionKey(byte[] data) {
        return symmetricKey(UdfTypeIdentifier.Encryption_HKDF_AES_512, data);
    }

    /**
     * Return the key share in UDF form
     * 
     * @param data The data to convert to udf form
     * @return The UDF string
     */
    public static String keyShare(byte[] data) {
        int bits = data.length * 8;
        return typeBDSToString(UdfTypeIdentifier.ShamirSecret, data, bits + 8, 0);
    }

    /**
     * Return the key value <paramref name="data"/> in UDF form.
     * 
     * @param data The data to convert to key form
     * @return the corresponding UDF string
     */
    public static String symmetricKeyUDF(byte[] data) {
        return contentDigestOfUDF(encryptionKey(data), 0, null);
    }

    /**
     * Calculate a UDF fingerprint from a PKIX KeyInfo blob with specified
     * precision.
     * 
     * @param data            Data to be fingerprinted.
     * @param bits            Precision, must be a multiple of 25 bits.
     * @param digestAlgorithm The digest algorithm to use.
     * @return The binary UDF fingerprint.
     */
    public static UDF fromKeyInfo(byte[] data, int bits, DigestAlgorithm digestAlgorithm) {
        digestAlgorithm = digestAlgorithm == null ? DigestAlgorithm.SHA2_512 : digestAlgorithm;
        return dataToUDFBinary(data, UDFConstants.PKIXKey, bits, digestAlgorithm, null);
    }

    /**
     * Parse a UDF to obtain the type identifier and Binary Data Sequence.
     * 
     * @param udfString UDF to parse.
     * @return the UDFBuffer
     */
    public static UDF parse(String udfString) {
        byte[] buffer = base32.decode(udfString);
        return new UDF(buffer);
    }

    public UdfTypeIdentifier typeIdentifier() {
        return UdfTypeIdentifier.valueOf(buffer[0]);
    }

    public byte[] data() {
        byte[] digest = new byte[buffer.length - 1];
        System.arraycopy(buffer, 1, digest, 0, buffer.length - 1);
        return digest;
    }
}
