package org.plooh.udf;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.jupiter.api.Test;

public class UDFTest {

    @Test
    public void testBase32Print() {
        String s = "I am francis here!";
        byte[] pArray = s.getBytes(StandardCharsets.UTF_8);
        String presentationBase32 = UDF.presentationBase32(pArray, 4, "-", -1);
        assertEquals("JEQG-C3JA-MZZG-C3TD-NFZS-A2DF-OJSS-C", presentationBase32);
    }

    @Test
    public void testUTF8BytesReadData() {
        String input = "UDF Compressed Document 4187123";
        byte[] data = input.getBytes(StandardCharsets.UTF_8);
        String expected = "55 44 46 20 43 6F 6D 70 72 65 73 73 65 64 20 44 6F 63 75 6D 65 6E 74 20 34 31 38 37 31 32 33";
        hexCompare(expected, data);
    }

    /**
     * ContentType "text/plain"
     */
    @Test
    public void testUTF8BytesReadContentTypes() {
        String input = "text/plain";
        byte[] data = input.getBytes(StandardCharsets.UTF_8);
        String expected = "74 65 78 74 2F 70 6C 61 69 6E";
        hexCompare(expected, data);
    }

    /**
     * H(<Data>)
     */
    @Test
    public void testSHA2Digest() {
        String input = "UDF Compressed Document 4187123";
        byte[] data = input.getBytes(StandardCharsets.UTF_8);
        byte[] sha512 = DigestUtils.sha512(data);
        String expected = "36 21 FA 2A C5 D8 62 5C 2D 0B 45 FB 65 93 FC 69 C1 ED F7 00 AE 6F E3 3D 38 13 FE AB 76 AA 74 13 6D 5A 2B 20 DE D6 A5 CF 6C 04 E6 56 3F F3 C0 C7 C4 1D 3F 43 DD DC F1 A5 67 A7 E0 67 9A B0 C6 B7";
        hexCompare(expected, sha512);
    }

    /**
     * <Content-ID> + ':' + H(<Data>) =
     */
    @Test
    public void udfDataBufferTest() {
        String ctyString = "text/plain";
        // byte[] ctyBytes = ctyString.getBytes(StandardCharsets.UTF_8);

        String dataString = "UDF Compressed Document 4187123";
        byte[] dataStringBytes = dataString.getBytes(StandardCharsets.UTF_8);
        byte[] dataDigest = DigestUtils.sha512(dataStringBytes);

        byte[] udfDataBuffer = UDF.udfDataBuffer(dataDigest, ctyString);

        String expected = "74 65 78 74 2F 70 6C 61 69 6E 3A 36 21 FA 2A C5 D8 62 5C 2D 0B 45 FB 65 93 FC 69 C1 ED F7 00 AE 6F E3 3D 38 13 FE AB 76 AA 74 13 6D 5A 2B 20 DE D6 A5 CF 6C 04 E6 56 3F F3 C0 C7 C4 1D 3F 43 DD DC F1 A5 67 A7 E0 67 9A B0 C6 B7";

        hexCompare(expected, udfDataBuffer);
    }

    /**
     * H(<Content-ID> + ':' + H(<Data>))
     */
    @Test
    public void udfDataBufferTest2() {
        String ctyString = "text/plain";
        // byte[] ctyBytes = ctyString.getBytes(StandardCharsets.UTF_8);

        String dataString = "UDF Compressed Document 4187123";
        byte[] dataStringBytes = dataString.getBytes(StandardCharsets.UTF_8);
        byte[] dataDigest = DigestUtils.sha512(dataStringBytes);

        byte[] udfDataBuffer = UDF.udfDataBuffer(dataDigest, ctyString);

        byte[] bufferDigest = DigestUtils.sha512(udfDataBuffer);

        String expected = "8E 14 D9 19 4E D6 02 12 C3 30 A7 BB 5F C7 17 6D AE 9A 56 7C A8 2A 23 1F 96 75 ED 53 10 EC E8 F2 60 14 24 D0 C8 BC 55 3D C0 70 F7 5E 86 38 1A 0B CB 55 9C B2 87 81 27 FF 3C EC E2 F0 90 A0 00 00";

        hexCompare(expected, bufferDigest);
    }

    @Test
    public void udfBSDDataBufferTest2() {
        String ctyString = "text/plain";
        // byte[] ctyBytes = ctyString.getBytes(StandardCharsets.UTF_8);

        String dataString = "UDF Compressed Document 4187123";
        byte[] dataStringBytes = dataString.getBytes(StandardCharsets.UTF_8);
        byte[] dataDigest = DigestUtils.sha512(dataStringBytes);

        byte[] udfDataBuffer = UDF.udfDataBuffer(dataDigest, ctyString);

        byte[] bufferDigest = DigestUtils.sha512(udfDataBuffer);

        int compression = UDF.getCompression(bufferDigest);
        assertEquals(1, compression);

        UdfTypeIdentifier typeIdentifier = UdfTypeIdentifier.getTypeIdentifier(DigestAlgorithm.SHA2_512, compression);
        assertEquals(UdfTypeIdentifier.Digest_SHA_2_512_20, typeIdentifier);

        UDF udf = UDF.typeBDSToBinary(typeIdentifier, bufferDigest, 800, 0);
        byte[] typeBDSToBinary = udf.buffer;
        String expected = "61 8E 14 D9 19 4E D6 02 12 C3 30 A7 BB 5F C7 17 6D AE 9A 56 7C A8 2A 23 1F 96 75 ED 53 10 EC E8 F2 60 14 24 D0 C8 BC 55 3D C0 70 F7 5E 86 38 1A 0B CB 55 9C B2 87 81 27 FF 3C EC E2 F0 90 A0 00";

        hexCompare(expected, typeBDSToBinary);
    }

    @Test
    public void udfBSDDataBufferTest3() {
        String ctyString = "text/plain";
        String dataString = "UDF Compressed Document 4187123";
        byte[] dataStringBytes = dataString.getBytes(StandardCharsets.UTF_8);
        UDF udfBinary = UDF.dataToUDFBinary(dataStringBytes, ctyString, 800, DigestAlgorithm.SHA2_512, null);

        String expected = "61 8E 14 D9 19 4E D6 02 12 C3 30 A7 BB 5F C7 17 6D AE 9A 56 7C A8 2A 23 1F 96 75 ED 53 10 EC E8 F2 60 14 24 D0 C8 BC 55 3D C0 70 F7 5E 86 38 1A 0B CB 55 9C B2 87 81 27 FF 3C EC E2 F0 90 A0 00";
        hexCompare(expected, udfBinary.buffer);
    }

    @Test
    public void udf800() {
        String ctyString = "text/plain";
        String dataString = "UDF Compressed Document 4187123";
        byte[] dataStringBytes = dataString.getBytes(StandardCharsets.UTF_8);
        UDF udfBinary = UDF.dataToUDFBinary(dataStringBytes, ctyString, 800, DigestAlgorithm.SHA2_512, null);

        // 440 bits
        String expectedFull = "MGHB-JWIZ-J3LA-EEWD-GCT3-WX6H-C5W2-5GSW-PSUC-UIY7-SZ26-2UYQ-5TUP-EYAU-ETIM-RPCV-HXAH-B526-QY4B-UC6L-KWOL-FB4B-E77T-Z3HC-6CIK-AAA";
        String presentationFull = udfBinary.presentationBase32();
        assertEquals(expectedFull, presentationFull);
    }

    @Test
    public void udf125() {
        String ctyString = "text/plain";
        String dataString = "UDF Compressed Document 4187123";
        byte[] dataStringBytes = dataString.getBytes(StandardCharsets.UTF_8);
        UDF udfBinary = UDF.dataToUDFBinary(dataStringBytes, ctyString, 200, DigestAlgorithm.SHA2_512, null);

        String expectedShort = "MGHB-JWIZ-J3LA-EEWD-GCT3-WX6H-C5W2";
        String presentationHort = UDF.presentationBase32(udfBinary.buffer, 4, "-", 125);
        assertEquals(expectedShort, presentationHort);
    }

    private void hexCompare(String expected, byte[] data) {
        String encodeHexString = Hex.encodeHexString(data, false);
        String[] chunks = UDF.chunk(encodeHexString, 2);
        String joined = String.join(" ", chunks);
        assertEquals(expected, joined);
    }

    @Test
    public void testNonce() throws DecoderException {
        String nonceByte = "CC 27 19 9C 4D C9 3B 71 EF 79 02 2E 5D 55 52 1B C3";
        String deleteWhitespace = StringUtils.deleteWhitespace(nonceByte);
        byte[] data = Hex.decodeHex(deleteWhitespace.toCharArray());
        String nonce = UDF.nonce(data, data.length * 8);
        String expected = "NDGC-OGM4-JXET-W4PP-PEBC-4XKV-KINQ";
        assertEquals(expected, nonce);
    }

}