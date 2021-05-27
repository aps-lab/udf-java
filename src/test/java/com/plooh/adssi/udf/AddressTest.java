package com.plooh.adssi.udf;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

public class AddressTest {

    @Test
    public void testPhone125() {
        String phone = "+491722346123";
        byte[] data = phone.getBytes(StandardCharsets.UTF_8);
        UDF udf = UDF.dataToUDFBinary(data, AddressType.phone.name(), 0, null, null);
        String presentationBase32 = udf.presentationBase32(125);
        assertEquals("MCIT-HW7U-5AKU-JLLF-44ZK-QXF4-QKHJ", presentationBase32);
    }

    @Test
    public void testEmail125() {
        String email = "marion.mueller@mail.is";
        byte[] data = email.getBytes(StandardCharsets.UTF_8);
        UDF udf = UDF.dataToUDFBinary(data, AddressType.email.name(), 0, null, null);
        String presentationBase32 = udf.presentationBase32(125);
        assertEquals("MDG3-BQLT-SKY2-DAR3-EIAH-2GI3-LZHZ", presentationBase32);
    }

    @Test
    public void testIban125() {
        String iban = "DE8937040044053201300";
        byte[] data = iban.getBytes(StandardCharsets.UTF_8);
        UDF udf = UDF.dataToUDFBinary(data, AddressType.iban.name(), 0, null, null);
        String presentationBase32 = udf.presentationBase32(125);
        assertEquals("MCDN-UFPD-5R6T-GB3R-SP2K-X5RY-35UC", presentationBase32);
    }

    static enum AddressType {
        phone, email, iban;
    }
}