# Unified Data Fingerpring (UDF)

This module implement UDF such as defined in [Mathematical Mesh 3.0 Part II: Uniform Data Fingerprint draft-hallambaker-mesh-udf-10](https://www.ietf.org/archive/id/draft-hallambaker-mesh-udf-10.txt).

Give a piece of data DATA.
- The UDF is defined as: ```H(<Content-ID> + ':' + H(<Data>))``` where H is the hash algerithm used to compute the 
digest of data presented. The Content-ID is the mime type of DATA (or any meta infor used qo qualify DATA).
- In the final representation, the UDF is prefixed by a byindicating the UDFTypeIdentifier as defined in [mmesh-3.2](https://tools.ietf.org/html/draft-hallambaker-mesh-udf-10#section-3.2)

Our intention is to use UDF for referencing known information like:

```java
    @Test
    public void testPhone125(){
        String phone = "+491722346123";
        byte[] data = phone.getBytes(StandardCharsets.UTF_8);
        UDF udf = UDF.dataToUDFBinary(data, AddressType.phone.name(), 0, null, null);
        String presentationBase32 = udf.presentationBase32(125);
        assertEquals("MCIT-HW7U-5AKU-JLLF-44ZK-QXF4-QKHJ", presentationBase32);
    }

    @Test
    public void testEmail125(){
        String email = "marion.mueller@mail.is";
        byte[] data = email.getBytes(StandardCharsets.UTF_8);
        UDF udf = UDF.dataToUDFBinary(data, AddressType.email.name(), 0, null, null);
        String presentationBase32 = udf.presentationBase32(125);
        assertEquals("MDG3-BQLT-SKY2-DAR3-EIAH-2GI3-LZHZ", presentationBase32);
    }
```

We might then be able to use: did:sw:MCIT-HW7U-5AKU-JLLF-44ZK-QXF4-QKHJ to reference a record associated with the 
phone number +491722346123.