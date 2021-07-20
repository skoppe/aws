module aws.sigv4;

import std.array;
import std.algorithm;
import std.digest.sha;
import std.range;
import std.stdio;
import std.string;

immutable algorithm = "AWS4-HMAC-SHA256";
immutable streaming_payload_hash = "STREAMING-" ~ algorithm ~ "-PAYLOAD";

struct CanonicalRequest
{
    string method;
    string uri;
    string[string] queryParameters;
    string[string] headers;
    // const(ubyte)[] payload;
    string payloadHash;
}

void setPayload(ref CanonicalRequest req, in ubyte[] payload) @safe {
    auto payloadHash = payload.hash();
    req.payloadHash = payloadHash;
    req.headers["x-amz-content-sha256"] = payloadHash;
}

void setStreamingPayloadHash(ref CanonicalRequest req, string decodedLength) @safe {
    req.headers["x-amz-content-sha256"] = streaming_payload_hash;
    req.headers["x-amz-decoded-content-length"] = decodedLength;
    req.payloadHash = streaming_payload_hash;
}

@trusted pure
string canonicalQueryString(in string[string] queryParameters)
{
    import std.uri : encodeComponent;

    string[string] encoded;
    foreach (p; queryParameters.keys()) 
    {
        encoded[encodeComponent(p)] = encodeComponent(queryParameters[p]);
    }
    string[] keys = encoded.keys();
    sort(keys);
    return keys.map!(k => k ~ "=" ~ encoded[k]).join("&");
}

@trusted pure
string canonicalHeaders(in string[string] headers)
{
    string[string] trimmed;
    foreach (h; headers.keys())
    {
        trimmed[h.toLower().strip()] = headers[h].strip(); // TODO: should convert sequential spaces in the header value to a single space
    }
    string[] keys = trimmed.keys();
    sort(keys);
    return keys.map!(k => k ~ ":" ~ trimmed[k] ~ "\n").join("");
}

@trusted pure
string signedHeaders(in string[string] headers)
{
    string[] keys = headers.keys().map!(k => k.toLower()).array();
    sort(keys);
    return keys.join(";");
}

@safe pure
string hash(in ubyte[] payload)
{
    return sha256Of(payload)[].toHexString().toLower();
}

@safe pure
private string requestStringBase(in CanonicalRequest r)
{
    return 
        r.method.toUpper() ~ "\n" ~
        (r.uri.empty ? "/" : r.uri) ~ "\n" ~
        canonicalQueryString(r.queryParameters) ~ "\n" ~
        canonicalHeaders(r.headers) ~ "\n" ~
        signedHeaders(r.headers);
}

@safe pure
string requestString(in CanonicalRequest r)
{
    return r.requestStringBase ~ "\n" ~
        r.payloadHash;
}

@safe pure
string makeCRSigV4(in CanonicalRequest r)
{
    return r.requestString.representation.hash;
}

unittest {
    string[string] empty;

    auto r = CanonicalRequest(
            "POST",
            "/",
            empty,
            ["content-type": "application/x-www-form-urlencoded; charset=utf-8",
             "host": "iam.amazonaws.com",
             "x-amz-date": "20110909T233600Z"]);
    r.setPayload(cast(ubyte[])"Action=ListUsers&Version=2010-05-08");

    auto sig = makeCRSigV4(r);

    assert(sig == "6bb0c1d1a458667c2717e3b2f7b14033f757a8e7230013d40b1e4d18b2378fe4");
}

struct SignableRequest
{
    string dateString;
    string timeStringUTC;
    string region;
    string service;
    CanonicalRequest canonicalRequest;
}

private string signableStringBase(in SignableRequest r) @safe
{
    return algorithm ~ "\n" ~
        r.dateString ~ "T" ~ r.timeStringUTC ~ "Z\n" ~
        r.dateString ~ "/" ~ r.region ~ "/" ~ r.service ~ "/aws4_request";
}

string signableString(in SignableRequest r) @safe {
    return r.signableStringBase ~ "\n" ~
        r.canonicalRequest.makeCRSigV4;
}

unittest {
    string[string] empty;

    SignableRequest r;
    r.dateString = "20110909";
    r.timeStringUTC = "233600";
    r.region = "us-east-1";
    r.service = "iam";
    r.canonicalRequest = CanonicalRequest(
            "POST",
            "/",
            empty,
            ["content-type": "application/x-www-form-urlencoded; charset=utf-8",
             "host": "iam.amazonaws.com",
             "x-amz-date": "20110909T233600Z"]);
    r.canonicalRequest.setPayload(cast(ubyte[])"Action=ListUsers&Version=2010-05-08");

    auto sampleString =
        algorithm ~ "\n" ~
        "20110909T233600Z\n" ~
        "20110909/us-east-1/iam/aws4_request\n" ~ 
        "6bb0c1d1a458667c2717e3b2f7b14033f757a8e7230013d40b1e4d18b2378fe4";

    assert(sampleString == signableString(r));
}

@safe pure nothrow @nogc
auto hmac_sha256(in ubyte[] key, in ubyte[] message)
in {
    assert(key.length <= 64);
}
body {
    assert(key.length <= 64);
    SHA256 sha;
    ubyte[64] pad = 0x36;
    pad[0 .. key.length] ^= key[];
    sha.put(pad);
    sha.put(message);
    auto hash = sha.finish;
    sha.start;
    pad[] = 0x5c;
    pad[0 .. key.length] ^= key[];
    sha.put(pad);
    sha.put(hash);
    hash = sha.finish;
    return hash;
}

unittest {
    ubyte[] key = cast(ubyte[])"key";
    ubyte[] message = cast(ubyte[])"The quick brown fox jumps over the lazy dog";

    string mac = hmac_sha256(key, message).toHexString().toLower();
    assert(mac == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8");
}

auto signingKey(string secret, string dateString, string region, string service)
{
    ubyte[] kSecret = cast(ubyte[])("AWS4" ~ secret);
    auto kDate = hmac_sha256(kSecret, cast(ubyte[])dateString);
    auto kRegion = hmac_sha256(kDate, cast(ubyte[])region);
    auto kService = hmac_sha256(kRegion, cast(ubyte[])service);
    return hmac_sha256(kService, cast(ubyte[])"aws4_request");
}

unittest {
    string secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    auto signKey = signingKey(secretKey, "20110909", "us-east-1", "iam");
    
    ubyte[] expected = [152, 241, 216, 137, 254, 196, 244, 66, 26, 220, 82, 43, 171, 12, 225, 248, 46, 105, 41, 194, 98, 237, 21, 229, 169, 76, 144, 239, 209, 227, 176, 231 ];
    assert(expected == signKey);
}

unittest {
    // import unit_threaded;
    string secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    auto signKey = signingKey(secretKey, "20150830", "us-east-1", "iam");
    assert(signKey.toHexString().toLower == "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9");
}

unittest {
    auto sampleString = "AWS4-HMAC-SHA256\n"~
        "20150830T123600Z\n"~
        "20150830/us-east-1/iam/aws4_request\n"~
        "f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59";

    string secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    auto signKey = signingKey(secretKey, "20150830", "us-east-1", "iam");
    auto signature = hmac_sha256(signKey, cast(ubyte[])sampleString).toHexString().toLower();
    assert(signature == "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7");
}

alias sign = hmac_sha256;

unittest {
    auto sampleString =
        "AWS4-HMAC-SHA256\n" ~
        "20110909T233600Z\n" ~
        "20110909/us-east-1/iam/aws4_request\n" ~ 
        "3511de7e95d28ecd39e9513b642aee07e54f4941150d8df8bf94b328ef7e55e2";

    auto secretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    auto signKey = signingKey(secretKey, "20110909", "us-east-1", "iam");

    auto signature = sign(signKey, cast(ubyte[])sampleString).toHexString().toLower();
    auto expected = "ced6826de92d2bdeed8f846f0bf508e8559e98e4b0199114b84c54174deb456c";

    assert(signature == expected);
}

/**
 * CredentialScope == date / region / service / aws4_request
 */
string createSignatureHeader(string accessKeyID, string credentialScope, string[string] reqHeaders, ubyte[] signature)
{
    return algorithm ~ " Credential=" ~ accessKeyID ~ "/" ~ credentialScope ~ "/aws4_request, SignedHeaders=" ~ signedHeaders(reqHeaders) ~ ", Signature=" ~ signature.toHexString().toLower();
}

string dateFromISOString(string iso)
{
    auto i = iso.indexOf('T');
    if (i == -1) throw new Exception("ISO time in wrong format: " ~ iso);
    return iso[0..i];
}

string timeFromISOString(string iso)
{
    auto t = iso.indexOf('T');
    auto z = iso.indexOf('Z');
    if (t == -1 || z == -1) throw new Exception("ISO time in wrong format: " ~ iso);
    return iso[t+1..z];
}

unittest {
    assert(dateFromISOString("20110909T1203Z") == "20110909");
}

struct SignableChunk
{
    static immutable string emptyHash;

    static this()
    {
        emptyHash = hash([]);
    }

    string dateString;
    string timeStringUTC;
    string region;
    string service;

    string seedHash;
    string payloadHash;
}

string signableString(SignableChunk c) @safe {
    return algorithm ~ "-PAYLOAD\n" ~
        c.dateString ~ "T" ~ c.timeStringUTC ~ "Z\n" ~
        c.dateString ~ "/" ~ c.region ~ "/" ~ c.service ~ "/aws4_request\n" ~
        c.seedHash ~ "\n" ~
        SignableChunk.emptyHash ~ "\n" ~
        c.payloadHash;
}


unittest {
    //Example taken from here: http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html

    immutable string AWSAccessKeyId     = "AKIAIOSFODNN7EXAMPLE";
    immutable string AWSSecretAccessKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    immutable string isoDateTime = "20130524T000000Z";
    immutable string date = dateFromISOString(isoDateTime);
    immutable string time = timeFromISOString(isoDateTime);

    immutable string region  = "us-east-1";
    immutable string service = "s3";
    immutable string bucket = "examplebucket";

    /*  Request:
      
        PUT /examplebucket/chunkObject.txt HTTP/1.1
        Host: s3.amazonaws.com
        x-amz-date: 20130524T000000Z 
        x-amz-storage-class: REDUCED_REDUNDANCY
        Authorization: SignatureToBeCalculated
        x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD
        Content-Encoding: aws-chunked
        x-amz-decoded-content-length: 66560
        Content-Length: 66824
        <Payload>
     */


    /*  Canonical Request:
      
        PUT
        /examplebucket/chunkObject.txt

        content-encoding:aws-chunked
        content-length:66824
        host:s3.amazonaws.com
        x-amz-content-sha256:STREAMING-AWS4-HMAC-SHA256-PAYLOAD
        x-amz-date:20130524T000000Z
        x-amz-decoded-content-length:66560
        x-amz-storage-class:REDUCED_REDUNDANCY

        content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class
        STREAMING-AWS4-HMAC-SHA256-PAYLOAD
     */

    auto canonicalRequest = CanonicalRequest(
            "PUT",
            "/examplebucket/chunkObject.txt",
            null,
            [
                "content-encoding":             "aws-chunked",
                "content-length":               "66824",
                "host":                         "s3.amazonaws.com",
                "x-amz-date":                   isoDateTime,
                "x-amz-storage-class":          "REDUCED_REDUNDANCY",
            ],
            null
        );
    canonicalRequest.setStreamingPayloadHash("66560");

    auto canonicalRequestSignature = canonicalRequest.makeCRSigV4;
    assert(canonicalRequestSignature == "cee3fed04b70f867d036f722359b0b1f2f0e5dc0efadbc082b76c4c60e316455");

    /* Signable String:
       AWS4-HMAC-SHA256
       20130524T000000Z
       20130524/us-east-1/s3/aws4_request
       cee3fed04b70f867d036f722359b0b1f2f0e5dc0efadbc082b76c4c60e316455
     */

    auto signableRequest = SignableRequest(date, time, region, service, canonicalRequest);
    auto signableString = signableRequest.signableString;
    assert(signableString == "AWS4-HMAC-SHA256\n" ~
                             "20130524T000000Z\n" ~ 
                             "20130524/us-east-1/s3/aws4_request\n" ~
                             "cee3fed04b70f867d036f722359b0b1f2f0e5dc0efadbc082b76c4c60e316455");

    auto key = signingKey(AWSSecretAccessKey, date, region, service);
    auto binarySignature = key.sign(cast(ubyte[])signableString);
    auto seedSignature = binarySignature.toHexString().toLower();
    assert(seedSignature == "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9");

    auto credScope = date ~ "/" ~ region ~ "/" ~ service;
    auto authHeader = createSignatureHeader(AWSAccessKeyId, credScope, canonicalRequest.headers, binarySignature);
    assert(authHeader == "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " ~
                         "SignedHeaders=content-encoding;content-length;host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-storage-class, " ~
                         "Signature=4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9");

    auto payload1 = new ubyte[](0x10000);
    payload1[] = 97;
    auto chunk1 = SignableChunk(date,time,region,service,seedSignature,hash(payload1));
    auto signableChunkString1 = chunk1.signableString;
    assert(signableChunkString1 == "AWS4-HMAC-SHA256-PAYLOAD\n" ~ 
                                   "20130524T000000Z\n" ~ 
                                   "20130524/us-east-1/s3/aws4_request\n" ~ 
                                   "4f232c4386841ef735655705268965c44a0e4690baa4adea153f7db9fa80a0a9\n" ~ 
                                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" ~ 
                                   "bf718b6f653bebc184e1479f1935b8da974d701b893afcf49e701f3e2f9f9c5a");
    auto chunkSignature1 = key.sign(cast(ubyte[])signableChunkString1).toHexString().toLower();
    assert(chunkSignature1 == "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648");

    auto payload2 = new ubyte[](0x400);
    payload2[] = 97;
    auto chunk2 = SignableChunk(date,time,region,service,chunkSignature1,hash(payload2));
    auto signableChunkString2 = chunk2.signableString;
    assert(signableChunkString2 == "AWS4-HMAC-SHA256-PAYLOAD\n" ~
                                   "20130524T000000Z\n" ~
                                   "20130524/us-east-1/s3/aws4_request\n" ~
                                   "ad80c730a21e5b8d04586a2213dd63b9a0e99e0e2307b0ade35a65485a288648\n" ~
                                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" ~
                                   "2edc986847e209b4016e141a6dc8716d3207350f416969382d431539bf292e4a");
    auto chunkSignature2 = key.sign(cast(ubyte[])signableChunkString2).toHexString().toLower();
    assert(chunkSignature2 == "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497");

    auto payload3 = new ubyte[](0);
    auto chunk3 = SignableChunk(date,time,region,service,chunkSignature2,hash(payload3));
    auto signableChunkString3 = chunk3.signableString;
    assert(signableChunkString3 == "AWS4-HMAC-SHA256-PAYLOAD\n" ~
                                   "20130524T000000Z\n" ~
                                   "20130524/us-east-1/s3/aws4_request\n" ~
                                   "0055627c9e194cb4542bae2aa5492e3c1575bbb81b612b7d234b86a503ef5497\n" ~
                                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" ~
                                   "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    auto chunkSignature3 = key.sign(cast(ubyte[])signableChunkString3).toHexString().toLower();
    assert(chunkSignature3 == "b6c6ea8a5354eaf15b3cb7646744f4275b71ea724fed81ceb9323e279d449df9");
}
