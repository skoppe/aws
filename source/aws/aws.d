module aws.aws;

import std.algorithm;
import std.datetime;
import std.random;
import std.range;
import std.stdio;
import std.string;
import std.conv;

import std.digest.sha;
import aws.sigv4;
import std.math;

import arsd.dom;

public import aws.credentials;

auto safeInnerText(Element node) {
    if (node is null)
        return null;
    return node.innerText;
}

class AWSException : Exception
{
    immutable string type;
    immutable bool retriable;

    this(string type, bool retriable, string message, string file = __FILE__, size_t line = __LINE__, Throwable next = null)
    {
        super(type ~ ": " ~ message, file, line, next);
        this.type = type;
        this.retriable = retriable;
    }

    /**
      Returns the 'ThrottlingException' from 'com.amazon.coral.service#ThrottlingException'
     */
    @property string simpleType()
    {
        auto h = type.indexOf('#');
        if (h == -1) return type;
        return type[h+1..$];
    }
}

/**
  Thrown when the signature/authorization information is wrong
 */
class AuthorizationException : AWSException
{
    this(string type, string message, string file = __FILE__, size_t line = __LINE__, Throwable next = null)
    {
        super(type, false, message, file, line, next);
    }
}

abstract class RESTClient {
    import std.range : isInputRange, hasLength;
    import requests : Response;
    immutable string endpoint;
    immutable string baseUri;
    immutable string region;
    immutable string service;

    private AWSCredentialSource m_credsSource;

    this(string endpoint, string region, string service, AWSCredentialSource credsSource) nothrow @safe
    {
        this.region = region;
        if (endpoint.startsWith("http://")) {
            this.baseUri = endpoint;
            this.endpoint = endpoint[7..$];
        } else if (endpoint.startsWith("https://")) {
            this.baseUri = endpoint;
            this.endpoint = endpoint[8..$];
        } else {
            this.baseUri = "https://"~endpoint;
            this.endpoint = endpoint;
        }
        this.service = service;
        this.m_credsSource = credsSource;
    }

    private static string buildQueryParameterString(string[string] queryParameters)
    {
        import std.uri : encodeComponent;

        return queryParameters
            .byKeyValue
            .map!(kv => only(encodeComponent(kv.key), encodeComponent(kv.value)).joiner("="))
            .joiner("&")
            .text();
    }

    Response doRequest(string method, string resource, string[string] queryParameters, string[string] headers) shared {
        return (cast()this).doRequest(method, resource, queryParameters, headers);
    }
    Response doRequest(string method, string resource, string[string] queryParameters, string[string] headers)
    {
        import requests : Request;
        if (!resource.startsWith("/"))
            resource = "/" ~ resource;

        //Initialize credentials
        auto creds = m_credsSource.credentials(region ~ "/" ~ service);
        auto queryString = buildQueryParameterString(queryParameters);

        auto url = baseUri ~ resource;
        auto req = Request();

        req.method = method;
        req.addHeaders(headers);
        req.useStreaming = true;
        ubyte[] reqBody = null;
        req.addHeaders(["host": endpoint]);
        if (creds.sessionToken && !creds.sessionToken.empty)
            req.addHeaders(["x-amz-security-token": creds.sessionToken]);

        req.addHeaders(signRequest2(resource, method, req.headers, queryParameters, null, creds, region, service));

        return req.execute(method, url~"?"~queryString);
    }

    Response doUpload(Range)(string method, string resource, string[string] queryParameters,
                             string[string] headers, in string[] additionalSignedHeaders,
                             scope Range payload, ulong blockSize = 512*1024) if (isInputRange!Range && hasLength!Range) {
        return doUpload(method, resource, queryParameters, headers, additionalSignedHeaders, payload, payload.length, blockSize);
    }

    Response doUpload(Range)(string method, string resource, string[string] queryParameters,
                             string[string] headers, in string[] additionalSignedHeaders,
                             scope Range payload, size_t payloadSize, ulong blockSize = 512*1024) if (isInputRange!Range) {
        import requests : Request;

        //Calculate the body size upfront for the "Content-Length" header
        auto base16 = (ulong x) => ceil(log2(x)/4).to!ulong;
        enum ulong signatureSize = ";chunk-signature=".length + 64;
        immutable ulong numFullSizeBlocks = payloadSize / blockSize;
        immutable ulong lastBlockSize = payloadSize % blockSize;
        immutable ulong bodySize =  numFullSizeBlocks * (base16(blockSize)  + signatureSize + 4 + blockSize) //Full-Sized blocks (4 = 2*"\r\n")
            + (lastBlockSize  ? (base16(lastBlockSize) + signatureSize + 4 + lastBlockSize) : 0) //Part-Sized last block
            + (1 + signatureSize + 4); //Finishing 0-sized block


        if (!resource.startsWith("/"))
            resource = "/" ~ resource;

        //Initialize credentials
        auto creds = m_credsSource.credentials(region ~ "/" ~ service);

        auto url = baseUri ~ resource;
        auto req = Request();

        req.method = method;
        req.addHeaders(headers);
        req.useStreaming = true;
        ubyte[] reqBody = null;
        req.addHeaders(["host": endpoint]);
        if (creds.sessionToken && !creds.sessionToken.empty)
            req.addHeaders(["x-amz-security-token": creds.sessionToken]);

        req.addHeaders(signRequest2(url, method, req.headers, queryParameters, null, creds, region, service));

        auto isoTimeString = currentTimeString();
        req.addHeaders(["x-amz-date": isoTimeString]);
        auto date = isoTimeString.dateFromISOString;
        auto time = isoTimeString.timeFromISOString;

        if ("content-type" !in headers)
            req.addHeaders(["content-type": "application/octet-stream"]);

        req.addHeaders(["content-length": bodySize.to!string,
                        // "content-encoding": "aws-chunked",
                        "x-amz-content-sha256": streaming_payload_hash,
                        "x-amz-decoded-content-length": payloadSize.to!string]);

        auto canonicalRequest = CanonicalRequest(
                                                 method.to!string,
                                                 resource,
                                                 queryParameters,
                                                 [
                                                  "host":                         req.headers["host"],
                                                  // "content-encoding":             req.headers["content-encoding"],
                                                  "content-length":               req.headers["content-length"],
                                                  "x-amz-date":                   req.headers["x-amz-date"],
                                                  ]
                                                 );
        canonicalRequest.setStreamingPayloadHash(payloadSize.to!string);

        foreach (key; additionalSignedHeaders)
            canonicalRequest.headers[key] = req.headers[key];

        //Calculate the seed signature
        auto signableRequest = SignableRequest(date, time, region, service, canonicalRequest);
        auto key = signingKey(creds.accessKeySecret, date, region, service);
        auto binarySignature = key.sign(cast(ubyte[])signableRequest.signableString);

        auto credScope = date ~ "/" ~ region ~ "/" ~ service;
        auto authHeader = createSignatureHeader(creds.accessKeyID, credScope, canonicalRequest.headers, binarySignature);
        req.addHeaders(["authorization": authHeader]);

        string signature = binarySignature.toHexString().toLower();
        auto extension = (ubyte[] data) @trusted
            {
                // has to be trusted because compiler things toLower escapes the stack allocated hex-string
                auto chunk = SignableChunk(date, time, region, service, signature, hash(data));
                signature = key.sign(chunk.signableString.representation).toHexString().toLower();
                return text(";chunk-signature=", signature);
            };

        auto chunked = payload.chunkedContent(blockSize, extension);

        return req.execute(method, url, chunked);
    }

    Document readXML(Response response)
    {
        import std.algorithm : joiner;
        import std.array : array;
        ubyte[] content = response.receiveAsRange().joiner.array;
        return new Document(cast(string)content);
    }

    void checkForError(Response response, string file = __FILE__, size_t line = __LINE__, Throwable next = null)
    {
        if (response.code < 400)
            return; // No error

        auto document = readXML(response);
        auto code = document.querySelector("error code").safeInnerText;
        auto message = document.querySelector("error message").safeInnerText;
        throw makeException(code, response.code / 100 == 5, message, file, line, next);
    }

    AWSException makeException(string type, bool retriable, string message,
        string file = __FILE__, size_t line = __LINE__, Throwable next = null)
    {
        if (type == "UnrecognizedClientException" || type == "InvalidSignatureException")
            throw new AuthorizationException(type, message, file, line, next);
        return new AWSException(type, retriable, message, file, line, next);
    }
}

private auto currentTimeString()
{
    auto t = Clock.currTime(UTC());
    t.fracSecs = 0.seconds;
    return t.toISOString();
}

private string[string] signRequest2(string uri, string method, string[string] headers, string[string] queryParameters,
                         in ubyte[] requestBody, AWSCredentials creds, string region, string service)
{
    auto timeString = currentTimeString();
    auto dateString = dateFromISOString(timeString);
    auto credScope = dateString ~ "/" ~ region ~ "/" ~ service;

    SignableRequest signRequest;
    signRequest.dateString = dateString;
    signRequest.timeStringUTC = timeFromISOString(timeString);
    signRequest.region = region;
    signRequest.service = service;
    signRequest.canonicalRequest.method = method;

    auto pos = uri.indexOf("?");
    if (pos < 0)
        pos = uri.length;

    signRequest.canonicalRequest.uri = uri[0..pos];
    signRequest.canonicalRequest.queryParameters = queryParameters;

    string[string] newHeaders = ["x-amz-date": timeString];
    import std.algorithm : startsWith;
    import std.range : chain;
    foreach (x; chain(headers.byKeyValue, newHeaders.byKeyValue)) {
        auto lower = x.key.toLower();
        if (lower == "host" || lower.startsWith("x-amz-"))
            signRequest.canonicalRequest.headers[lower] = x.value;
    }
    signRequest.canonicalRequest.setPayload(requestBody);
    newHeaders["x-amz-content-sha256"] = signRequest.canonicalRequest.payloadHash;

    ubyte[32] signKey = signingKey(creds.accessKeySecret, dateString, region, service);
    ubyte[] stringToSign = cast(ubyte[])signableString(signRequest);

    auto signature = sign(signKey, stringToSign);
    auto authHeader = createSignatureHeader(creds.accessKeyID, credScope, signRequest.canonicalRequest.headers, signature);
    newHeaders["authorization"] = authHeader;

    return newHeaders;
}

struct ChunkedContent(Range) if (is(ElementType!Range == ubyte) || is(ElementType!Range == ubyte[])) {
    enum Position {
        data,
        finalizer,
        end
    }
    static if (is(ElementType!Range == ubyte)) {
        import std.range : chunks, Chunks;
        Chunks!Range range;
    } else {
        Range range;
    }
    alias ExtensionCallback = string delegate(ubyte[]);
    ExtensionCallback extension;
    static ubyte[] delimiter = ['\r','\n'];
    Position pos;
    this(Range range, size_t chunkSize, ExtensionCallback cb) {
        static if (is(ElementType!Range == ubyte)) {
            this.range = range.chunks(chunkSize);
        } else
            this.range = range;
        this.extension = cb;
        pos = range.empty ? Position.finalizer : Position.data;
    }
    bool empty() {
        return pos == Position.end;
    }
    auto front() {
        import std.format : format;
        ubyte[] data;
        if (pos == Position.data)
            data = range.front;
        string length = format("%x", data.length);
        string headerString = extension != null ? length ~ extension(data) : length;
        ubyte[] header = cast(ubyte[])headerString.representation;
        import std.array : join;
        return join([header, delimiter, data, delimiter]);
    }
    void popFront() {
        if (pos != Position.data)
            pos = Position.end;
        else {
            range.popFront();
            while (!range.empty) {
                if (range.front.length != 0)
                    break;
                range.popFront();
            }
            pos = range.empty ? Position.finalizer : Position.data;
        }
    }
}

auto chunkedContent(Range)(Range range, size_t chunkSize, string delegate(ubyte[]) extension = null) {
    return ChunkedContent!(Range)(range, chunkSize, extension);
}

unittest {
    ubyte[] data = ['h','e','l','l','o',' ','w','o','r','l','d'];
    ubyte[][] expected = [[52, 13, 10, 104, 101, 108, 108, 13, 10], [52, 13, 10, 111, 32, 119, 111, 13, 10], [51, 13, 10, 114, 108, 100, 13, 10], [48, 13, 10, 13, 10]];
    assert(data.chunkedContent(4).map!(i => i.array).array() == expected);
}

unittest {
    ubyte[] data = ['h','e','l','l','o',' ','w','o','r','l','d'];
    ubyte[][] expected = [[98, 13, 10, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 13, 10], [48, 13, 10, 13, 10]];
    assert(data.chunkedContent(11).map!(i => i.array).array() == expected);
}

unittest {
    ubyte[] data = ['h','e','l','l','o',' ','w','o','r','l','d'];
    ubyte[][] expected = [[52, 13, 10, 104, 101, 108, 108, 13, 10], [52, 13, 10, 111, 32, 119, 111, 13, 10], [51, 13, 10, 114, 108, 100, 13, 10], [48, 13, 10, 13, 10]];
    string delegate(ubyte[]) extension = (ubyte[] data) {
        return "";
    };
    assert(data.chunkedContent(4, extension).map!(i => i.array).array() == expected);
}

unittest {
    ubyte[] data = ['h','e','l','l','o',' ','w','o','r','l','d'];
    string delegate(ubyte[]) extension = (ubyte[] data) {
        return ";chunk-signature=CHECKCHECK";
    };
    ubyte[][] expected = [[52, 59, 99, 104, 117, 110, 107, 45, 115, 105, 103, 110, 97, 116, 117, 114, 101, 61, 67, 72, 69, 67, 75, 67, 72, 69, 67, 75, 13, 10, 104, 101, 108, 108, 13, 10], [52, 59, 99, 104, 117, 110, 107, 45, 115, 105, 103, 110, 97, 116, 117, 114, 101, 61, 67, 72, 69, 67, 75, 67, 72, 69, 67, 75, 13, 10, 111, 32, 119, 111, 13, 10], [51, 59, 99, 104, 117, 110, 107, 45, 115, 105, 103, 110, 97, 116, 117, 114, 101, 61, 67, 72, 69, 67, 75, 67, 72, 69, 67, 75, 13, 10, 114, 108, 100, 13, 10], [48, 59, 99, 104, 117, 110, 107, 45, 115, 105, 103, 110, 97, 116, 117, 114, 101, 61, 67, 72, 69, 67, 75, 67, 72, 69, 67, 75, 13, 10, 13, 10]];
    assert(data.chunkedContent(4, extension).map!(i => i.array).array() == expected);
}
