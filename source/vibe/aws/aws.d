/**
  Vibe-based AWS client
 */

module vibe.aws.aws;

import std.algorithm;
import std.datetime;
import std.random;
import std.range;
import std.stdio;
import std.string;
import std.conv;

import std.digest.sha;
import vibe.aws.sigv4;
import std.math;

import arsd.dom;

public import vibe.aws.credentials;

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
  Configuraton for AWS clients
 */
struct ClientConfiguration
{
    uint maxErrorRetry = 3;
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
    import requests : Response;
    immutable string endpoint;
    immutable string baseUri;
    immutable string region;
    immutable string service;

    private AWSCredentialSource m_credsSource;
    private ClientConfiguration m_config;

    this(string endpoint, string region, string service, AWSCredentialSource credsSource, ClientConfiguration config=ClientConfiguration())
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
        this.m_config = config;
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

    Response doRequest(string method, string resource, string[string] queryParameters, string[string] headers)
    {
        import requests : Request;
        if (!resource.startsWith("/"))
            resource = "/" ~ resource;

        //Initialize credentials
        auto creds = m_credsSource.credentials(region ~ "/" ~ service);
        auto queryString = buildQueryParameterString(queryParameters);

        auto url = baseUri ~ resource;// ~ "?" ~ queryString;
        auto req = Request();

        req.method = method;
        req.addHeaders(headers);
        req.useStreaming = true;
        ubyte[] reqBody = null;
        req.addHeaders(["host": endpoint, "Accept-Encoding": "gzip,deflate", "User-Agent": "MinIO (linux; amd64) minio-go/v7.0.11 mcli/RELEASE.2021-06-08T01-29-37Z", "connection": "Keep-Alive"]);
        if (creds.sessionToken && !creds.sessionToken.empty)
            req.addHeaders(["x-amz-security-token": creds.sessionToken]);

        req.addHeaders(signRequest2(resource, method, req.headers, queryParameters, null, creds, region, service));

        import std.stdio;
        writeln(url~"?"~queryString);
        writeln(req.headers);
        auto resp = req.get(url~"?"~queryString);
        checkForError2(resp);
        return resp;
    }

    import std.range : isInputRange, hasLength;
    Response doUpload(Range)(string method, string resource, string[string] queryParameters,
                                string[string] headers, in string[] additionalSignedHeaders,
                                scope Range payload, ulong blockSize = 512*1024)
         if (isInputRange!Range && hasLength!Range)
    {
        import requests : Request;
        size_t payloadSize = payload.length;
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


            //Since we might be doing retries, update the date
            auto isoTimeString = currentTimeString();
            req.addHeaders(["x-amz-date": isoTimeString]);
            auto date = isoTimeString.dateFromISOString;
            auto time = isoTimeString.timeFromISOString;
            //Adjust the headers necessary for a chunked transmission
            // string newEncoding = "aws-chunked";
            // if ("content-encoding" in headers)
            //     newEncoding = headers["content-encoding"];
            
            if ("content-type" !in headers)
            //     req.contentType = headers["Content-Type"];
            // else
                req.addHeaders(["content-type": "application/octet-stream"]);
            
                           req.addHeaders(["content-length": bodySize.to!string,
                                           // "content-encoding": newEncoding,
                                           "x-amz-content-sha256": "STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
                                           "x-amz-decoded-content-length": payloadSize.to!string]);

            //Seems not to be working properly (S3 returns error if "Content-Length" is not used)
//                req.headers["Transfer-Encoding"] = "chunked";
//                if ("Content-Length" in headers)
//                    req.headers.remove("Content-Length");

            auto canonicalRequest = CanonicalRequest(
                    method.to!string,
                    resource,
                    queryParameters,
                    [
                        "host":                         req.headers["host"],
                        // "content-encoding":             req.headers["content-encoding"],
                        "content-length":               req.headers["content-length"],
                        "x-amz-content-sha256":         req.headers["x-amz-content-sha256"],
                        "x-amz-date":                   req.headers["x-amz-date"],
                        "x-amz-decoded-content-length": req.headers["x-amz-decoded-content-length"],
//                        "transfer-encoding":            req.headers["Transfer-Encoding"],
                    ],
                    null
                );

            foreach (key; additionalSignedHeaders)
                canonicalRequest.headers[key] = req.headers[key];

            //Calculate the seed signature
            auto signableRequest = SignableRequest(date, time, region, service, canonicalRequest);
            auto key = signingKey(creds.accessKeySecret, date, region, service);
            auto binarySignature = key.sign(cast(ubyte[])signableRequest.signableStringForStream);

            auto credScope = date ~ "/" ~ region ~ "/" ~ service;
            auto authHeader = createSignatureHeader(creds.accessKeyID, credScope, canonicalRequest.headers, binarySignature);
            req.addHeaders(["authorization": authHeader]);


            string signature = binarySignature.toHexString().toLower();
            auto extension = (ubyte[] data) @safe
                            {
                                auto chunk = SignableChunk(date, time, region, service, signature, hash(data));
                                signature = key.sign(chunk.signableString.representation).toHexString().toLower();
                                return ";chunk-signature=" ~ signature;
                            };

            auto chunked = payload.chunkedContent(blockSize, extension);

            auto resp = req.execute(method, url, chunked);
        checkForError2(resp);
        return resp;
    }

    /+
    HTTPClientResponse doUpload(HTTPMethod method, string resource, string[string] queryParameters,
                                in InetHeaderMap headers, in string[] additionalSignedHeaders,
                                scope RandomAccessStream payload, ulong blockSize = 512*1024)
    {
        auto retries = ExponentialBackoff(m_config.maxErrorRetry);
        foreach(triesLeft; retries)
        {
            payload.seek(0);
            return doUpload(method, resource, queryParameters, headers, additionalSignedHeaders,
                            payload, payload.size, blockSize);
        }
        assert(0);
    }

    HTTPClientResponse doUpload(HTTPMethod method, string resource, string[string] queryParameters,
                                in InetHeaderMap headers, in string[] additionalSignedHeaders,
                                scope InputStream payload, ulong payloadSize, ulong blockSize = 512*1024)
    {
        //Calculate the body size upfront for the "Content-Length" header
        logDebug("doUpload for resource %s", resource);
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
        auto credScope = region ~ "/" ~ service;
        auto creds = m_credsSource.credentials(credScope);

        HTTPClientResponse resp;
        scope(failure) 
            if (resp)
            {
                resp.dropBody();
                resp.destroy();
            }

        auto url = "https://" ~ endpoint ~ resource;
        if (queryParameters !is null)
        {
            url ~= "?" ~ buildQueryParameterString(queryParameters);
        }

        resp = requestHTTP(url, (scope HTTPClientRequest req) {
            req.method = method;
            
            //Initialize the headers
            foreach(key, value; headers)
                req.headers[key] = value;

            //Since we might be doing retries, update the date
            auto isoTimeString = currentTimeString();
            req.headers["x-amz-date"] = isoTimeString;
            auto date = isoTimeString.dateFromISOString;
            auto time = isoTimeString.timeFromISOString;
            
            //Adjust the headers necessary for a chunked transmission
            string newEncoding = "aws-chunked";
            if ("Content-Encoding" in headers)
                newEncoding ~= "," ~headers["Content-Encoding"];
            
            if ("Content-Type" in headers)
                req.contentType = headers["Content-Type"];
            else
                req.contentType = "application/octet-stream";
            
            req.headers["Content-Length"] = bodySize.to!string;
            req.headers["Content-Encoding"] = newEncoding;
            req.headers["x-amz-content-sha256"] = "STREAMING-AWS4-HMAC-SHA256-PAYLOAD";
            req.headers["x-amz-decoded-content-length"] = payloadSize.to!string;

            //Seems not to be working properly (S3 returns error if "Content-Length" is not used)
//                req.headers["Transfer-Encoding"] = "chunked";
//                if ("Content-Length" in headers)
//                    req.headers.remove("Content-Length");

            auto canonicalRequest = CanonicalRequest(
                    method.to!string,
                    resource,
                    queryParameters,
                    [
                        "host":                         req.headers["host"],
                        "content-encoding":             req.headers["Content-Encoding"],
                        "content-length":               req.headers["Content-Length"],
                        "x-amz-content-sha256":         req.headers["x-amz-content-sha256"],
                        "x-amz-date":                   req.headers["x-amz-date"],
                        "x-amz-decoded-content-length": req.headers["x-amz-decoded-content-length"],
//                        "transfer-encoding":            req.headers["Transfer-Encoding"],
                    ],
                    null
                );

            foreach (key; additionalSignedHeaders)
                canonicalRequest.headers[key] = req.headers[key];

            //Calculate the seed signature
            auto signableRequest = SignableRequest(date, time, region, service, canonicalRequest);
            auto key = signingKey(creds.accessKeySecret, date, region, service);
            auto binarySignature = key.sign(cast(ubyte[])signableRequest.signableStringForStream);

            auto credScope = date ~ "/" ~ region ~ "/" ~ service;
            auto authHeader = createSignatureHeader(creds.accessKeyID, credScope, canonicalRequest.headers, binarySignature);
            req.headers["authorization"] = authHeader;

            //Write the data in chunks to the stream
            auto outputStream = createChunkedOutputStream(req.bodyWriter);
            outputStream.maxBufferSize = blockSize;
//            auto outputStream = cast(ChunkedOutputStream) req.bodyWriter;
//            enforce(outputStream !is null);

            string signature = binarySignature.toHexString().toLower();
            outputStream.chunkExtensionCallback = (in ubyte[] data) @safe
            {
                logDebug("doUpload: chunkExtensionCallback data is %s bytes", data.length);
                auto chunk = SignableChunk(date, time, region, service, signature, hash(data));
                signature = key.sign(chunk.signableString.representation).toHexString().toLower();
                return "chunk-signature=" ~ signature;
            };
            logDebug("doUpload: write payload");
            payload.pipe(outputStream);
            logDebug("doUpload: finalize ... ");
            outputStream.finalize;
            logDebug("doUpload: finalized.");
        });
        checkForError(resp);
        return resp;
    }+/

    Document readXML2(Response response)
    {
        import std.algorithm : joiner;
        import std.array : array;
        ubyte[] content = response.receiveAsRange().joiner.array;
        return new Document(cast(string)content);
    }

    void checkForError2(Response response, string file = __FILE__, size_t line = __LINE__, Throwable next = null)
    {
        if (response.code < 400)
            return; // No error

        auto document = readXML2(response);
        auto code = document.querySelector("Error Code").safeInnerText;
        auto message = document.querySelector("Error Message").safeInnerText;
        throw makeException(code, response.code / 100 == 5, message, file, line, next);
    }
    // Document readXML(HTTPClientResponse response)
    // {
    //     auto stringBuilder = appender!string;
    //     auto reader = response.bodyReader;

    //     auto buffer = memutils.all.ThreadMem.alloc!(ubyte[])(1024);
    //     scope(exit)
    //         memutils.all.ThreadMem.free(buffer);

    //     while(reader.leastSize > 0)
    //     {
    //         auto size = min(reader.leastSize,buffer.length);
    //         auto bytes = buffer[0..size];
    //         reader.read(bytes);
    //         stringBuilder.put(bytes);
    //     }
    //     import std.stdio;
    //     writeln(stringBuilder.data);
    //     return new Document(stringBuilder.data);
    // }

    // void checkForError(HTTPClientResponse response, string file = __FILE__, size_t line = __LINE__, Throwable next = null)
    // {
    //     if (response.statusCode < 400)
    //         return; // No error

    //     auto document = readXML(response);
    //     auto code = document.querySelector("Error Code").safeInnerText;
    //     auto message = document.querySelector("Error Message").safeInnerText;
    //     logError(message);
    //     throw makeException(code, response.statusCode / 100 == 5, message, file, line, next);
    // }

    AWSException makeException(string type, bool retriable, string message,
        string file = __FILE__, size_t line = __LINE__, Throwable next = null)
    {
        if (type == "UnrecognizedClientException" || type == "InvalidSignatureException")
            throw new AuthorizationException(type, message, file, line, next);
        return new AWSException(type, retriable, message, file, line, next);
    }
}

/+
class AWSClient {
    protected static immutable exceptionPrefix = "com.amazon.coral.service#";

    immutable string endpoint;
    immutable string region;
    immutable string service;

    private AWSCredentialSource m_credsSource;
    private ClientConfiguration m_config;

    this(string endpoint, string region, string service, AWSCredentialSource credsSource, ClientConfiguration config=ClientConfiguration()) 
    {
        this.region = region;
        this.endpoint = endpoint;
        this.service = service;
        this.m_credsSource = credsSource;
        this.m_config = config;
    }

    AWSResponse doRequest(string operation, Json request)
    {
        auto backoff = ExponentialBackoff(m_config.maxErrorRetry);

        for (; !backoff.finished; backoff.inc())
        {
            auto credScope = region ~ "/" ~ service;
            auto creds = m_credsSource.credentials(credScope);
            HTTPClientResponse resp;
            try
            {
                // FIXME: Auto-retries for retriable errors
                // FIXME: Report credential errors and retry for failed credentials
                 resp = requestHTTP("https://" ~ endpoint ~ "/", (scope req) {
                    auto timeString = currentTimeString();
                    auto jsonString = cast(ubyte[])request.toString();

                    req.method = HTTPMethod.POST;
                    req.headers["x-amz-target"] = operation;
                    req.headers["x-amz-date"] = currentTimeString();
                    req.headers["host"] = endpoint;
                    if (creds.sessionToken && !creds.sessionToken.empty)
                        req.headers["x-amz-security-token"] = creds.sessionToken;
                    req.contentType = "application/x-amz-json-1.1";
                    signRequest(req, null, jsonString, creds, timeString, region, service);
                    req.writeBody(jsonString);
                });

                checkForError(resp);

                return new AWSResponse(resp);
            }
            catch (AuthorizationException ex)
            {
                logWarn(ex.msg);
                // Report credentials as invalid. Will retry if possible.
                m_credsSource.credentialsInvalid(credScope, creds, ex.msg);
                resp.dropBody();
                resp.destroy();
                if (!backoff.canRetry) throw ex;
            }
            catch (AWSException ex)
            {
                logWarn(ex.msg);
                resp.dropBody();
                resp.destroy();
                // Retry if possible and retriable, otherwise give up.
                if (!backoff.canRetry || !ex.retriable) throw ex;
            } 
            catch (Throwable t) //ssl errors from ssl.d
            {
              if (!backoff.canRetry)
              {
                vibe.core.log.logError("no retries left, failing request");
                throw(t);
              }
            }
            backoff.sleep();
        }
        assert(0);
    }

    void checkForError(HTTPClientResponse response)
    {
        if (response.statusCode < 400) return; // No error

        auto bod = response.readJson();

        throw makeException(bod["__type"].get!string, response.statusCode / 100 == 5, bod["message"].opt!string(""));
    }

    AWSException makeException(string type, bool retriable, string message)
    {
        if (type == exceptionPrefix ~ "UnrecognizedClientException" || type == exceptionPrefix ~ "InvalidSignatureException")
            throw new AuthorizationException(type, message);
        return new AWSException(type, retriable, message);
    }
}+/

private auto currentTimeString()
{
    auto t = Clock.currTime(UTC());
    t.fracSecs = 0.seconds;
    return t.toISOString();
}

private string[string] signRequest2(string uri, string method, string[string] headers, string[string] queryParameters,
                         in ubyte[] requestBody, AWSCredentials creds, 
                         string region, string service)
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

    string[string] newHeaders = ["x-amz-date": timeString,
                                 "x-amz-content-sha256": sha256Of(requestBody).toHexString().toLower()];
    import std.algorithm : startsWith;
    import std.range : chain;
    foreach (x; chain(headers.byKeyValue, newHeaders.byKeyValue)) {
        auto lower = x.key.toLower();
        if (lower == "host" || lower.startsWith("x-amz-"))
            signRequest.canonicalRequest.headers[lower] = x.value;
    }
    signRequest.canonicalRequest.payload = requestBody;

    ubyte[] signKey = signingKey(creds.accessKeySecret, dateString, region, service);
    ubyte[] stringToSign = cast(ubyte[])signableString(signRequest);

    import std.stdio;
    writeln(signRequest.canonicalRequest.requestString);
    writeln(cast(string)stringToSign);
    auto signature = sign(signKey, stringToSign);

    auto authHeader = createSignatureHeader(creds.accessKeyID, credScope, signRequest.canonicalRequest.headers, signature);
    newHeaders["authorization"] = authHeader;

    return newHeaders;
}

// private void signRequest(HTTPClientRequest req, string[string] queryParameters,
//                          in ubyte[] requestBody, AWSCredentials creds, 
//                          string timeString, string region, string service)
// {
//     auto dateString = dateFromISOString(timeString);
//     auto credScope = dateString ~ "/" ~ region ~ "/" ~ service;

//     SignableRequest signRequest;
//     signRequest.dateString = dateString;
//     signRequest.timeStringUTC = timeFromISOString(timeString);
//     signRequest.region = region;
//     signRequest.service = service;
//     signRequest.canonicalRequest.method = req.method.to!string();

//     auto pos = req.requestURL.indexOf("?");
//     if (pos < 0)
//         pos = req.requestURL.length;
//     signRequest.canonicalRequest.uri = req.requestURL[0..pos];

//     signRequest.canonicalRequest.queryParameters = queryParameters;

//     import std.algorithm : startsWith;
//     auto reqHeaders = req.headers.toRepresentation;
//     foreach (x; reqHeaders) {
//         auto lower = x.key.toLower();
//         if (lower == "host" || lower.startsWith("x-amz-"))
//             signRequest.canonicalRequest.headers[x.key] = x.value;
//     }
//     signRequest.canonicalRequest.payload = requestBody;

//     ubyte[] signKey = signingKey(creds.accessKeySecret, dateString, region, service);
//     ubyte[] stringToSign = cast(ubyte[])signableString(signRequest);

//     auto signature = sign(signKey, stringToSign);

//     auto authHeader = createSignatureHeader(creds.accessKeyID, credScope, signRequest.canonicalRequest.headers, signature);
//     req.headers["authorization"] = authHeader;
// }

// class AWSResponse
// {
  
//     private Json m_body;

//     this(HTTPClientResponse response)
//     {
//         //m_response = response;
//         m_body = response.readJson();
//         response.dropBody();
//         response.destroy();
//     }
    
//     override string toString()
//     {
//       return m_body.toString();
//     }

//     @property Json responseBody() { return m_body; }
// }


enum Position {
    data,
    finalizer,
    end
}
struct ChunkedContent(Range) if (is(ElementType!Range == ubyte)) {
    import std.range : chunks;
    Chunks!Range range;
    alias ExtensionCallback = string delegate(ubyte[]);
    ExtensionCallback extension;
    static ubyte[] delimiter = ['\r','\n'];
    Position pos;
    this(Range range, size_t chunkSize, ExtensionCallback cb) {
        this.range = range.chunks(chunkSize);
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
        import std.algorithm : joiner;
        import std.array : join;
        auto j = join([header, delimiter, data, delimiter]);//.array();
        import std.stdio;
        writeln(j);
        return j;
    }
    void popFront() {
        if (pos != Position.data)
            pos = Position.end;
        else {
            range.popFront();
            pos = range.empty ? Position.finalizer : Position.data;
        }
    }
}

auto chunkedContent(Range)(Range range, size_t chunkSize, string delegate(ubyte[]) extension = null) {
    return ChunkedContent!(Range)(range, chunkSize, extension);
}
/+
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
+/
