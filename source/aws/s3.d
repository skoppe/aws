module aws.s3;

import aws.aws;
import aws.credentials;
import aws.sigv4;

import std.typecons: Tuple, tuple;
import std.string : toLower;

enum StorageClass: string
{
    STANDARD = "STANDARD",
    REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY",
    GLACIER = "GLACIER"
}

struct BucketListResult
{
    static struct S3Resource
    {
        static struct Owner
        {
            string id;
            string displayName;
        }

        string key;
        string lastModfied;
        string etag;
        ulong size;
        Owner owner;
        StorageClass storageClass;
    }

    string name;
    string prefix;
    string marker;
    string nextMarker;
    S3Resource[] resources;
    string[] commonPrefixes;
    uint maxKeys;
    bool isTruncated;
}

// auto listFilesRecursive(S3 client, string path = null)
// {
//     import std.algorithm : endsWith;
//     import std.range : empty;
//     if(!path.empty && !path.endsWith("/"))
//         path ~= "/";
//     return S3Resources(client, null, path);
// }

// auto listFiles(S3 client, string path = null)
// {
//     import std.algorithm : endsWith;
//     import std.range : empty;
//     if(!path.empty && !path.endsWith("/"))
//         path ~= "/";
//     return S3Resources(client, "/", path);
// }

// auto listFolders(S3 client, string path = null)
// {
//     import std.range : empty;
//     import std.algorithm : endsWith;
//     if(!path.empty && !path.endsWith("/"))
//         path ~= "/";
//     return S3Prefixes(client, "/", path);
// }

// struct S3Resources
// {
//     import std.range.primitives;
//     mixin _S3Common;

//     auto front() @property
//     {
//         assert(!empty);
//         return res.resources.front;
//     }

//     auto empty() const @property
//     {
//         return res.resources.empty;
//     }

//     auto popFront()
//     {
//         assert(!empty);
//         res.resources.popFront;
//         if(empty && res.isTruncated)
//         {
//             next;
//         }
//     }

// }

// struct S3Prefixes
// {
//     import std.range.primitives;
//     mixin _S3Common;

//     auto front() @property
//     {
//         assert(!empty);
//         return res.commonPrefixes.front;
//     }

//     auto empty() const @property
//     {
//         return res.commonPrefixes.empty;
//     }

//     auto popFront()
//     {
//         assert(!empty);
//         res.commonPrefixes.popFront;
//         if(empty && res.isTruncated)
//         {
//             next;
//         }
//     }
// }

// private mixin template _S3Common()
// {
//     private S3 client;
//     private BucketListResult res;
//     private string delimiter;
//     private string prefix;
//     private uint maxKeys;

//     private void next()
//     {
//         res = client.list(delimiter, prefix, res.nextMarker, maxKeys);
//     }

//     @disable this();

//     this(S3 client, string delimiter, string prefix, uint maxKeys = 0)
//     {
//         this.client = client;
//         this.delimiter = delimiter;
//         this.prefix = prefix;
//         this.maxKeys = maxKeys;
//         next();
//     }

//     auto save() @property
//     {
//         return this;
//     }
// }

import arsd.dom;

class S3 : RESTClient
{
    this(string endpoint, string region, AWSCredentialSource credsSource) nothrow @safe {
        super(endpoint, region, "s3", credsSource);
    }

    auto createBucket(string bucket) {
        string[string] headers;
        string[] signedHeaders = null;
        ubyte[] input = null;
        auto resp = doUpload("PUT", bucket, null, headers, signedHeaders, input, 1024);
        checkForError(resp);
    }

    auto list(string bucket, string delimiter = null, string prefix = null, string marker = null, uint maxKeys = 0)
    {
        assert(maxKeys <= 1000);

        import std.stdio;
        import std.conv;

        string[string] headers;
        string[string] queryParameters;
        queryParameters["list-type"] = "2";
        if (bucket !is null && bucket != "")
            queryParameters["encoding-type"] = "url";

        if (delimiter !is null)
            queryParameters["delimiter"] = delimiter;

        if (prefix !is null)
            queryParameters["prefix"] = prefix;
        else
            queryParameters["prefix"] = "";

        if (marker !is null)
            queryParameters["continuation-token"] = marker;

        if (maxKeys)
            queryParameters["max-keys"] = maxKeys.to!string;

        auto resp = doRequest("GET", bucket~"/", queryParameters, headers);
        checkForError(resp);
        auto response = readXML(resp);

        BucketListResult result;
        result.name = response.querySelector("listbucketresult name").safeInnerText;
        result.prefix = response.querySelector("listbucketresult prefix").safeInnerText;
        result.marker = response.querySelector("listbucketresult marker").safeInnerText;
        result.maxKeys = response.querySelector("listbucketresult maxkeys").safeInnerText.to!uint;
        result.isTruncated = response.querySelector("listbucketresult istruncated").safeInnerText.toLower.to!bool;

        if (result.isTruncated)
            result.nextMarker = response.querySelector("listbucketresult nextcontinuationtoken").safeInnerText;

        auto entries = response.querySelectorAll("listbucketresult contents");

        if (entries) {
          result.resources.reserve = 1000;
          foreach(node; entries)
            {
              BucketListResult.S3Resource entry;
              BucketListResult.S3Resource.Owner owner;

              entry.key = node.querySelector("key").safeInnerText;
              entry.lastModfied = node.querySelector("lastModified").safeInnerText;
              entry.etag = node.querySelector("etag").safeInnerText;
              entry.size = node.querySelector("size").safeInnerText.to!ulong;
              import std.conv;
              entry.storageClass = node.querySelector("storageclass").safeInnerText.to!StorageClass;

              result.resources.assumeSafeAppend ~= entry;
            }
          result.resources.reserve = result.resources.length;
        }

        auto prefixes = response.querySelectorAll("listbucketresult commonprefixes prefix");
        result.commonPrefixes.reserve = 1000;
        foreach(node; prefixes)
            result.commonPrefixes.assumeSafeAppend ~= node.innerText;
        result.commonPrefixes.reserve = result.commonPrefixes.length;

        return result;
    }

    void upload(InputStream)(
                              string bucket,
                string resource,
                InputStream input,
                string contentType = "application/octet-stream",
                StorageClass storageClass = StorageClass.STANDARD,
                size_t chunkSize = 512*1024,
                )
    {
        import std.conv : to;
        string[string] headers;
        headers["content-type"] = contentType;
        headers["x-amz-storage-class"] = storageClass.to!string;
        string[] signedHeaders = ["x-amz-storage-class"];
        auto resp = doUpload("PUT", bucket~"/"~resource, null, headers, signedHeaders, input, chunkSize);
        checkForError(resp);
    }

    auto download(string bucket, string resource,
                  string[string] queryParameters = null, string[string] headers = null)
    {
        auto resp = doRequest("GET", bucket~"/"~resource, queryParameters, headers);
        checkForError(resp);
        return resp;
    }

    auto info(string bucket, string resource, string[string] queryParameters = null, string[string] headers = null)
    {
        auto resp = doRequest("HEAD", bucket~"/"~resource, queryParameters, headers);
        checkForError(resp);
        return resp.responseHeaders;
    }
/+
    /++
    On_failure: aborts multipart upload.
    +/
    void multipartUpload(
        string resource,
        scope InputStream input,
        InetHeaderMap headers = InetHeaderMap.init,
        string contentType = "application/octet-stream",
        StorageClass storageClass = StorageClass.STANDARD, 
        SysTime expires = SysTime.init,
        size_t chunkSize = 512*1024,
        size_t partSize = 5*1024*1024,
        )
    {
        import vibe.d : logDebug, logWarn, createMemoryStream;
        import std.array: appender, uninitializedArray;
        import std.algorithm.comparison: min;
        import std.exception : enforce;
        logDebug("multipartUpload for %s ...", resource);
        enforce(partSize >= 5 * 1024 * 1024, "multipartUpload: minimal allowed part size is 5 MB.");
        auto id = startMultipartUpload(resource, headers, contentType, storageClass, expires);
        scope(failure)
        {
            logWarn("aborting multipart upload for resource=%s, uploadId=%s", resource, id);
            try
            {
                abortMultipartUpload(resource, id);
            }
            catch(Exception e)
            {
                logWarn(e.msg);
            }
        }

        auto buf = uninitializedArray!(ubyte[])(partSize);
        auto etags = appender!(Tuple!(string, size_t)[]);

        size_t least = input.leastSize;
        for(size_t part = 1;;part++)
        {
            size_t length;
            do
            {
                auto newLength = least + length;
                if(newLength > buf.length)
                    newLength = buf.length;
                input.read(buf[length .. newLength]);
                length = newLength;
                least = input.leastSize;
            }
            while(least && length < buf.length);
            logDebug("buf.length = %s", buf.length);
            logDebug("least = %s", least);
            logDebug("multipartUpload: sending %s bytes for part %s ...", length, part);
            auto etag = uploadPart(resource, id, part, createMemoryStream(buf[0 .. length], false), contentType, chunkSize);
            etags.put(tuple(etag, part));
            if(least == 0)
                break;
        }
        enforce(etags.data, "At least one part should be uploaded.");
        completeMultipartUpload(resource, id, etags.data);
    }

    string uploadPart(
        string resource,
        string id,
        size_t part,
        RandomAccessStream input,
        string contentType = "application/octet-stream",
        size_t chunkSize = 512*1024,
        )
    {
        import vibe.d : HTTPMethod, logDebug;
        import std.conv : to;
        string[string] queryParameters = [
            "partNumber": part.to!string,
            "uploadId": id,
        ];
        InetHeaderMap headers;
        headers["Content-Type"] = contentType;
        logDebug("uploadPart: doUpload ...");
        auto httpResp = doUpload(HTTPMethod.PUT, resource, queryParameters, headers, null, input, chunkSize);
        logDebug("uploadPart: doUpload finished.");
        httpResp.dropBody();
        auto etag = httpResp.headers["ETag"];
        httpResp.destroy();
        logDebug("uploadPart: finished.");
        return etag;
    }

    string startMultipartUpload(
        string resource,
        InetHeaderMap headers = InetHeaderMap.init,
        string contentType = "application/octet-stream", 
        StorageClass storageClass = StorageClass.STANDARD,
        SysTime expires = SysTime.init,
        )
    {
        import vibe.d : HTTPMethod;
        import std.conv : to;
        headers["Content-Type"] = contentType;
        headers["x-amz-storage-class"] = storageClass.to!string;
        string[] signedHeaders = ["x-amz-storage-class"];
        if(expires != SysTime.init)
        {
            expires.fracSecs = expires.fracSecs.init;
            headers["Expires"] = expires.toISOString; // HTTP format is different. So, we need to check if it is works.
        }
        auto httpResp = doRequest(HTTPMethod.POST, resource, ["uploads":null], headers);
        scope(exit)
        {
            httpResp.dropBody();
            httpResp.destroy();
        }
        auto document = readXML(httpResp);
        auto id = document.querySelector("InitiateMultipartUploadResult UploadId").safeInnerText;
        return id;
    }

    void completeMultipartUpload(
        string resource,
        string id,
        in Tuple!(string, size_t)[] parts,
        InetHeaderMap headers = InetHeaderMap.init,
        )
    {
        import vibe.d : HTTPMethod;
        import std.format;
        import std.array: appender;
        auto app = appender!(char[]);
        app.put(`<CompleteMultipartUpload>`);
        FormatSpec!char fmt;
        foreach(ref part; parts)
        {
            app.put(`<Part><PartNumber>`);
            app.formatValue(part[1], fmt);
            app.put(`</PartNumber><ETag>`);
            app.put(part[0]);
            app.put(`</ETag></Part>`);
        }
        app.put(`</CompleteMultipartUpload>`);
        auto httpResp = doRequest(HTTPMethod.POST, resource, ["uploadId":id], headers, cast(ubyte[])app.data);
        httpResp.dropBody();
        httpResp.destroy();
    }

    void abortMultipartUpload(string resource, string id)
    {
        import vibe.d : HTTPMethod;
        auto httpResp = doRequest(HTTPMethod.DELETE, resource, ["uploadId":id], InetHeaderMap.init);
        httpResp.dropBody();
        httpResp.destroy();
    }

    +/
}
