module vibe.aws.s3;

import vibe.d;

import vibe.aws.aws;
import vibe.aws.credentials;
import vibe.aws.sigv4;

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

auto listFilesRecursive(S3 client, string path = null)
{
    if(!path.empty && !path.endsWith("/"))
        path ~= "/";
    return S3Resources(client, null, path);
}

auto listFiles(S3 client, string path = null)
{
    if(!path.empty && !path.endsWith("/"))
        path ~= "/";
    return S3Resources(client, "/", path);
}

auto listFolders(S3 client, string path = null)
{
    if(!path.empty && !path.endsWith("/"))
        path ~= "/";
    return S3Prefixes(client, "/", path);
}

struct S3Resources
{
    import std.range.primitives;
    mixin _S3Common;

    auto front() @property
    {
        assert(!empty);
        return res.resources.front;
    }

    auto empty() const @property
    {
        return res.resources.empty;
    }

    auto popFront()
    {
        assert(!empty);
        res.resources.popFront;
        if(empty && res.isTruncated)
        {
            next;
        }
    }

}

struct S3Prefixes
{
    import std.range.primitives;
    mixin _S3Common;

    auto front() @property
    {
        assert(!empty);
        return res.commonPrefixes.front;
    }

    auto empty() const @property
    {
        return res.commonPrefixes.empty;
    }

    auto popFront()
    {
        assert(!empty);
        res.commonPrefixes.popFront;
        if(empty && res.isTruncated)
        {
            next;
        }
    }
}

private mixin template _S3Common()
{
    private S3 client;
    private BucketListResult res;
    private string delimiter;
    private string prefix;
    private uint maxKeys;

    private void next()
    {
        res = client.list(delimiter, prefix, res.nextMarker, maxKeys);
    }

    @disable this();

    this(S3 client, string delimiter, string prefix, uint maxKeys = 0)
    {
        this.client = client;
        this.delimiter = delimiter;
        this.prefix = prefix;
        this.maxKeys = maxKeys;
        next();
    }

    auto save() @property
    {
        return this;
    }
}

class S3 : RESTClient
{
    private string bucket;

    this(string bucket, string region, AWSCredentialSource credsSource, ClientConfiguration config = ClientConfiguration())
    {
        this.bucket = bucket;
        super(bucket ~ (region ? ".s3-" ~ region ~ ".amazonaws.com" : ".s3.amazonaws.com"), region, "s3", credsSource, config);
    }

    auto list(string delimiter = null, string prefix = null, string marker = null, uint maxKeys = 0)
    {
        assert(maxKeys <= 1000);

        import memutils.all;
        import std.stdio;
        import std.conv;

        InetHeaderMap headers;
        string[string] queryParameters;

        if (delimiter !is null)
            queryParameters["delimiter"] = delimiter;

        if (prefix !is null)
            queryParameters["prefix"] = prefix;

        if (marker !is null)
            queryParameters["marker"] = marker;

        if (maxKeys)
            queryParameters["max-keys"] = maxKeys.to!string;

        auto resp = doRequest(HTTPMethod.GET, "/", queryParameters, headers);
        auto response = readXML(resp);
        resp.dropBody();
        resp.destroy();

        BucketListResult result;
        result.name = response.parseXPath("/ListBucketResult/Name")[0].getCData;
        result.prefix = response.parseXPath("/ListBucketResult/Prefix")[0].getCData;
        result.marker = response.parseXPath("/ListBucketResult/Marker")[0].getCData;
        result.maxKeys = response.parseXPath("/ListBucketResult/MaxKeys")[0].getCData.to!uint;
        result.isTruncated = response.parseXPath("/ListBucketResult/IsTruncated")[0].getCData.toLower.to!bool;

        if (result.isTruncated)
            result.nextMarker = response.parseXPath("/ListBucketResult/NextMarker")[0].getCData;

        auto entries = response.parseXPath("/ListBucketResult/Contents");

        result.resources.reserve = 1000;
        foreach(node; entries)
        {
            BucketListResult.S3Resource entry;
            BucketListResult.S3Resource.Owner owner;

            entry.key = node.parseXPath("Key")[0].getCData;
            entry.lastModfied = node.parseXPath("LastModified")[0].getCData;
            entry.etag = node.parseXPath("ETag")[0].getCData;
            entry.size = node.parseXPath("Size")[0].getCData.to!ulong;
            entry.storageClass = node.parseXPath("StorageClass")[0].getCData.toImpl!StorageClass;

            result.resources.assumeSafeAppend ~= entry;
        }
        result.resources.reserve = result.resources.length;

        result.commonPrefixes.reserve = 1000;
        entries = response.parseXPath("/ListBucketResult/CommonPrefixes/Prefix");
        foreach(node; entries)
            result.commonPrefixes.assumeSafeAppend ~= node.getCData;
        result.commonPrefixes.reserve = result.commonPrefixes.length;

        return result;
    }

    void upload(string resource, RandomAccessStream input, string contentType = "application/octet-stream", 
                StorageClass storageClass = StorageClass.STANDARD, ulong chunkSize = 512*1024)
    {
        InetHeaderMap headers;
        headers["Content-Type"] = contentType;
        headers["x-amz-storage-class"] = storageClass.to!string;
        string[] signedHeaders = ["x-amz-storage-class"];
        auto httpResp = doUpload(HTTPMethod.PUT, resource, headers, signedHeaders, input, chunkSize);
        httpResp.dropBody();
        httpResp.destroy();
    }

    void info(string resource, scope void delegate(scope HTTPClientResponse) del,
                string[string] queryParameters = null, InetHeaderMap headers = InetHeaderMap.init)
    {
        auto httpResp = doRequest(HTTPMethod.HEAD, resource, queryParameters, headers);
        scope(exit)
        {
            httpResp.dropBody();
            httpResp.destroy();
        }
        del(httpResp);
    }

    void download(string resource, scope void delegate(scope HTTPClientResponse) del,
                string[string] queryParameters = null, InetHeaderMap headers = InetHeaderMap.init)
    {
        auto httpResp = doRequest(HTTPMethod.GET, resource, queryParameters, headers);
        scope(exit)
        {
            httpResp.dropBody();
            httpResp.destroy();
        }
        del(httpResp);
    }

    /++
    Returns:
        Response headers list, which has type  DictionaryList!(string,false,12L,false)
    +/
    auto download(string resource, scope void delegate(scope InputStream) del,
                string[string] queryParameters = null, InetHeaderMap headers = InetHeaderMap.init)
    {
        typeof(HTTPClientResponse.headers) ret;
        download(resource, (scope HTTPClientResponse resp) {
            ret = resp.headers;
            del(resp.bodyReader);
        }, queryParameters, headers);
        return ret;
    }

    /// ditto
    auto download(string resource, scope OutputStream stream,
                string[string] queryParameters = null, InetHeaderMap headers = InetHeaderMap.init)
    {
        return download(resource, (scope InputStream input) { stream.write(input); }, queryParameters, headers);
    }

    /// ditto
    auto download(string resource, string saveTo,
                string[string] queryParameters = null, InetHeaderMap headers = InetHeaderMap.init)
    {
        auto file = openFile(saveTo, FileMode.createTrunc);
        scope(exit)
            file.close();
        return download(resource, file, queryParameters, headers);
    }
}
