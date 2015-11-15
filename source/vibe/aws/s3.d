module vibe.aws.s3;

import vibe.d;

import vibe.aws.aws;
import vibe.aws.credentials;
import vibe.aws.sigv4;

class S3 : RESTClient
{
private:
    string bucket;

public:
    enum StorageClass: string
    {
        STANDARD = "STANDARD",
        REDUCED_REDUNDANCY = "REDUCED_REDUNDANCY",
        GLACIER = "GLACIER"
    }

    this(string bucket, string region, AWSCredentialSource credsSource, ClientConfiguration config = ClientConfiguration())
    {
        this.bucket = bucket;
        super(bucket ~ ".s3-" ~ region ~ ".amazonaws.com", region, "s3", credsSource, config);
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

        auto response = readXML(doRequest(HTTPMethod.GET, "/", queryParameters, headers));

        struct BucketListResult
        {
            struct S3Resource
            {
                struct Owner
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
            ulong maxKeys;
            bool isTruncated;
            S3Resource[] resources;
            string[] commonPrefixes;
        }

        BucketListResult result;
        result.name = response.parseXPath("/ListBucketResult/Name")[0].getCData;
        result.prefix = response.parseXPath("/ListBucketResult/Prefix")[0].getCData;
        result.marker = response.parseXPath("/ListBucketResult/Marker")[0].getCData;
        result.maxKeys = response.parseXPath("/ListBucketResult/MaxKeys")[0].getCData.to!ulong;
        result.isTruncated = response.parseXPath("/ListBucketResult/IsTruncated")[0].getCData.toLower.to!bool;

        if (result.isTruncated)
            result.nextMarker = response.parseXPath("/ListBucketResult/NextMarker")[0].getCData;

        auto entries = response.parseXPath("/ListBucketResult/Contents");
        foreach(node; entries)
        {
            BucketListResult.S3Resource entry;
            BucketListResult.S3Resource.Owner owner;

            entry.key = node.parseXPath("Key")[0].getCData;
            entry.lastModfied = node.parseXPath("LastModified")[0].getCData;
            entry.etag = node.parseXPath("ETag")[0].getCData;
            entry.size = node.parseXPath("Size")[0].getCData.to!ulong;
            entry.storageClass = node.parseXPath("StorageClass")[0].getCData.toImpl!StorageClass;

            result.resources ~= entry;
        }

        entries = response.parseXPath("/ListBucketResult/CommonPrefixes/Prefix");
        foreach(node; entries)
            result.commonPrefixes ~= node.getCData;

        return result;
    }

    void upload(string resource, RandomAccessStream input, string contentType = "application/octet-stream", 
                StorageClass storageClass = StorageClass.STANDARD, ulong chunkSize = 512*1024)
    {
        InetHeaderMap headers;
        headers["Content-Type"] = contentType;
        headers["x-amz-storage-class"] = storageClass.to!string;
        string[] signedHeaders = ["x-amz-storage-class"];
        doUpload(HTTPMethod.PUT, resource, headers, signedHeaders, input, chunkSize);
    }
}