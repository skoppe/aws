module vibe.aws.s3;

import vibe.d;

import vibe.aws.aws;
import vibe.aws.credentials;
import vibe.aws.sigv4;

class S3 : AWSClient
{
private:
    string bucket;

public:
    this(string bucket, string region, AWSCredentialSource credsSource)
    {
        this.bucket = bucket;
        super("s3-" ~ region ~ ".amazonaws.com/" ~ bucket, region, "s3", credsSource);
    }

    void put(string resource, RandomAccessStream input, 
             string contentType = "application/octet-stream", ulong chunkSize = 512*1024
            )
    {
        InetHeaderMap headers;
        headers["Content-Type"] = contentType;
        doRESTUpload(HTTPMethod.PUT, resource, headers, input, input.size, chunkSize);
    }
}