import vibe.d;

import vibe.aws.credentials;
import vibe.aws.s3;
import std.process : environment;

shared static this()
{
    //Use the environment variables "AWS_ACCESS_KEY_ID",
    //"AWS_ACCESS_KEY", "S3_EXAMPLE_BUCKET" and "S3_EXAMPLE_REGION"
    //to configure this example.

    auto creds = new EnvAWSCredentials;
    auto bucket = environment.get("S3_EXAMPLE_BUCKET");
    auto region = environment.get("S3_EXAMPLE_REGION");

    auto sss = new S3(bucket,region,creds);

    setTimer(1.seconds, {
        sss.put("test.txt", openFile("test.txt"), "text/plain");
    });
}

