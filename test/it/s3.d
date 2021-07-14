import vibe.aws.s3;
import vibe.aws.aws;
import vibe.aws.credentials;


unittest {
    import std.array : appender;
    import std.stdio;
    auto creds = new StaticAWSCredentials("test", "test");

    auto region = "us-east-1";
    // auto region = "ams3";

    auto cfg = ClientConfiguration();
    // auto endpoint = "https://ams3.digitaloceanspaces.com";
    auto endpoint = "http://localhost:4566";
    cfg.maxErrorRetry = 1;
    auto s3 = new S3(endpoint,region,creds,cfg);

    s3.createBucket("test-bucket");
    s3.upload2("test-bucket", "myfile", cast(ubyte[])[48,49,50,51,52,53]);


    import std.algorithm : joiner;
    import std.array : array;
    s3.download2("test-bucket", "myfile").receiveAsRange.joiner().array().writeln();
    auto directories = appender!string;
    auto files = appender!string;

    string marker = null;
    while(true)
        {
            auto result = s3.list2("test-bucket", "/", null,marker,100);
            foreach(directory; result.commonPrefixes)
                directories.put(directory~"\n");

            foreach(file; result.resources)
                files.put(file.key~"\n");

            if (result.isTruncated)
                marker = result.nextMarker;
            else
                break;
        }


    writeln(directories);
    writeln(files);
}
