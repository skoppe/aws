import vibe.d;

import vibe.aws.aws;
import vibe.aws.credentials;
import vibe.aws.s3;
import std.process : environment;

import std.array;
import std.algorithm;

shared static this()
{
//    setLogLevel(LogLevel.trace);

    //Use the environment variables "AWS_ACCESS_KEY_ID",
    //"AWS_SECRET_KEY", "S3_EXAMPLE_BUCKET" and "S3_EXAMPLE_REGION"
    //to configure this example.

    auto creds = new EnvAWSCredentials;
    auto bucket = environment.get("S3_EXAMPLE_BUCKET");
    auto region = environment.get("S3_EXAMPLE_REGION");

    auto cfg = ClientConfiguration();
    cfg.maxErrorRetry = 1;
    auto s3 = new S3(bucket,region,creds,cfg);

    auto mutex = new TaskMutex;
    auto condition = new TaskCondition(mutex);
    int runningTasks = 3;

    setTimer(1.seconds, {
        synchronized(mutex)
            runningTasks++;

        scope(exit)
            synchronized(mutex)
                if (--runningTasks == 0)
                    condition.notify();
        synchronized(mutex)
        {
            logInfo("== listFolders begin ==");
            s3.listFolders.each!logInfo;
            logInfo("== listFolders end ==");
        }
    });

    setTimer(1.seconds, {
        synchronized(mutex)
            runningTasks++;

        scope(exit)
            synchronized(mutex)
                if (--runningTasks == 0)
                    condition.notify();

        synchronized(mutex)
        {
            logInfo("== listFiles begin ==");
            s3.listFiles.map!(a => a.key).each!logInfo;
            logInfo("== listFiles end ==");
        }
    });

    setTimer(1.seconds, {
        synchronized(mutex)
            runningTasks++;

        scope(exit)
            synchronized(mutex)
                if (--runningTasks == 0)
                    condition.notify();

        synchronized(mutex)
        {
            logInfo("== listFiles begin data ==");
            s3.listFiles("data").map!(a => a.key).each!logInfo;
            logInfo("== listFiles end ==");
        }
    });

    setTimer(1.seconds, {
        synchronized(mutex)
            runningTasks++;

        scope(exit)
            synchronized(mutex)
                if (--runningTasks == 0)
                    condition.notify();

        synchronized(mutex)
        {
            logInfo("== listFilesRecursive begin data ==");
            s3.listFilesRecursive("data").map!(a => a.key).each!logInfo;
            logInfo("== listFilesRecursive end ==");
        }
    });

    setTimer(1.msecs, {
        synchronized(mutex)
            while(true)
            {
                condition.wait();
                if (runningTasks == 0)
                {
                    exitEventLoop();
                    break;
                }
            }
    });
}

