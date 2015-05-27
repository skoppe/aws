module vibe.aws.kinesis;

import std.base64;
import std.algorithm;
import std.array;
import vibe.data.json;
import vibe.aws.aws;
import vibe.aws.credentials;

class Kinesis : AWSClient
{
    private static immutable string apiVersion = "Kinesis_20131202";
    private string stream;

    this(string stream, string region, AWSCredentialSource credsSource)
    {
        this.stream = stream;
        super("kinesis." ~ region ~ ".amazonaws.com", region, "kinesis", credsSource);
    }

    auto putRecord(Record rec)
    {
        //  PartitionKey: Determines which shard in the stream the data record is assigned to. Partition keys are Unicode strings with a maximum length limit of 256 characters for each key. Amazon Kinesis uses the partition key as input to a hash function that maps the partition key and associated data to a specific shard. Specifically, an MD5 hash function is used to map partition keys to 128-bit integer values and to map associated data records to shards. As a result of this hashing mechanism, all data records with the same partition key will map to the same shard within the stream.
        auto j = rec.toJson();
        j["StreamName"] = this.stream;
        import std.stdio;

        auto res = this.doRequest( apiVersion ~ ".PutRecord", j);
        return res.responseBody();
    }

    auto putRecords(Record[] records)
    {
        auto j = Json.emptyObject;
        j["StreamName"] = this.stream;
        j["Records"] = records.map!(r => r.toJson()).array;

        auto res = this.doRequest( apiVersion ~ ".PutRecords", j);
        return res.responseBody();

    }

}

class Record
{

    string pk;
    string data;

    this(string partitionKey, string data)
    {
        this.pk = partitionKey;
        this.data = cast(string) Base64.encode(cast(ubyte[]) data);
    }
    
    this(string partitionKey, ubyte[] data)
    {
        this.pk = partitionKey;
        this.data = cast(string) Base64.encode(data);
    }

    Json toJson()
    {
        auto j = Json.emptyObject;
        j["PartitionKey"] = pk;
        j["Data"] = data;
        return j;
    }
}

