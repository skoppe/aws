
import unit_threaded;

int main(string[] args)
{
  return args.runTests!(
                        "vibe.aws.aws",
                        "vibe.aws.credentials",
                        "vibe.aws.s3",
                        "vibe.aws.sigv4",
                        );
}
