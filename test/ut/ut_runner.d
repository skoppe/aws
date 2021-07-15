
import unit_threaded;

int main(string[] args)
{
  return args.runTests!(
                        "aws.aws",
                        "aws.credentials",
                        "aws.s3",
                        "aws.sigv4",
                        );
}
