module aws.credentials;

/**
  AWS Credentials
 */
struct AWSCredentials
{
    string accessKeyID;
    string accessKeySecret;
    string sessionToken;
}

/**
  AWS Credential source

  Classes that implement this provide credentials for AWS requests. A
  Credential Source is an active object, since credentials may change during
  the lifetime of the application
 */
interface AWSCredentialSource
{
    /**
      Retrieve the current set of credentials
     */
    AWSCredentials credentials(string credScope);

    /**
      Called when credentials turn out to be rejected by the backend
     */
    void credentialsInvalid(string credScope, AWSCredentials creds, string reason);
}

/**
  Provider of a static set of AWS credentials

  This will never use a session token, since the credentials have to be root or
  static IAM credentials.
 */
class StaticAWSCredentials : AWSCredentialSource
{
    AWSCredentials m_creds;

    this(string accessKeyID, string accessKeySecret)
    {
        m_creds = AWSCredentials(accessKeyID, accessKeySecret, "");
    }

    AWSCredentials credentials(string credScope)
    {
        // FIXME: Different creds for different scopes?
        return m_creds;
    }

    void credentialsInvalid(string credScope, AWSCredentials creds, string reason)
    {
        // Nothing we can do about this, just throw an exception
        throw new Exception("Static credentials with ID " ~ creds.accessKeyID ~ " rejected because: " ~ reason);
    }
}


/// AWS Environment
enum AwsEnvironment : string
{
    /// AWS_ACCESS_KEY_ID
    idVariant0 = "AWS_ACCESS_KEY_ID",
    /// AWS_ACCESS_KEY
    idVariant1 = "AWS_ACCESS_KEY",
    /// AWS_SECRET_KEY
    secretVariant0 = "AWS_SECRET_KEY",
    /// AWS_SECRET_ACCESS_KEY
    secretVariant1 = "AWS_SECRET_ACCESS_KEY",
}

class EnvAWSCredentials : StaticAWSCredentials
{
    this()
    {
        import std.exception : enforce;
        import std.process : environment;
        with(AwsEnvironment)
        {
            string accessKeyID     = environment
                .get(idVariant0, environment.get(idVariant1))
                .enforce(idVariant0 ~ " or " ~ idVariant1 ~ " environment variables should be defined.");
            string accessKeySecret = environment
                .get(secretVariant0, environment.get(secretVariant1))
                .enforce(secretVariant0 ~ " or " ~ secretVariant1 ~ " environment variables should be defined.");
            super(accessKeyID, accessKeySecret);
        }
    }
}
