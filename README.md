vibe-s3
========

### this library is highly alpha and mostly untested. use at your own risk

see example dub projects for usage

to run the example you need to export your credentials:

```bash
export AWS_ACCESS_KEY_ID=XXX
export AWS_SECRET_KEY=XXX
export S3_EXAMPLE_BUCKET=myTestBucket
export S3_EXAMPLE_REGION=eu-west-1
```

Note for OS X: 
you need to force use Homebrews OpenSSL
`brew link --force openssl`
