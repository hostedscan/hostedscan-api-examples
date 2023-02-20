# Receive HostedScan Webhooks Using an AWS Lambda Function

This example demonstrates how to receive [HostedScan webhook events](https://docs.hostedscan.com/webhooks/overview) using an AWS Lambda function written in Rust.

This example includes an [AWS SAM](https://aws.amazon.com/serverless/sam/) template. The [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html) can be used to test the function locally and to deploy into an AWS account. Alternatively, the function can be created manually through the AWS console by building, zipping, and uploading the artifacts manually.

The Lambda function is created with a [function URL](https://aws.amazon.com/blogs/aws/announcing-aws-lambda-function-urls-built-in-https-endpoints-for-single-function-microservices/) so that it can receive webhook events via an https endpoint.

## Verifying webhook messages signatures

The example code verifies the signatures of webhook messages. This is an industry-wide best practice for webhooks, especially since webhook endpoints are usually public http endpoints. For production use, replace the `example-secret` signing secret with the real signing secret assigned to your webhook endpoint by HostedScan, which can be found in your account settings at https://hostedscan.com/settings.

## Test locally with the SAM cli

- `sam build`
- `sam local invoke -e test_data/risk_opened.json`

The there 3 different test events in the /test_data folder: risk_opened.json, risk_closed.json, and scan_succeeded.json

## Deploy to AWS Lambda with SAM cli

- `sam build`
- `sam deploy --stack-name << desired stack name >> --capabilities CAPABILITY_IAM`
