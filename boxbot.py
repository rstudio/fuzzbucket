import json

# import boto3


def hello(event, context):
    body = {
        "message": "please do not have this cow",
        "input": event,
    }
    return {"statusCode": 200, "body": json.dumps(body)}
