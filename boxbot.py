import json
import time

# import boto3


def box_please(event, context):
    body = {
        "message": "please do not have this cow",
        "now": time.time(),
        "input": event,
    }
    return {"statusCode": 200, "body": json.dumps(body)}
