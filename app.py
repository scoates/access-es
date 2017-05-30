import logging
from flask import Flask, Response, stream_with_context, request
import requests
import boto3
from botocore.credentials import Credentials as BotoCredentials
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from aws_requests_auth.aws_auth import AWSRequestsAuth
from base64 import b64decode
import os
from bcrypt import hashpw, gensalt


logger = logging.getLogger()

app = Flask(__name__, static_folder=None)

aws_default_region = os.environ.get("AWS_REGION", "us-east-1")

remote_hostname = os.environ.get("ES_HOSTNAME")
dynamo_table = os.environ.get("DYNAMODB_TABLE", "access_es_users")
aws_region = os.environ.get("ES_REGION", aws_default_region)
boto_session = boto3.session.Session(region_name=aws_region)
credentials = boto_session.get_credentials().get_frozen_credentials()

# from https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#hbh
EXCLUDED_HEADERS = set([
    'Connection',
    'Keep-Alive',
    'Proxy-Authenticate',
    'Proxy-Authorization',
    'TE',
    'Trailer',
    'Transfer-Encoding',
    'Upgrade',
    'Host',
    # plus exclude Content-Length because requests calculates it
    'Content-Length',
    # plus exclude the incoming HTTP auth
    'Authorization',
])

dynamodb = boto3.resource('dynamodb', region_name=aws_region)
table = dynamodb.Table(dynamo_table)

methods = ['GET', 'POST', 'HEAD', 'PUT', 'OPTIONS', 'DELETE', 'PATH']
@app.route('/<path:path>', methods=methods)
@app.route('/', defaults={'path': ''}, methods=methods)
def proxy_request(path, **kwargs):
    """Takes an incoming request and proxies it to the specified host"""

    successful_auth = False
    auth_header = request.headers.get('authorization')
    if auth_header:
        logger.debug("got auth header")
        (basic, auth) = auth_header.split(" ", 2)
        if (basic.lower() == 'basic') and auth:

            logger.debug("got basic")
            (username, password) = b64decode(auth).split(b':', 2)
            try:
                logger.debug("query: {}".format(username.decode()))
                response = table.query(KeyConditionExpression=Key('username').eq(username.decode()))

                logger.debug("response: {}".format(response))

                if response:
                    record = response.get('Items')
                    logger.debug("Got dynamodb record: {}".format(record))

                    this_record = record[0]

                    if this_record:
                        passwd = this_record.get('password')
                        logger.debug("Record has password: {}".format(passwd))
                        if passwd:
                            passwd = bytes(passwd, 'utf8')
                            if passwd == hashpw(password, passwd):
                                logger.debug("Password matches.")
                                successful_auth = True

            # didn't find the record
            except ClientError as e:
                logger.debug("Did not get dynamodb record")
                logger.debug(e)
                successful_auth = False

    if not successful_auth:
        return Response('You must authenticate.', 401, {'WWW-Authenticate':'Basic realm="Login Required"'})

    url = request.url_rule.rule
    target_url = "https://{}/{}".format(remote_hostname, path)
    logger.debug('target_url: {}'.format(target_url))

    method = getattr(requests, request.method.lower())
    headers = {
        k: v for (k, v) in request.headers.items() if k not in EXCLUDED_HEADERS
    }

    awsauth = AWSRequestsAuth(
        aws_access_key=credentials.access_key,
        aws_secret_access_key=credentials.secret_key,
        aws_token=credentials.token,
        aws_host=remote_hostname,
        aws_region=boto_session.region_name,
        aws_service='es'
    )

    logger.debug("AWSAUTH:")
    logger.debug(awsauth)

    req = method(
        target_url,
        auth=awsauth,
        params=request.query_string,
        data=request.data,
        headers=headers,
        stream=True
    )
    return Response(stream_with_context(req.iter_content()), content_type = req.headers['content-type'])


if __name__ == '__main__':

    if os.environ.get('DEBUG', False):
        logging.basicConfig(level=logging.DEBUG)

    # this is pretty slow for the initial kibana load
    # to get this to load, you'll need to `pip install gevent` in your venv
    # ...but don't deploy gevent with zappa
    from gevent.wsgi import WSGIServer
    http_server = WSGIServer(('127.0.0.1', 5000), app)
    http_server.serve_forever()
