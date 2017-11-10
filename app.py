import logging
from flask import Flask, Response, stream_with_context, request, render_template, session, redirect, url_for
import requests
import boto3
from botocore.credentials import Credentials as BotoCredentials
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from botocore.client import Config
from aws_requests_auth.aws_auth import AWSRequestsAuth
from base64 import b64decode
import os
from bcrypt import hashpw, gensalt
import time
from uuid import uuid4
from urllib.parse import urlparse

logger = logging.getLogger()

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ['SESSION_SECRET']  # intentionally not guarded so it fails, for now

aws_default_region = os.environ.get("AWS_REGION", "us-east-1")

remote_hostname = os.environ.get("ES_HOSTNAME")
dynamo_table = os.environ.get("DYNAMODB_TABLE", "access_es_users")
aws_region = os.environ.get("ES_REGION", aws_default_region)
boto_session = boto3.session.Session(region_name=aws_region)
credentials = boto_session.get_credentials().get_frozen_credentials()
session_recheck = int(os.environ.get("SESSION_RECHECK", 300))  # recheck the session every 5 mins
overflow_size = int(os.environ.get("OVERFLOW_SIZE", 5 * 1024 * 1024))  # 5MB
overflow_bucket = os.environ.get('OVERFLOW_BUCKET', None)  # intentionally not guarded so it fails, for now

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


def _check_login(username=None, password=None, expires=False):

    if username is None and password is None:
        # fetch from session
        username = session.get('username')
        password = session.get('password')
        expires = session.get('expires')

    if not username or not password:
        return False

    logger.debug("Expires: {} {} {}".format(expires, time.time(), expires - time.time()))
    if username and password and expires:
        if expires > time.time():
            logger.debug('Unexpired session; skipping Dynamo')
            return True


    try:
        response = table.query(KeyConditionExpression=Key('username').eq(username))

        logger.debug("response: {}".format(response))

        if response:
            record = response.get('Items')
            logger.debug("Got dynamodb record: {}".format(record))

            if record:
                this_record = record[0]

                if this_record:
                    passwd = this_record.get('password')
                    logger.debug("Record has password: {}".format(passwd))
                    if passwd:
                        passwd = bytes(passwd, 'utf8')
                        password = bytes(password, 'utf8')
                        if passwd == hashpw(password, passwd):
                            logger.debug("Password matches.")
                            return True

    # didn't find the record
    except ClientError as e:
        logger.debug("Did not get dynamodb record")
        logger.debug(e)

    return False


@app.route('/--access-es-meta/login', methods=['GET'])
def login_form():
    return render_template('login.html', url=url_for('login_handler'))

@app.route('/--access-es-meta/login', methods=['POST'])
def login_handler():
    if _check_login(request.form['username'], request.form['password']):
        session['username'] = request.form['username']
        session['password'] = request.form['password']
        session['expires'] = time.time() + session_recheck
        return redirect('/_plugin/kibana/app/kibana')
    else:
        return redirect(url_for('login_form'))


@app.route('/--access-es-meta/logout', methods=['GET','POST'])
def logout_handler():
    session['username'] = None
    session['password'] = None
    return redirect(url_for('login_form'))


methods = ['GET', 'POST', 'HEAD', 'PUT', 'OPTIONS', 'DELETE', 'PATCH']
@app.route('/<path:path>', methods=methods)
@app.route('/', defaults={'path': ''}, methods=methods)
def proxy_request(path, **kwargs):
    """Takes an incoming request and proxies it to the specified host"""

    if not _check_login():
        return redirect(url_for('login_form'))

    url = request.url_rule.rule
    target_url = "https://{}/{}".format(remote_hostname, path)

    method = getattr(requests, request.method.lower())
    headers = {
        k: v for (k, v) in request.headers.items() if k not in EXCLUDED_HEADERS
    }

    # authentication with which to sign the requests request
    awsauth = AWSRequestsAuth(
        aws_access_key=credentials.access_key,
        aws_secret_access_key=credentials.secret_key,
        aws_token=credentials.token,
        aws_host=remote_hostname,
        aws_region=boto_session.region_name,
        aws_service='es'
    )

    req = method(
        target_url,
        auth=awsauth,
        params=request.query_string,
        data=request.data,
        headers=headers,
        stream=False,
        allow_redirects=False
    )

    content = req.content

    if overflow_bucket is not None and len(content) > overflow_size:

        # the response would be bigger than overflow_size, so instead of trying to serve it,
        # we'll put the resulting body on S3, and redirect to a (temporary, signed) URL
        # this is especially useful because API Gateway has a body size limitation, and
        # Kibana serves *huge* blobs of JSON

        # UUID filename (same suffix as original request if possible)
        u = urlparse(target_url)
        if '.' in u.path:
            filename = str(uuid4()) + '.' + u.path.split('.')[-1]
        else:
            filename = str(uuid4())

        s3 = boto3.resource('s3')
        s3_client = boto3.client('s3', config=Config(signature_version='s3v4'))

        bucket = s3.Bucket(overflow_bucket)

        # actually put it in the bucket. beware that boto is really noisy for this in debug log level
        obj = bucket.put_object(
            Key=filename,
            Body=content,
            ACL='authenticated-read',
            ContentType=req.headers['content-type']
        )

        # URL only works for 60 seconds
        url = s3_client.generate_presigned_url('get_object', Params = {'Bucket': overflow_bucket, 'Key': filename}, ExpiresIn=60)

        # "see other"
        return redirect(url, 303)

    elif req.headers.get('Location', False):
        response = Response(content)
        response.status_code = 302
        response.headers['Location'] = req.headers.get('Location')
        return response
    else:
        # otherwise, just serve it normally
        return Response(content, content_type=req.headers['content-type'])


if __name__ == '__main__':

    if os.environ.get('DEBUG', False):
        logging.basicConfig(level=logging.DEBUG)

    app.run(debug=os.environ.get('DEBUG', False))
