import logging
from flask import Flask, Response, stream_with_context, request, render_template, session, redirect, url_for
import requests
import boto3
from botocore.credentials import Credentials as BotoCredentials
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from aws_requests_auth.aws_auth import AWSRequestsAuth
from base64 import b64decode
import os
from bcrypt import hashpw, gensalt
import time


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
    return Response(stream_with_context(req.iter_content(chunk_size=None)), content_type = req.headers['content-type'])


if __name__ == '__main__':

    if os.environ.get('DEBUG', False):
        logging.basicConfig(level=logging.DEBUG)

    # this is pretty slow for the initial kibana load
    # to get this to load, you'll need to `pip install gevent` in your venv
    # ...but don't deploy gevent with zappa
    from gevent.wsgi import WSGIServer
    http_server = WSGIServer(('127.0.0.1', 5000), app)
    http_server.serve_forever()
