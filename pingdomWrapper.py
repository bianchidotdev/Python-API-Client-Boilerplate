#!/usr/bin/env python

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from requests_oauthlib import OAuth1
from math import floor
from datetime import datetime, timedelta
import yaml
import logging
import os
import sys
from enum import Enum

# Set up basic logger
logger = logging.getLogger('pingdom.pingdomWrapper')

# Setup stdout logger
soh = logging.StreamHandler(sys.stdout)
# Can optionally set logging levels per handler
# soh.setLevel(logging.WARN)
logger.addHandler(soh)

# File handler for logging to a file
# fh = logging.FileHandler('apiWrapper.log')
# fh.setLevel(logging.DEBUG)
# logger.addHandler(fh)

# Get log level from env vars
log_level = os.environ.get('LOG_LEVEL', 'INFO').upper()
if os.environ.get('DEBUG'):
    if log_level:
        logger.warn("Overriding LOG_LEVEL setting with DEBUG")
    log_level = 'DEBUG'

try:
    logger.setLevel(log_level)
except ValueError:
    logger.setLevel(logging.INFO)
    logger.warn("Variable LOG_LEVEL not valid - Setting Log Level to INFO")


class AuthenticationError(Exception):
    pass


AuthType = Enum('AuthType', 'HTTPBASICAUTH HTTPDIGESTAUTH OAUTH1 OAUTH2 NONE')


class Pingdom(object):
    def __init__(
        self,
        user=None,
        password=None,
        client_app_key=None,
        client_app_secret=None,
        user_oauth_token=None,
        user_oauth_token_secret=None,
        api_app_key=None,
        auth_type=None
    ):
        '''Set up client for API communications
           This is where you'll need to specify all the authentication and
           required headers

           Preference will be given towards passed in variables, otherwise
           environment variables will be used

           Config file is supported but discouraged since it's a common
           source of credential leaks
        '''
        # Setup Host here
        self.url = 'https://api.pingdom.com'
        # Setup Session object for all future API calls
        self.session = requests.Session()

        # Setup authentication
        # If interested in using a config file instead of env vars, load with
        # self._load_key(config_key, path)
        # Feel free to clear out auth methods not implemented by the API
        if not auth_type:
            auth_type = AuthType[os.getenv('AUTHTYPE', default='NONE')]
        if (auth_type == AuthType.HTTPBASICAUTH or
                auth_type == AuthType.HTTPDIGESTAUTH):
            if not user:
                user = os.getenv('CLIENT_USER')
            if not password:
                password = os.getenv('CLIENT_PASSWORD')
            if auth_type == AuthType.HTTPBASICAUTH:
                self.session.auth = HTTPBasicAuth(user, password)
            else:
                self.session.auth = HTTPDigestAuth(user, password)
        if auth_type == AuthType.OAUTH1:
            if not client_app_key:
                client_app_key = os.getenv('CLIENT_APP_KEY')
            if not client_app_secret:
                client_app_secret = os.getenv('CLIENT_APP_SECRET')
            if not user_oauth_token:
                user_oauth_token = os.getenv('USER_OAUTH_TOKEN')
            if not user_oauth_token_secret:
                user_oauth_token_secret = os.getenv('USER_OAUTH_TOKEN_SECRET')
            self.session.auth = OAuth1(
                client_app_key,
                client_app_secret,
                user_oauth_token,
                user_oauth_token_secret
            )
        if auth_type == AuthType.OAUTH2:
            # Feel free to create a PR if you want to contribute
            raise NotImplementedError("OAuth2 currently not supported")

        # Some APIs require an API key in a header in addition to or instead
        # of standard authentication methods
        if not api_app_key:
            api_app_key = os.getenv('API_APP_KEY')
        self.session.headers.update({'App-Key': api_app_key})

        # Setup any additional headers required by the API
        # This sometimes includes additional account info
        account_owner = os.getenv('PINGDOM_ACCOUNT_OWNER')
        if account_owner:
            self.session.headers.update({'account-email': account_owner})

        logger.info('Authenticating...')
        if self._authenticate():
            logger.info('Authentication Successful!')
        else:
            logger.info('Authentication Failed!')
            raise AuthenticationError('Authentication Failed!')

    def _load_key(self, config_key, path):
        '''Example function for loading config values from a yml file
        '''
        with open(path) as stream:
            yaml_data = yaml.safe_load(stream)
            return yaml_data[config_key]

    def _authenticate(self):
        '''Authenticate by making simple request
           Some APIs will offer a simple auth validation endpoint, some
           won't.
           I like to make the simplest authenticated request when
           instantiating the client just to make sure the auth works
        '''
        resp_json = self._make_request('/api/2.1/servertime', 'GET')
        try:
            pass
        except AuthenticationError as e:
            raise e
        print(resp_json)
        if resp_json:
            return True
        else:
            return False

    def _make_request(self, endpoint, method, query_params=None, body=None):
        '''Handles all requests to Pingdom API
        '''
        url = self.url + endpoint
        req = requests.Request(method, url, params=query_params, json=body)
        prepped = self.session.prepare_request(req)

        # Log request prior to sending
        self._pprint_request(prepped)

        # Actually make request to endpoint
        r = self.session.send(prepped)

        # Log response immediately upon return
        self._pprint_response(r)

        # Handle all response codes as elegantly as needed in a single spot
        if r.status_code == requests.codes.ok:
            try:
                resp_json = r.json()
                logger.debug('Response: {}'.format(resp_json))
                return resp_json
            except ValueError:
                return r.text

        elif r.status_code == 401:
            logger.info("Authentication Unsuccessful!")
            try:
                resp_json = r.json()
                logger.debug('Details: ' + str(resp_json))
                raise AuthenticationError(resp_json)
            except ValueError:
                raise
        
        # TODO handle rate limiting gracefully

        # Raises HTTP error if status_code is 4XX or 5XX
        elif r.status_code >= 400:
            logger.error('Received a ' + str(r.status_code) + ' error!')
            try:
                logger.debug('Details: ' + str(r.json()))
            except ValueError:
                pass
            r.raise_for_status()

    def _pprint_request(self, prepped):
        '''
        method endpoint HTTP/version
        Host: host
        header_key: header_value

        body
        '''
        method = prepped.method
        url = prepped.path_url
        headers = '\n'.join('{}: {}'.format(k, v) for k, v in
                            prepped.headers.items())
        # Print body if present or empty string if not
        body = prepped.body or ""

        logger.info("Requesting {} to {}".format(method, url))

        logger.debug(
            '{}\n{} {} HTTP/1.1\n{}\n\n{}'.format(
                '-----------REQUEST-----------',
                method,
                url,
                headers,
                body
            )
        )

    def _pprint_response(self, r):
        '''
        HTTP/version status_code status_text
        header_key: header_value

        body
        '''
        # Not using requests_toolbelt.dump because I want to be able to
        # print the request before submitting and response after
        # ref: https://stackoverflow.com/a/35392830/8418673

        httpv0, httpv1 = list(str(r.raw.version))
        httpv = 'HTTP/{}.{}'.format(httpv0, httpv1)
        status_code = r.status_code
        status_text = r.reason
        headers = '\n'.join('{}: {}'.format(k, v) for k, v in
                            r.headers.items())
        body = r.text or ""
        # Convert timedelta to milliseconds
        elapsed = floor(r.elapsed.total_seconds() * 1000)

        logger.info(
            "Response {} {} received in {}ms".format(
                status_code,
                status_text,
                elapsed
            )
        )

        logger.debug(
            '{}\n{} {} {}\n{}\n\n{}'.format(
                '-----------RESPONSE-----------',
                httpv,
                status_code,
                status_text,
                headers,
                body
            )
        )

    def make_request(
        self,
        endpoint,
        method,
        query_params=None,
        body=None
    ):
        return self._make_request(endpoint, method, query_params, body)

    def list_checks(
            self,
            tags=[],
            offset=0,
            limit=20
    ):
        '''Get list of checks in Pingdom

        :tags: list of tags to filter checks on - checks will match ANY tag
        '''
        endpoint = '/api/2.1/checks'
        params = {}
        if tags:
            params['tags'] = ','.join(tags)
        else:
            tags = None
        params['offset'] = offset
        params['limit'] = limit
        params['include_tags'] = True

        return self._make_request(endpoint, 'GET', query_params=params)

    def get_check_details(self, check_id):
        """TODO: Docstring for get_check_details.
        """
        endpoint = '/api/2.1/checks/{}'.format(check_id)
        return self._make_request(endpoint, 'GET')

    def pause_unpause_mult_checks(self, check_list, pause=True):
        """Pauses or Unpauses multiple checks

        :check_list: list of check ids to update
        :pause: True to pause checks, False to unpause checks
        :returns: TODO

        """
        endpoint = '/api/2.1/checks'
        check_ids = ','.join(check_list)
        params = {}
        params['checkids'] = check_ids
        params['paused'] = pause
        return self._make_request(endpoint, 'PUT', query_params=params)

    def create_new_check(
            self,
            name,
            host,
            **kwargs
    ):
        '''Create new check in Pingdom
        '''
        endpoint = '/api/2.1/checks'
        params = {}
        params['name'] = name
        params['host'] = host
        # Allows an arbitrary number of keyword arguments to this method
        # to be converted into query_params
        for key, value in kwargs.items():
            params[key] = value
        return self._make_request(endpoint, 'POST', query_params=params)

    def create_new_maintenance_window(
            self,
            description,
            from_datetime,
            to_datetime,
            uptime_ids=None,
            tms_ids=None
    ):
        '''Create new maintenance window in Pingdom
        '''
        endpoint = '/api/2.1/maintenance'
        params = {}
        params['description'] = description

        if from_datetime is type(datetime):
            # floor needed because datetime.timestamp() returns
            # >>> datetime.datetime.now().timestamp()
            # 1550686321.920955 - <epoch seconds>.<epoch microseconds>
            params['from'] = floor(from_datetime.timestamp())
        else:
            params['from'] = from_datetime
        params['to'] = floor(to_datetime.timestamp())
        if uptime_ids:
            # Convert easy to use list to comma-delimited for the API
            params['uptimeids'] = ','.join(map(str, uptime_ids))
        if tms_ids:
            params['tmsids'] = ','.join(map(str, tms_ids))
        return self._make_request(endpoint, 'POST', query_params=params)


if __name__ == "__main__":
    account = Pingdom(
        'test@example.com',
        'password',
        auth_type=AuthType.HTTPBASICAUTH
    )
    from_datetime = datetime.now()
    to_datetime = datetime.now() + timedelta(1)
    account.list_checks()
    account.create_new_maintenance_window('name', from_datetime, to_datetime,
                                          uptime_ids='123,345')
