import logging

# Disable Requests' warning when using bad SSL certs
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from collections import OrderedDict
import csv
import io
import json
import sys
import time

import arrow
import click
import requests

from .Exceptions import *

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logger = logging.getLogger('utils.GoPhishAPI')

class Groups(object):

    def list_groups(self):
        # List the groups on the server
        url = 'groups'
        return self._getURL(url)

    def import_group_csv(self, csv_path, group_size, group_name):
        # Import the defined CSV file
        # Divide the CSV file into $group_size

        url = 'groups/'

        group_dict = GeneralUtilties.divide_csv(csv_path, group_size, group_name)

        # Upload each group
        for g_name in group_dict:
            # POST

            data = {'name': g_name, "targets": list(group_dict[g_name])}
            try:
                # click.secho('[*] Attempting to upload group {}...'.format(g_name), fg='green')
                resp = self._postURL(url, payload=data, json_return=False)
            except HTTPError.GroupNameInUse:
                err_msg = '[!] The group name \'{}\' is already in use.'.format(g_name)
                click.secho(err_msg, fg='red')
                if self.cont:
                    click.secho('[*] Continuing...', fg='green')
                else:
                    sys.exit()

            # Pause for 2 seconds to let the server catch up
            logger.info('Pausing to let the server catch up.')
            time.sleep(2)

    def get_groups(self):
        # Get the groups on the host as JSON
        url = 'groups/'

        resp = self._getURL(url)

        return resp

    def del_group(self, id):
        # Delete the specified group

        url = 'groups/{}'.format(id)

        return self._delURL(url)


class Campaigns(object):

    def create_campaign(self, campaign_name, template_name, url, landing_page, sending_profile, group, launch_date='now', timezone='US/Eastern'):
        # Create a campaign
        url = 'campaigns/'

        if launch_date == 'now':
            launch_date = arrow.utcnow().to(timezone).format('YYYY-MM-DD HH:mm')
        else:
            click.secho('Parsing doesn\'t work yet', fg='red')
            sys.exit()

        campaign_request = {"name": campaign_name, "template":{"name": template_name},"url": url, "page": {"name": landing_page}, "smtp":{"name": sending_profile}, "launch_date": launch_date, "groups": [{"name": group}]}

        resp = self._postURL(url, payload=campaign_request, json_return=False)
        return resp

    def get_campaigns(self, campaign_int):
        """Get the data for the current campaign"""
        url = 'campaigns/{}'.format(campaign_int)

        return self._getURL(url)

class GoPhish(Groups, Campaigns):

    def __init__(self, api_key, host, port, verify=False, cont=False):
        """
        GoPhish API Wrapper
        :param api_key:
        :param host:
        :param port:
        :param verify:
        :param cont: Flag to continue if the group being created already exists on the GoPhish Server.
        """
        logger = logging.getLogger("utils.modules.GoPhishAPI")
        if host == None:
            logger.error('No host defined. Provide a host.')
            raise GoPhish.NoHostProvided('No host defined')
        if port == None:
            logger.error('No port defined. Provide a port.')
            raise GoPhish.NoPortProvided('No port defined.')
        if api_key == None:
            logger.error('No API Key provided. ')
            raise GoPhish.NoAPIKeyProvided('No API Key provided.')

        # Check if host starts with 'https://' or 'http://'
        if not (host.startswith('https://') or host.startswith('http://')):
            # Append 'https:// to the beginning of the host
            host = 'https://{}'.format(host)

        self.api_key = api_key
        self.host = host
        self.port = port
        self.cont = cont
        self.redirects = False

        # Create the session for Requests and consistency
        self.sess = requests.Session()
        self.sess.verify = verify
        self.sess.headers = {'Content-Type': 'application/json'}

    def _url_builder(self, resource_location):
        """
        Builds the complete URI
        :param resource_location: Leading slash all the way to but not including the ?
        :return: URI in a string.
        """
        url = '{base}:{port}/api/{location}?api_key={api_key}'.format(base=self.host, port=self.port,
                                                              location=resource_location, api_key=self.api_key)
        return url

    def _getURL(self, url):
        """
        Base for simple GET requests
        :param url:
        :return:
        """
        full_url = self._url_builder(url)
        resp = methods.get(full_url, self.sess)
        return resp.json()

    def _postURL(self, url, payload=None, json_return=True):
        """
        Base for simple GET requests
        :param url:
        :param payload:
        :rtype: dict
        """
        full_url = self._url_builder(url)
        resp = methods.post(full_url, self.sess, data=payload)
        if json_return:
            return resp.json()
        else:
            return resp

    def _delURL(self, url):
        """
        Make DELETE request
        :param url:
        :rtype: dict
        """
        full_url = self._url_builder(url)
        resp = methods.del_req(full_url, self.sess)
        return resp.json()

    def check_auth(self):
        # Get a list of current campaigns
        url = 'campaigns'
        return self._getURL(url)


class methods:
    """All HTTP methods in use"""

    @staticmethod
    def httpErrors(resp):
        status_code = resp.status_code

        if status_code == 400:
            # Bad Request
            raise HTTPError.BadRequest(resp.json()['message']) from None
        elif status_code == 401:
            # Unauthorized
            raise HTTPError.UnAuthorized(resp.json()['message']) from None
        elif status_code == 405:
            raise HTTPError.MethodNotAllowed(resp.json()['message']) from None
        elif status_code == 409:
            raise HTTPError.GroupNameInUse(resp.json()['message']) from None
        elif status_code == 301:
            print('Redirect')
        elif status_code == 201:
            pass
        elif status_code != 200:
            raise HTTPError.UnKnownHTTPError(resp.json()['message']) from None

    @staticmethod
    def get(url, sess):
        """Make a GET request"""
        r = sess.get(url)
        # Check for errors
        methods.httpErrors(r)

        # No news is good news
        return r

    @staticmethod
    def post(url, sess, data=None):
        """Make a POST request"""

        # dumps is there to ensure the data is properly formatted
        r = sess.post(url, data=json.dumps(data))
        # Check for errors
        methods.httpErrors(r)


        # No news is good news
        return r

    @staticmethod
    def del_req(url, sess):
        """Make DELETE request"""
        r = sess.delete(url)
        # Check for errors
        methods.httpErrors(r)

        # No news is good news
        return r


class GeneralUtilties(object):

    def __init__(self):
        pass

    @staticmethod
    def divide_csv(csv_path, group_size, group_name):
        # Divide CSV file into groups
        group_counter = 0
        temp_list = list()
        group_dict = OrderedDict()
        count = 0
        with open(csv_path, 'r') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                count += 1
                if count < group_size:
                    temp_list.append(row)
                else:
                    temp_list.append(row)
                    group_counter += 1
                    group_final_name = '{name}_{group_counter}'.format(name=group_name, group_counter=group_counter)
                    group_dict[group_final_name] = temp_list
                    # Reset everything
                    temp_list = list()
                    count = 0
            if len(temp_list) != 0:
                # There are left over rows
                temp_list.append(row)
                group_counter += 1
                group_final_name = '{name}_{group_counter}'.format(name=group_name, group_counter=group_counter)
                group_dict[group_final_name] = temp_list

        return group_dict