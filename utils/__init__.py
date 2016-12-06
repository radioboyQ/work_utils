# Standard Library
import os
from os import walk
import configparser
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address, IPv4Network, IPv6Network
import logging
import subprocess
import sys

# Packages
import arrow
import click
from lxml import etree

# My junk
from .lib.iptools import IPTypeChecker, ExcelTools, IPToolsExceptions, IPCheck
from .lib import NessusAPIFunctions as NessusAPIFunctions
from .lib.toolBox import tools
from .lib.toolBox import nessus_login as login

# Disable Requests' warning when using bad SSL certs
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)