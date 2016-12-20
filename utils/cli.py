#!/usr/local/bin/python3
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

class Context(object):

    def __init__(self):
        self.verbose = False
        self.debug = False

    def log(self, msg, *args):
        """Logs a message to stderr."""
        if args:
            msg %= args
        click.echo(msg, file=sys.stderr)

    def logc(self, msg, fg='white', bg='black', *args):
        """Log with color"""
        click.secho(msg, fg=fg, bg=bg)

    def vlog(self, msg, *args):
        """Logs a message to stderr only if verbose is enabled."""
        if self.verbose:
            self.log(msg, *args)

    def vlogc(self, msg, fg='white', bg='', *args):
        """Logs a message to stderr only if verbose is enabled."""
        if self.verbose:
            self.logc(msg, fg, bg, *args)

    def dlog(self, msg, *args):
        """Log debug messages"""
        if self.debug:
            self.log(msg, *args)

pass_context = click.make_pass_decorator(Context, ensure=True)
cmd_folder = os.path.abspath(os.path.join(os.path.dirname(__file__), 'commands'))
CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

class utilsCLI(click.MultiCommand):

    def list_commands(self, ctx):
        rv = []
        for filename in os.listdir(cmd_folder):
            if filename.endswith('.py') and \
               filename.startswith('cmd_'):
                rv.append(filename[4:-3])
        rv.sort()
        return rv

    def get_command(self, ctx, name):
        matches = [x for x in self.list_commands(ctx) if x.startswith(name)]
        if not matches:
            return None
        elif len(matches) == 1:
            name = matches[0]
            try:
                if sys.version_info[0] == 2:
                    name = name.encode('ascii', 'replace')
                mod = __import__('utils.commands.cmd_' + name,
                                 None, None, ['cli'])
            except ImportError:
                return
            return mod.cli
        else:
            ctx.fail('Too many matches: %s' % ', '.join(sorted(matches)))

@click.command(cls=utilsCLI,context_settings=CONTEXT_SETTINGS)
@click.option('-v', '--verbose', help='Show logging messages beyond just error and critical. -Work in progress-', is_flag=True, default=False)
@click.option('--config', help='Specify a configuration file to use.', type=click.Path(exists=True, dir_okay=False, resolve_path=True, allow_dash=True), default='~/myToolsPath/utils/.config.ini')
@click.option('--debug', help='Enable debugging. -Work in progress-', is_flag=True, default=False)
@pass_context
def cli(ctx, verbose, config, debug):
    """Tools for assessments"""
    # This is the root command
    ctx.verbose = verbose
    ctx.debug = debug
    # Initialize tool set
    if ctx.debug:
        ctx.toolset = tools(debug)
    else:
        ctx.debug = tools(debug=False)

    # Logging

    # Quiet down Requests logging
    logging.getLogger("requests").setLevel(logging.WARNING)
    # Quiet down urllib3 logging
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    logger = logging.getLogger('utils')
    logger.setLevel(logging.DEBUG)
    # create console handler and set level
    ch = logging.StreamHandler()

    if verbose and not ctx.debug:
        ch.setLevel(logging.INFO)
    elif ctx.debug:
        ch.setLevel(logging.DEBUG)
    else:
        ch.setLevel(logging.WARNING)

    # create formatter
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    # Disable propagation
    logger.propagate = False

