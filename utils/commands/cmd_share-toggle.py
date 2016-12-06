import configparser
import logging
import os
import sys

import click

from utils.cli import pass_context

@click.command(name='share-toggle', short_help='Connect or disconnect from the shared drive')
@click.option('-s', '--status', is_flag=True, help='Check if the share is mounted and exit.', default=False)
@click.option('-r', '--remote-server', help='Specify remote server to connect to.', type=click.Choice(['home', 'qnap']), default='qnap')
@pass_context
def cli(ctx, status, remote_server):
    """
    Mount the specified share.
    """
    """
    Goals:
     - Check status of mount
     - Log into QNAP by default
     - Specify other shares
     + Impliment logging the whole way through
     + Read config file
     + Get QNAP hostname
     + Get username and password from file
     + Allow user to unmount share
    """
    config_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "../.config.ini")

    # QNAP settings
    qnap_path = 'smb://{uname}:{pword}@dc2asqnap01.asmt.gps/ProServices/'
    qnap_share_location = '/Volumes/ProServices/'

    # Home server settings
    home_path = 'smb://{uname}:{pword}@bklncdn1/homes/quincy/'
    home_share_location = '/Volumes/quincy/'

    # Create predefined SMB shares dictionary
    share_dict = {'qnap': {'path': qnap_path, 'share_location': qnap_share_location}, 'home': {'path': home_path, 'share_location': home_share_location}}

    toolset = ctx.toolset
    # Check status of the share
    share_status = toolset.check_share(share_dict[remote_server]['share_location'])

    # Just show user if the share is mounted or not
    if status:
        if share_status:
            ctx.logc('[!] The shared drive is already mounted.', fg='green')
            sys.exit()
    else:
        # Mount drive if not mounted, unmount if mounted
        if share_status:
            ctx.logc('[!] The shared drive is already mounted. Attempting to unmount it.', fg='white')
            rtn_str = toolset.mount_changer(share_dict[remote_server]['share_location'])
            if not rtn_str[0]:
                ctx.log(rtn_str)
                ctx.logc('[!] {}'.format(rtn_str[1]), fg='red')
            elif rtn_str[0]:
                ctx.logc('[*] Share unmounted successfully.', fg='white')
        else:
            ctx.logc('[*] Share not mounted', fg='white')
            # logger = logging.getLogger('')
            config = configparser.ConfigParser()
            config.read(config_file)
            ctx.dlog("Trying to read the config file.")
            username = config[remote_server.upper()]['Username']
            password = config[remote_server.upper()]['Password']
            ctx.dlog('Read the config file successfully')

            filled_path = share_dict[remote_server]['path'].format(uname=username, pword=password)

            # Mount the shared drive
            ctx.logc('[*] Mounting the share.', fg='white')
            click.launch(filled_path)
