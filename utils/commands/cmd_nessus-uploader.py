import os
from os import walk
import sys

import click

from ..lib.toolBox import nessus_login as login
from utils.cli import pass_context

# Disable Requests' warning when using bad SSL certs
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

@click.command(name='nessus-uploader', short_help='Upload a folder or series of Nessus files to a server.')
@click.option('-l', '--local-nessus', required=True, type=click.Path(exists=False, file_okay=True, dir_okay=True, readable=True, resolve_path=True), help='Path to local Nessus file(s).')
@click.option('-t', '--target', type=click.STRING, help='Server to upload Nessus file. This should be an IP address or hostanme.', default='dc2astns01.asmt.gps')
@click.option('-p', '--port', type=click.INT, default='8834')
@click.option('-r', '--remote-folder', type=click.INT, help='Destination folder ID on Nessus server.', required=True)
@click.option('--test', is_flag=True, default=False, help='Test authentication to Nessus server.')
@pass_context
def cli(ctx, local_nessus, target, remote_folder, port, test):
    """
    Upload lots of Nessus files to a folder in a Nessus Server.
    - Get user credentials - API or username and password
    - Determine if local_nessus is a directory or file
    -- Find all '.nessus' files in directory
    - Upload Nessus file to given folder
    """

    # If local-nessus is a file, skip OS walk and trying to find more Nessus files
    nessus_list = list()
    if os.path.isfile(local_nessus):
        if local_nessus.split('.')[-1:][0] == 'nessus':
            nessus_list.append(os.path.split(local_nessus))
    else:
        for (dirpath, dirnames, filenames) in walk(local_nessus):
            for fn in filenames:
                if fn.split('.')[-1:][0] == 'nessus':
                    nessus_list.append((dirpath, fn))
    # Make sure we actually found a Nessus file to upload
    if len(nessus_list) == 0:
        ctx.logc('[!] No Nessus files were specified.',fg='red')
        ctx.logc('[*] Exiting.', fg='green')
        sys.exit()
    # Try to log in, catch any errors
    napi = login(target, port, test)
    if not test:
        for full_path in nessus_list:
            click.secho('[*] Attempting to upload {}'.format(full_path[1].rstrip()), fg='white')
            napi.upload(os.path.join(full_path[0], full_path[1]))
            click.secho('[*] Upload successful.', fg='green')

            click.secho('[*] Attempting to import the scan into the correct folder.', fg='white')
            napi.scan_import(full_path[1], remote_folder)
            click.secho('[*] Import successful.', fg='green')
    else:
        click.secho('[*] This was a test. No files were uploaded.', fg='blue', bg='white')
    click.secho('[*] All done!', fg='green')
    napi.log_out()