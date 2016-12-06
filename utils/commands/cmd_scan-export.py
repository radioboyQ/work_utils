import os
import sys

import arrow
import click

from ..lib.toolBox import nessus_login as login
from ..lib import NessusAPIFunctions as NessusAPIFunctions
from utils.cli import pass_context

# Disable Requests' warning when using bad SSL certs
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

@click.command(name='scan-export', short_help='Export a scan from a Nessus server.')
@click.option('-i', '--id', required=True, type=click.INT, help='ID of the scan on the Nessus server.')
@click.option('-o', '--output-path', type=click.Path(exists=False, file_okay=True, dir_okay=True, resolve_path=True, writable=True), help='Location and/or name to save the scan', envvar='PWD')
@click.option('-t', '--target', type=click.STRING, help='Server to export Nessus file. This should be an IP address or hostanme.', default='dc2astns01.asmt.gps')
@click.option('-p', '--port', type=click.INT, default='8834')
@click.option('-eT', '--export-type', help='Define the exported file\'s type.', type=click.Choice(['nessus', 'db', 'pdf', 'html', 'csv']), default='nessus')
@click.option('--test', is_flag=True, default=False, help='Test authentication to Nessus server.')
@pass_context
def cli(ctx, id, output_path, target, port, test, export_type):
    """Quick and dirty way to export Nessus files"""
    # Try to log in, catch any errors
    napi = login(target, port, test)
    # Check if its a directory
    if os.path.isfile(output_path):
        if output_path.split('.')[-1:][0] == export_type:
            save_file = output_path
        else:
            ctx.logc('[!] The extension on this file does not match the export type of {}.'.format(export_type))
            cont_bool = click.prompt('[?] Do you want to continue?', show_default=True, type=click.BOOL)
            if cont_bool == True:
                save_file = output_path
            else:
                ctx.logc('[*] Exiting.', fg='red')
                sys.exit()
    elif os.path.isdir(output_path):
        # Specified a  directory
        # Todo: Use Nessus file name
        # Create filename
        default_filename = nessus_scan_default_filename()
        save_file = os.path.join(output_path, default_filename)
    elif os.path.exists(output_path):
        ctx.logc('[!] That file already exists, pick a new file name. Exiting.', fg='red')
        sys.exit()

    ctx.logc('[*] Starting to download the file. ', fg='green')
    if not test:
        # Normal mode, not test mode
        try:
            if export_type == "nessus":
                resp = napi.download_scan(id)
            else:
                resp = napi.download_scan(id, export_type)
        except NessusAPIFunctions.NessusException.RequestedFileNotFound:
            ctx.logc('[!] The requested file was not found. Check the file ID and try again. Exiting.', fg='red')
            sys.exit()
        ctx.logc('[*] Saving the scan to {}'.format(save_file), fg='green')
        with open(save_file, 'wb') as oF:
            oF.write(resp)
        ctx.logc('[*] Done!', fg='green')
    else:
        # Test mode
        ctx.logc('[*] Test mode, not actually downloading the file.', fg='green')
        ctx.logc('[*] Done!', fg='green')
        napi.log_out()


def nessus_scan_default_filename():
    """Create a default filename for saved files from a Nessus server"""
    # Todo: Pull name of scan and use that to save the file
    utc = arrow.utcnow()
    local = utc.to('US/Eastern')
    date = local.format('YYYY-MM-DD')

    default_filename = 'GuidePoint_Security_Nessus_Results_{}.nessus'.format(date)
    return default_filename