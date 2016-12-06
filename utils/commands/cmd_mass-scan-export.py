# Standard Library
import os
import sys

# Packages
import click

# My junk
from ..lib import NessusAPIFunctions as NessusAPIFunctions
from ..lib.toolBox import nessus_login as login
from utils.cli import pass_context

# Disable Requests' warning when using bad SSL certs
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

@click.command(name='mass-scan-export', short_help='Export all the scans in a given folder from a Nessus server.')
@click.option('-i', '--folder-id', required=True, type=click.INT, help='ID of the scan on the Nessus server.')
@click.option('-o', '--output-path', type=click.Path(exists=False, file_okay=False, dir_okay=True, resolve_path=True, writable=True), help='Location and/or name to save the scan', envvar='PWD')
@click.option('-t', '--target', type=click.STRING, help='Server to upload Nessus file. This should be an IP address or hostanme.', default='dc2astns01.asmt.gps')
@click.option('-p', '--port', type=click.INT, default='8834')
@click.option('-eT', '--export-type', help='Define the exported file\'s type.', type=click.Choice(['nessus', 'db', 'pdf', 'html', 'csv']), default='nessus')
@click.option('--test', is_flag=True, default=False, help='Test authentication to Nessus server.')
@pass_context
def cli(ctx, folder_id, output_path, target, port, test, export_type):
    """Export all scans in a directory"""
    # Try to log in, catch any errors
    napi = login(target, port, test)
    print(test)
    scan_list = list()
    scans = napi.list_scans()

    for j in scans['scans']:
        if j['folder_id'] == folder_id:
            scan_list.append({'name': j['name'], 'scan_id': j['id']})
    if len(scan_list) > 1:
        click.secho('[*] Found {} scans in the folder.'.format(len(scan_list)))
    elif len(scan_list) == 1:
        click.secho('[*] Found one scan in the folder.')
    elif len(scan_list) == 0:
        click.secho('[!] No scans found in the specified folder. Check the ID and try again.')
        sys.exit()

    for scan in scan_list:
        # Prep filename
        save_file = os.path.join(output_path, '{name}.{suffix}'.format(name=scan['name'].replace(' ', '_'), suffix=export_type))
        if not test:
            try:
                resp = napi.download_scan(int(scan['scan_id']))
                if export_type == "nessus":
                    resp = napi.download_scan(int(scan['scan_id']))
                else:
                    resp = napi.download_scan(int(scan['scan_id'], export_type))
            except NessusAPIFunctions.NessusException.RequestedFileNotFound:
                click.secho('[!] The requested file was not found. Check the file ID - {} - and try again. Exiting.'.format(scan['scan_id']), fg='red')
                sys.exit()
            click.secho('[*] Saving the scan to {}'.format(save_file), fg='green')
            with open(save_file, 'wb') as oF:
               oF.write(resp)
        else:
            click.secho('[*] Save file location: {}'.format(save_file))
    if test:
        click.secho('[*] This has been a test, no files were downloaded',fg='red')
    click.secho('[*] Done!', fg='green')