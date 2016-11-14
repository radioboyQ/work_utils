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
from lib.iptools import IPTypeChecker, ExcelTools, IPToolsExceptions, IPCheck
import lib.NessusAPIFunctions as NessusAPIFunctions
from lib.toolBox import tools
from lib.toolBox import nessus_login as login

# Disable Requests' warning when using bad SSL certs
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class AliasedGroup(click.Group):
    """Allows commands to be called by their first unique character"""

    def get_command(self, ctx, cmd_name):
        """
        Allows commands to be called by their first unique character
        :param ctx: Context information from Click
        :param cmd_name: Calling command name
        :return:
        """
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        matches = [x for x in self.list_commands(ctx)
                   if x.startswith(cmd_name)]
        if not matches:
            return None
        elif len(matches) == 1:
            return click.Group.get_command(self, ctx, matches[0])
        ctx.fail('Too many matches: %s' % ', '.join(sorted(matches)))

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('-v', '--verbose', help='Show logging messages beyond just error and critical.', is_flag=True)
@click.pass_context
def mainCLI(ctx, verbose):
    """
    Tools for assessments
    """
    debug = False

    if debug:
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(message)s', stream=sys.stderr)

        # Initialize tool set
        toolset = tools(debug=True)
    else:
        logging.basicConfig(level=logging.ERROR, format='%(levelname)s - %(message)s', stream=sys.stderr)

        # Initialize tool set
        toolset = tools(debug=False)
    ctx.obj = {'toolset': toolset, 'verbose': verbose}

@mainCLI.command(name='share-toggle', short_help='Connect or disconnect from the shared drive')
@click.option('-s', '--status', is_flag=True, help='Check if the share is mounted and exit.', default=False)
@click.option('-r', '--remote-server', help='Specify remote server to connect to.', type=click.Choice(['home', 'qnap']), default='qnap')
@click.pass_obj
def share_toggle(obj, status, remote_server):
    """
    Run a series of commands to set up for the day.
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
    config_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), "lib/.config.ini")

    # QNAP settings
    qnap_path = 'smb://{uname}:{pword}@dc2asqnap01.asmt.gps/ProServices/'
    qnap_share_location = '/Volumes/ProServices/'

    # Home server settings
    home_path = 'smb://{uname}:{pword}@bklncdn1/homes/quincy/'
    home_share_location = '/Volumes/quincy/'

    # Create predefined SMB shares dictionary
    share_dict = {'qnap': {'path': qnap_path, 'share_location': qnap_share_location}, 'home': {'path': home_path, 'share_location': home_share_location}}

    toolset = obj['toolset']
    # Check status of the share
    share_status = toolset.check_share(share_dict[remote_server]['share_location'])

    # Just show user if the share is mounted or not
    if status:
        if share_status:
            click.secho('[!] The shared drive is already mounted.', fg='green')
            sys.exit()
    else:
        # Mount drive if not mounted, unmount if mounted
        if share_status:
            click.secho('[!] The shared drive is already mounted. Attempting to unmount it.', fg='white')
            rtn_str = toolset.mount_changer(share_dict[remote_server]['share_location'])
            if not rtn_str[0]:
                logging.error(rtn_str)
                click.secho('[!] {}'.format(rtn_str[1]), fg='red')
            elif rtn_str[0]:
                click.secho('[*] Share unmounted successfully.', fg='white')
        else:
            logging.info('Share not mounted')
            # logger = logging.getLogger('')
            config = configparser.ConfigParser()
            config.read(config_file)
            logging.debug("Trying to read the config file.")
            username = config[remote_server.upper()]['Username']
            password = config[remote_server.upper()]['Password']
            logging.debug('Read the config file successfully')

            filled_path = share_dict[remote_server]['path'].format(uname=username, pword=password)

            # Mount the shared drive
            click.secho('[*] Mounting the share.', fg='white')
            click.launch(filled_path)

@mainCLI.command(name='nessus-uploader', short_help='Upload a folder or series of Nessus files to a server.')
@click.option('-l', '--local-nessus', required=True, type=click.Path(exists=False, file_okay=True, dir_okay=True, readable=True, resolve_path=True), help='Path to local Nessus file(s).')
@click.option('-t', '--target', type=click.STRING, help='Server to upload Nessus file. This should be an IP address or hostanme.', default='dc2astns01.asmt.gps')
@click.option('-p', '--port', type=click.INT, default='8834')
@click.option('-r', '--remote-folder', type=click.INT, help='Destination folder ID on Nessus server.', required=True)
@click.option('--test', is_flag=True, default=False, help='Test authentication to Nessus server.')
def nessus_uploader(local_nessus, target, remote_folder, port, test):
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
        click.secho('[!] No Nessus files were specified.',fg='red')
        click.secho('[*] Exiting.', fg='green')
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

@mainCLI.command(name='scan-export', short_help='Export a scan from a Nessus server.')
@click.option('-i', '--id', required=True, type=click.INT, help='ID of the scan on the Nessus server.')
@click.option('-o', '--output-path', type=click.Path(exists=False, file_okay=True, dir_okay=True, resolve_path=True, writable=True), help='Location and/or name to save the scan', envvar='PWD')
@click.option('-t', '--target', type=click.STRING, help='Server to upload Nessus file. This should be an IP address or hostanme.', default='dc2astns01.asmt.gps')
@click.option('-p', '--port', type=click.INT, default='8834')
@click.option('-eT', '--export-type', help='Define the exported file\'s type.', type=click.Choice(['nessus', 'db', 'pdf', 'html', 'csv']), default='nessus')
@click.option('--test', is_flag=True, default=False, help='Test authentication to Nessus server.')
def scan_export(id, output_path, target, port, test, export_type):
    """Quick and dirty way to export Nessus files"""
    # Try to log in, catch any errors
    napi = login(target, port, test)
    # Check if its a directory
    if os.path.isfile(output_path):
        if output_path.split('.')[-1:][0] == export_type:
            save_file = output_path
        else:
            click.secho('[!] The extension on this file does not match the export type of {}.'.format(export_type))
            cont_bool = click.prompt('[?] Do you want to continue?', show_default=True, type=click.BOOL)
            if cont_bool == True:
                save_file = output_path
            else:
                click.secho('[*] Exiting.', fg='red')
                sys.exit()
    elif os.path.isdir(output_path):
        # Specified a  directory
        # Todo: Use Nessus file name
        # Create filename
        default_filename = nessus_scan_default_filename()
        save_file = os.path.join(output_path, default_filename)
    elif os.path.exists(output_path):
        click.secho('[!] That file already exists, pick a new file name. Exiting.', fg='red')
        sys.exit()

    click.secho('[*] Starting to download the file. ', fg='green')
    if not test:
        # Normal mode, not test mode
        try:
            if export_type == "nessus":
                resp = napi.download_scan(id)
            else:
                resp = napi.download_scan(id, export_type)
        except NessusAPIFunctions.NessusException.RequestedFileNotFound:
            click.secho('[!] The requested file was not found. Check the file ID and try again. Exiting.', fg='red')
            sys.exit()
        click.secho('[*] Saving the scan to {}'.format(save_file), fg='green')
        with open(save_file, 'wb') as oF:
            oF.write(resp)
        click.secho('[*] Done!', fg='green')
    else:
        # Test mode
        click.secho('[*] Test mode, not actually downloading the file.', fg='green')
        click.secho('[*] Done!', fg='green')
        napi.log_out()

@mainCLI.command(name='mass-scan-export', short_help='Export all the scans in a given folder from a Nessus server.')
@click.option('-i', '--folder-id', required=True, type=click.INT, help='ID of the scan on the Nessus server.')
@click.option('-o', '--output-path', type=click.Path(exists=False, file_okay=False, dir_okay=True, resolve_path=True, writable=True), help='Location and/or name to save the scan', envvar='PWD')
@click.option('-t', '--target', type=click.STRING, help='Server to upload Nessus file. This should be an IP address or hostanme.', default='dc2astns01.asmt.gps')
@click.option('-p', '--port', type=click.INT, default='8834')
@click.option('-eT', '--export-type', help='Define the exported file\'s type.', type=click.Choice(['nessus', 'db', 'pdf', 'html', 'csv']), default='nessus')
@click.option('--test', is_flag=True, default=False, help='Test authentication to Nessus server.')
def mass_scan_export(folder_id, output_path, target, port, test, export_type):
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

@mainCLI.command(name='report-name')
@click.argument('nessus-file', type=click.Path(exists=False, file_okay=True, dir_okay=False, readable=True, resolve_path=True))
def report_name(nessus_file):
    """Get the report's name from inside the file."""
    tree = etree.parse(nessus_file)

    for node in tree.findall('.//Report'):
        report_name_str = node.attrib['name']
    if report_name_str:
        click.secho('[*] The report\'s name is: {}'.format(report_name_str), fg='green')
    else:
        click.secho('[!] This file does not have a report name. Is it a \'.nessus\' file?', fg='red')

@mainCLI.command(name='scope-check', help='Check if the given IP addresses or networks are in scope.')
@click.argument('scoping-file', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True, resolve_path=True))
@click.option('-u', '--unknown-ips', callback=IPTypeChecker.IP_Address, help='Unknown if these IPs are in scope.', multiple=True, required=True)
@click.option('-ws', '--worksheet-name', type=click.STRING, help='Name of the worksheet with IPs to check against.', default='Network Ranges')
@click.option('-cn', '--column-name', type=click.STRING, help='Name of the column with IPs to check against', default='Network Range')
@click.pass_obj
def scope_check(obj, scoping_file, unknown_ips, worksheet_name, column_name):
    """
    Find if the IPs given are in the scope list
    """
    """
    :param scoping_file: Location of scoping Excel doc. File path as string
    :type scoping_file: str
    :param unknown_ips: List of ipaddress objects which represent the unknown IPs
    :type unknown_ips: list
    :return: None, it just prints information to the console
    :rtype: None
    """
    ip_list = list()
    unknown_ips_clean = list()

    # Get IPs from scoping spreadsheet
    et = ExcelTools(scoping_file)
    # Check if worksheet is in workbook
    try:
        data = et.excelFileData(worksheet_name)
    except IPToolsExceptions.ExcelWorkBookError.WorksheetNotFound:
        raise click.BadParameter('Worksheet was not found in workbook')

    # Grab specific column from worksheet
    try:
        column_from_sheet = et.dataFromTableColumn(data, column_name)
    except IPToolsExceptions.ColumnDoesNotExist:
        raise click.BadParameter('Column name was not found in workbook')

    # Get a list of only valid IP addresses
    for i in column_from_sheet:
        try:
            ip_list.append(IPCheck.checkIfIP(i))
        except IPToolsExceptions.NotValidIP:
            logging.warning("'{}' is not a good IP address or network".format(i))

    if len(ip_list) == 0:
        err_str = "No IPs were found in column '{}' inside sheet '{}'.".format(column_name, worksheet_name)
        click.secho(err_str, fg='red')
        sys.exit()

    # Get a list of only valid IPs from unknown IPs
    for i in unknown_ips['good']:
        try:
            unknown_ips_clean.append(IPCheck.checkIfIP(i))
        except IPToolsExceptions.NotValidIP:
            logging.warning("'{}' is not a good IP address or network".format(i))

    if len(unknown_ips_clean) == 0:
        err_str = "No IPs were found in the list of provided IPs."
        click.secho(err_str, fg='red')
        sys.exit()

    # IP in scope flag
    ip_scope_flag = False

    # If if given IP or network is in scope
    for u_ip in unknown_ips_clean:
        if isinstance(u_ip, IPv4Address) or isinstance(u_ip, IPv6Address):
            in_scope_bool = IPCheck.ipInList(u_ip, ip_list)
            if in_scope_bool:
                click.secho('[*] Found that {} is in scope.'.format(str(u_ip)), fg='green')
                ip_scope_flag = True
            elif in_scope_bool == False and obj['verbose'] == True:
                click.secho('[*] {} is not in scope.'.format(str(u_ip)), fg='red')
        if isinstance(u_ip, IPv4Network) or isinstance(u_ip, IPv6Network):
            for i in ip_list:
                if isinstance(i, IPv4Network) or isinstance(i, IPv6Network):
                    # Check if the networks even overlap
                    if u_ip.overlaps(i) and u_ip >= i:
                        click.secho('[*] {} is completely in scope.'.format(u_ip), fg='green')
                        ip_scope_flag = True
                    elif u_ip.overlaps(i) and u_ip <= i:
                        click.secho('[*] {} is partially contained inside {}, which is in scope.'.format(u_ip, i), fg='blue')
                        ip_scope_flag = True
                        # Find which single addresses are in scope
                        for s in u_ip:
                            scope_bool = IPCheck.ipInList(s, i)
                            if scope_bool:
                                click.secho('[*] {} is in scope.'.format(s), fg='green')
                            elif scope_bool and obj['verbose']:
                                click.secho('[*] {} is NOT in scope.'.format(s), fg='red')
    if ip_scope_flag == False:
        click.secho('[*] None of the provided IPs are in the scoping document.')

@mainCLI.command(name='count-ips', help='Count given IPs in scoping worksheet or IPs provided.')
@click.argument('scoping-file', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True, resolve_path=True))
@click.option('-ws', '--worksheet-name', type=click.STRING, help='Name of the worksheet with IPs to check against.', default='Network Ranges')
@click.option('-cn', '--column-name', type=click.STRING, help='Name of the column with IPs to check against', default='Network Range')
def count_ips(scoping_file, worksheet_name, column_name):
    """Count IPs in scoping worksheet"""
    ip_list = list()
    master_count = 0
    network_count = 0
    addr_count = 0

    # Get IPs from scoping spreadsheet
    et = ExcelTools(scoping_file)
    # Check if worksheet is in workbook
    try:
        data = et.excelFileData(worksheet_name)
    except IPToolsExceptions.ExcelWorkBookError.WorksheetNotFound:
        raise click.BadParameter('Worksheet was not found in workbook')

    # Grab specific column from worksheet
    try:
        column_from_sheet = et.dataFromTableColumn(data, column_name)
    except IPToolsExceptions.ColumnDoesNotExist:
        raise click.BadParameter('Column name was not found in workbook')

    # Get a list of only valid IP addresses
    for i in column_from_sheet:
        try:
            ip_list.append(IPCheck.checkIfIP(i))
        except IPToolsExceptions.NotValidIP:
            logging.warning("'{}' is not a good IP address or network".format(i))

    if len(ip_list) == 0:
        err_str = "No IPs were found in column '{}' inside sheet '{}'.".format(column_name, worksheet_name)
        click.secho(err_str, fg='red')
        sys.exit()

    for ip in ip_list:
        if isinstance(ip, IPv4Address or isinstance(ip, IPv6Address)):
            pass # master_count += 1
            addr_count += 1
        elif isinstance(ip, IPv4Network) or isinstance(ip, IPv6Network):
            network_count += 1
            for i in ip:
                master_count += 1

    click.secho('[*] Scoping Stats:\n[+] Total hosts: {}\n[+] Individual Hosts: {}\n[+] Networks: {}'.format(master_count,addr_count,network_count))


def nessus_scan_default_filename():
    """Create a default filename for saved files from a Nessus server"""
    # Todo: Pull name of scan and use that to save the file
    utc = arrow.utcnow()
    local = utc.to('US/Eastern')
    date = local.format('YYYY-MM-DD')

    default_filename = 'GuidePoint_Security_Nessus_Results_{}.nessus'.format(date)
    return default_filename



if __name__ == '__main__':
    mainCLI()