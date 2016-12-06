# Standard Library
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
import logging
import sys

# Packages
import click

# My junk
from ..lib.iptools import ExcelTools, IPCheck
from ..lib.iptools import IPToolsExceptions
from utils.cli import pass_context

# Disable Requests' warning when using bad SSL certs
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


@click.command(name='count-ips', help='Count given IPs in scoping worksheet or IPs provided.')
@click.argument('scoping-file', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True, resolve_path=True))
@click.option('-ws', '--worksheet-name', type=click.STRING, help='Name of the worksheet with IPs to check against.', default='Network Ranges')
@click.option('-cn', '--column-name', type=click.STRING, help='Name of the column with IPs to check against', default='Network Range')
@pass_context
def cli(ctx, scoping_file, worksheet_name, column_name):
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
        ctx.logc(err_str, fg='red')
        sys.exit()

    for ip in ip_list:
        if isinstance(ip, IPv4Address or isinstance(ip, IPv6Address)):
            pass # master_count += 1
            addr_count += 1
        elif isinstance(ip, IPv4Network) or isinstance(ip, IPv6Network):
            network_count += 1
            for i in ip:
                master_count += 1

    ctx.logc('[*] Scoping Stats:\n[+] Total hosts: {}\n[+] Individual Hosts: {}\n[+] Networks: {}'.format(master_count,addr_count,network_count))