# Standard Library
import os
from os import walk
import configparser
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address, IPv4Network, IPv6Network
import logging
import subprocess
import sys

# Packages
import click

# My junk
from ..lib.iptools import IPTypeChecker, ExcelTools, IPToolsExceptions, IPCheck
from utils.cli import pass_context

# Disable Requests' warning when using bad SSL certs
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


@click.command(name='scope-check', help='Check if the given IP addresses or networks are in scope.')
@click.argument('scoping-file', type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True, resolve_path=True))
@click.option('-u', '--unknown-ips', callback=IPTypeChecker.IP_Address, help='Unknown if these IPs are in scope.', multiple=True, required=True)
@click.option('-ws', '--worksheet-name', type=click.STRING, help='Name of the worksheet with IPs to check against.', default='Network Ranges')
@click.option('-cn', '--column-name', type=click.STRING, help='Name of the column with IPs to check against', default='Network Range')
@pass_context
def cli(ctx, scoping_file, unknown_ips, worksheet_name, column_name):
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
        ctx.logc(err_str, fg='red')
        sys.exit()

    # Get a list of only valid IPs from unknown IPs
    for i in unknown_ips['good']:
        try:
            unknown_ips_clean.append(IPCheck.checkIfIP(i))
        except IPToolsExceptions.NotValidIP:
            logging.warning("'{}' is not a good IP address or network".format(i))

    if len(unknown_ips_clean) == 0:
        err_str = "No IPs were found in the list of provided IPs."
        ctx.logc(err_str, fg='red')
        sys.exit()

    # IP in scope flag
    ip_scope_flag = False

    # If if given IP or network is in scope
    for u_ip in unknown_ips_clean:
        if isinstance(u_ip, IPv4Address) or isinstance(u_ip, IPv6Address):
            in_scope_bool = IPCheck.ipInList(u_ip, ip_list)
            if in_scope_bool:
                ctx.logc('[*] Found that {} is in scope.'.format(str(u_ip)), fg='green')
                ip_scope_flag = True
            elif in_scope_bool == False and ctx.verbose == True:
                ctx.vlogc('[*] {} is not in scope.'.format(str(u_ip)), fg='red')
        if isinstance(u_ip, IPv4Network) or isinstance(u_ip, IPv6Network):
            for i in ip_list:
                if isinstance(i, IPv4Network) or isinstance(i, IPv6Network):
                    # Check if the networks even overlap
                    if u_ip.overlaps(i) and u_ip >= i:
                        ctx.logc('[*] {} is completely in scope.'.format(u_ip), fg='green')
                        ip_scope_flag = True
                    elif u_ip.overlaps(i) and u_ip <= i:
                        ctx.logc('[*] {} is partially contained inside {}, which is in scope.'.format(u_ip, i), fg='blue')
                        ip_scope_flag = True
                        # Find which single addresses are in scope
                        for s in u_ip:
                            scope_bool = IPCheck.ipInList(s, i)
                            if scope_bool:
                                ctx.logc('[*] {} is in scope.'.format(s), fg='green')
                            elif scope_bool and ctx.verbose:
                                ctx.vlogc('[*] {} is NOT in scope.'.format(s), fg='red')
    if ip_scope_flag == False:
        ctx.logc('[*] None of the provided IPs are in the scoping document.')