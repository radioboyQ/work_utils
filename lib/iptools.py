# Standard Library
import collections
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address, IPv4Network, IPv6Network
import logging

# Packages
import click
import pandas as pd
import xlrd

logger = logging.getLogger(__name__)

class IPTypeChecker(click.ParamType):
    '''Input type checking for Click'''
    name = 'IP'

    def IP_Address(ctx, param: str, data_in: tuple) -> dict:
        '''
        Checks if Click command arguments are actually IPs

        If you are looking to convert strings to IP addresses, use IPTools.check_if_ip

        Returns a dictionary with a list of IPs under 'good' and list of bad data under 'bad'.
        :param ctx: Click context object
        :type ctx: click.core.Option
        :param param: Click parameter object
        :type param: click.core.Option
        :param data_in: Tuple of IPs to check
        :return: Returns a dictionary with a list of IPs under 'good' and list of bad data under 'bad'.
        :rtype: dict
        '''
        good = list()
        bad = list()
        if len(data_in) >= 1:
            for ip in data_in:
                ip_res = IPCheck.checkIfIP(ip)
                if ip_res is not None:
                    good.append(ip_res)
                else:
                    bad.append(ip)
            if len(good) == 0:
                raise click.BadParameter('No IP addresses were provided which are valid')
            else:
                return {'good': good, 'bad': bad}
        else:
            return None

class IPCheck():

    @staticmethod
    def checkIfIP(ip: str):
        """
        Checks if the provided string is a valid IPv4 or IPv6 address

        This function either returns an ipaddress object or None
        :param ip: IP address in string format
        :type ip: str
        :return: Returns an ipaddress object
        :rtype: ipaddress
        """
        try:
            return ip_address(ip)
        except ValueError:
            try:
                return ip_network(ip, strict=False)
            except ValueError:
                raise IPToolsExceptions.NotValidIP("'{}' is not a valid IP network or address".format(ip)) from None

    @staticmethod
    def ipInList(u_ip, ip_list):
        """
        Check if an unknown IP address (not network), (u_ip) is in a provided list (ip_list)
        :param u_ip: IP address
        :param ip_list: List of IP addresses or networks
        :return: True if u_ip in ip_list; False if u_ip NOT in ip_list
        """
        for i in ip_list:
            if isinstance(i, IPv4Address or isinstance(i, IPv6Address)):
                if u_ip == i:
                    return True
            elif isinstance(i, IPv4Network) or isinstance(i, IPv6Network):
                if u_ip in i:
                    return True
        return False

class ExcelTools(object):

    def __init__(self, excel_filename: str):
        """
        Define Excel file to work on
        :param excel_filename: Filename or path to Excel file
        :type excel_filename: str
        """

        if not isinstance(excel_filename, str):
            raise TypeError('Filename must be a string')

        self.excel_filename = excel_filename

    def excelFileData(self, worksheet_name, skip_row: int = 1):
        """
        Get data from the Excel file and specific worksheet. Return a dictionary of the worksheet
        :param worksheet_name: Worksheet with data
        :type worksheet_name: str
        :param column_name_num: Column name or Column number with data in it
        :return: Network ranges as IPAddress type in list
        :rtype: list
        """
        try:
            df = pd.read_excel(self.excel_filename, worksheet_name, skiprows=skip_row)
        except xlrd.biffh.XLRDError:
            raise IPToolsExceptions.ExcelWorkbookError.WorksheetNotFound from None
        else:
            return df.to_dict()

    def dataFromTableColumn(self, table: dict, column_name: str):
        """
        Obtain specific columns from a given dictionary.
        These dictionaries are generated by Pandas

        ..note ::
            * column_name is assumed to be 'Network Range' as its commonly used
            * Raises IPToolsExceptions.ColumnDoesNotExist when the column doesn't exist

        :param table: Dictionaries generated by Pandas reading an Excel workbook
        :type table: dict
        :param column_name: Name of the column where the data resides
        :type column_name: str
        :return: Returns a list of all the data in a specific column
        :rtype: list
        """
        column_list = list()

        # Check if column exists
        if column_name not in table:
            err_str = "'{}' is not a valid column name".format(column_name)
            raise IPToolsExceptions.ExcelWorkbookError.ColumnDoesNotExist(err_str) from None

        # Get the entire column
        for row in table[column_name]:
            column_list.append(table[column_name][row])

        return column_list

class IPToolsExceptions(Exception):
    class ExcelWorkbookError(Exception):
        """Raised when there is a general workbook error"""
        class WorksheetNotFound(Exception):
            """Raised when the worksheet could not be opened"""
        class ColumnDoesNotExist(Exception):
            """Raised when the column is not found in the table"""
    class DNSError(Exception):
        """Exception raised when DNS queries encounter an error"""
        class DNSRecordNotFound(Exception):
            """Exception raised when DNS record was not found"""
    class NotValidIP(Exception):
        """Exception raised when given string is not a valid IP network or address"""
    class NoValidIPs(Exception):
        """Exception raised when no IP address are present"""