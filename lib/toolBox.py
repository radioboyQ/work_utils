# Standard Library
import os
import logging
import subprocess
import sys
from . import NessusAPIFunctions
import configparser

# Packages
import click

class tools():
    """Common tools"""
    __version__ = int(1.0)

    def __init__(self, debug=False):
        """Class initialization """
        self.debug = debug
        logging.basicConfig(level=logging.DEBUG, format='%(levelname)s - %(message)s', stream=sys.stderr)

    def warning(self, objs):
        """Print object to stderr"""
        click.secho('[!] {}'.format(objs), color='yellow')
        # print(str(objs), file=sys.stderr)

    def checkVersion(self):
        """Check Python version"""
        # Check that we are running Python 3 or later
        # If not 3.X then 2.7.X
        ##If not 2.7.X, exit with error
        if sys.version_info >= (3, 0):
            # Python version is 3 or better, continue
            if self.debug:
                self.warning("[+] Python version greater then 3 detected.")
                self.warning("[+] Python version details: " + str(sys.version_info))
        elif sys.version_info >= (2, 7):
            # If 2.7, print warning, but continue
            self.warning("[!] Python version 2.7 detected.  It should work, but Python 3 is recommended.")
        else:
            # If less then 2.7, exit throwing an error that the version is too old.
            self.warning("[!] Python version is too old! Please run with at least version 2.7.  \n [!] Exiting.")
            sys.exit()

    def checkOS(self):
        """Check the OS version"""
        # Check the OS version we are running on
        # Blacklist Windows because nobody likes Windows file paths
        blackList = ['Windows']

        # Darwin = Mac
        # Linux = Linux
        import platform
        systemType = platform.system()
        if systemType in blackList:
            self.warning("[!] This script does not support " + str(
                systemType) + ". Please use a Linux or Mac computer.\n[*] Exiting")
            sys.exit()
        if self.debug:
            self.warning("[+] Detected OS: " + systemType)

    def check_share(self, share_location):
        """
        Check if the provided path is a mount point or share.
        :rtype: bool
        :return: True for mounted and False for not mounted
        """
        return os.path.ismount(share_location)

    def mount_changer(self, share_location):
        """
        # Mount drive if not mounted, unmount if mounted
        :return: True for successful unmount and False for a failure. Also return error message in tuple
        """
        cmd_rtn = subprocess.run("diskutil unmount {}".format(share_location), shell=True, check=False, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        if cmd_rtn.returncode == 0:
            return (True, 'Share unmounted successfully',)
        elif cmd_rtn.returncode != 0:
            # If it failed somehow, return error msg
            err_str = '{}'.format(cmd_rtn.stderr.decode("utf-8"))
            return (False, err_str,)

def nessus_login(target, port, test):
        """Container for everything needed to log into Nessus"""

        config_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), ".config.ini")
        api_key_bool = False

        if os.path.isfile(config_file) and (target == 'kali-local' or target == '172.16.209.10' or target == 'dc2astns01.asmt.gps' or target == 'dc2astns01'):
            logging.info('Found a config file')
            config = configparser.ConfigParser()
            config.read(config_file)

            if target == 'kali-local' or target == '172.16.209.10':
                target = 'kali-local'
                # kali-local API keys
                logging.debug("Trying to read the config file for {}.".format(target))
                access_key = config[target]['access_key']
                secret_key = config[target]['secret_key']
                api_key_bool = True
            elif target == 'dc2astns01.asmt.gps' or target == 'dc2astns01':
                target = 'dc2astns01.asmt.gps'
                # dc2astns01.asmt.gps API keys
                logging.debug("Trying to read the config file for {}.".format(target))
                access_key = config[target]['access_key']
                secret_key = config[target]['secret_key']
            elif target == 'localhost':
                api_key_bool = True
                # ConAm API Keys
                logging.debug("Trying to read the config file for {}.".format(target))
                access_key = config[target]['access_key']
                secret_key = config[target]['secret_key']
        else:
            logging.warning('Couldn\'t find a config file.')
            logging.warning('Unrecognized Nessus host.')
            uname = click.prompt('[?] Username')
            passwd = click.prompt('[?] Password', hide_input=True)
            # print('Username: {}'.format(uname))
            # print('Password: {}'.format(passwd))

        # Authentication
        try:
            if api_key_bool == True:
                napi = NessusAPIFunctions.Nessus_Scanner('https://{}:{}'.format(target, port), api_akey=access_key,
                                                         api_skey=secret_key, insecure=True)
            elif api_key_bool == False:
                napi = NessusAPIFunctions.Nessus_Scanner('https://{}:{}'.format(target, port), insecure=True,
                                                         login=uname, password=passwd)
        except NessusAPIFunctions.NessusException.FailureToConnect:
            click.secho('[!] Failure connecting to remote server. Check your port and hostname/IP. Exiting.', fg='red')
            sys.exit()
        except NessusAPIFunctions.NessusException.InvalidCredentials:
            click.secho('[!] The provided credentials didn\'t work, check them and try again.', fg='red')
            sys.exit()

        if test == True:
            click.secho('[*] Successfully authenticated to the server.  ', fg='green')
        return napi