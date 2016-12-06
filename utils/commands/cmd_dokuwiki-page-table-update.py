import configparser
import logging
import os
import sys

import arrow
import click

sys.path.insert(0, '/Users/scottfraser/myToolsPath')
from utils.cli import pass_context
import XRequests


url = 'http://localhost/lib/exe/xmlrpc.php'
username = 'radioboy'
password = 'mn1Radioboyiaf0!'

d_conn = XRequests.doku_wiki(username, password)

@click.command(name='dokuwiki-page-table-update', short_help='Update the main page of the local Dokuwiki install.')
@pass_context
def cli(ctx):
    """Update the main page of the local Dokuwiki install."""
    page_dict = dict()
    final_table_list = list()
    all_page_table_headers = ['Name', 'Last Modified', 'Permissions', 'Size of Page']
    for page in d_conn.getAllPages:
        page_dict[page['id']] = [page['lastModified'], page['perms'], page['size']]

    for i in sorted(page_dict, key=lambda x: x[0][0]):
        temp_list = list()
        # Create a table
        attrib_list = page_dict[i]
        final_table_list.append(['[[ {} ]]'.format(i), arrow.get(str(attrib_list[0])).humanize(), page_dict[i][1],
                                 page_dict[i][2]])
    final_table_list.insert(0, all_page_table_headers)
    wiki_table = XRequests.doku_wiki_utils.create_table(final_table_list, center=True)

    # Upload new page
    page_name = 'start'

    # Check if we can edit the page
    permissions_num = d_conn.aclCheck(page_name)
    if permissions_num < 2:
        ctx.log('[!] Not enough permissions to edit')
        sys.exit()
    response = d_conn.putPage(page_name, wiki_table, ['sum', 'Updating Page List', 'minor', True])
    if response:
        pass # ctx.log('Success!')
    else:
        pass # ctx.log('Failure :(')