import configparser
import csv
from pprint import pprint

import click
from terminaltables import AsciiTable

from utils.cli import pass_context
from utils.lib.GoPhishAPI import *

logger = logging.getLogger(__name__)

def build_row(raw_row):
    """Create the list of values needed for the final report from GoPhish timeline"""
    temp_row = dict()
    ### Plan
    # Add email addresses to row
    # If message == Clicked or message == Submitted data
    ## Append 'Time Clicked' to dict. Format MM/DD/YYYY | HH:mm
    ## If message == Submitted data
    ### Append Credentials Harvested: Yes to dict
    ## Else:
    ### Append Credentials Harvested: No to dict
    # Append Reported: No, Replied to Email: No, Notes: ''

    # Append email
    temp_row['Email Address'] = raw_row['email']

    if raw_row['message'] == 'Clicked Link' or raw_row['message'] == 'Submitted Data':
        # print(raw_row['time'])
        # print(arrow.get(raw_row['time'], 'YYYY-MM-DDTHH:mm:ss.SSSSSSSSS-ZZ').format('MM/DD/YYYY | HH:mm'))
        temp_row['Time Clicked'] = arrow.get(raw_row['time'], 'YYYY-MM-DDTHH:mm:ss.SSSSSSSSS-ZZ').format('MM/DD/YYYY | HH:mm')
        if raw_row['message'] == 'Submitted Data':
            temp_row['Credentials Harvested'] = 'Yes'
        else:
            temp_row['Credentials Harvested'] = 'No'
    else:
        temp_row['Time Clicked'] = 'N/A'
        temp_row['Credentials Harvested'] = 'No'

    temp_row.update({'Reported': '', 'Replied to Email': '', 'Notes': ''})
    return temp_row



@click.group(invoke_without_command=False)
@click.option('-a', '--api-key', help='Specify an API key other than the config file.', type=click.STRING)
@click.option('-h', '--host', help='Address or domain name where GoPhish server lives.')
@click.option('-p', '--port', help='Port to connect to.', type=click.IntRange(1, 65535))
@click.option('-c', '--campaign-number', help='GoPhish campaign number to look up.', type=click.INT, required=True)
@pass_context
def cli(ctx, api_key, host, port, campaign_number):
    """Setup for other GoPhish commands"""
    ### Plan

    #### Configuration
    # Check what variables are still needed
    ## Read config file for those specific needs
    ### Error if any of the above values are not provided in the config file or CLI

    if api_key is None or host is None or port is None:
        config = configparser.ConfigParser()
        config.read(ctx.config)

        if api_key is None:
            api_key = config['GOPHISH']['api_key']
            logger.info('API Key from config file : {}'.format(api_key))

        if host is None:
            host = config['GOPHISH']['host']
            logger.info('Host from config file :    {}'.format(host))

        if port is None:
            port = config['GOPHISH']['port']
            logger.info('Port from config file :    {}'.format(port))

    ctx.api_key = api_key
    ctx.host = host
    ctx.port = port
    ctx.campaign_number = campaign_number
    ctx.campaign_info = None


@cli.command(name='create_csv')
@click.argument('output-file', type=click.Path(dir_okay=False, writable=True, resolve_path=True, allow_dash=True))
@pass_context
def csv_maker(ctx, output_file):
    """Format data from GoPhish into CSV files"""
    ### Plan

    ### Configuration
    # Check if campaign_info is not None
    ## If not None
    ### Process the data
    ## Else:
    ### Get data
    ### Process the data

    #### Get the data
    # Authenticate to the GoPhish server
    ## Capture auth failures
    # Request campaign data
    # Parse returned data into buckets
    ## Capture bad campaign data


    if ctx.campaign_info is None: # Command is not chained together, get our own data
        gophish_inst = GoPhish(ctx.api_key, ctx.host, ctx.port, verify=False)

        campaign_info = gophish_inst.get_campaigns(ctx.campaign_number)

        ctx.campaign_info = campaign_info
    else:
        campaign_info = ctx.campaign_info

    # Dict of final values per email
    final_email_dict = dict()

    headers = ['Email Address', 'Time Clicked', 'Credentials Harvested', 'Reported', 'Replied to Email', 'Notes']



    for i in campaign_info['timeline']:
        if i['message'] != 'Campaign Created': #  and len(i['details']) > 0:
            row = build_row(i)
            # Update file dictionary
            final_email_dict[row['Email Address']] = row

    with open(output_file, 'w') as f:
        writer = csv.DictWriter(f, headers)
        writer.writeheader()
        for email in final_email_dict:
            writer.writerow(final_email_dict[email])



@cli.command(name='status')
@pass_context
def status(ctx):
    """Phishing Campaign Status"""
    ### Plan

    #### Get the data
    # Authenticate to the GoPhish server
    ## Capture auth failures
    # Request campaign data
    # Parse returned data into buckets
    ## Capture bad campaign data

    #### Prep data for display

    #### Display data
    # Print data to screen

    api_key = ctx.api_key
    host = ctx.host
    port = ctx.port
    campaign_number = ctx.campaign_number

    gophish_inst = GoPhish(api_key, host, port, verify=False)

    campaign_info = gophish_inst.get_campaigns(campaign_number)

    # Add data to context object
    ctx.campaign_info = campaign_info

    # pprint(campaign_info, indent=1)

    total_emails = len(campaign_info['results'])

    event_ranking = {'Email Sent': 0, 'Email Opened': 1, 'Clicked Link': 2, 'Submitted Data': 3}

    email_sent_counter = 0
    email_opened_counter = 0
    clicked_link_counter = 0
    submitted_data_counter = 0

    # Status of each email address
    email_dict = dict()

    for i in campaign_info['timeline']:
        if i['message'] != 'Campaign Created':
            email_dict[i['email']] = {'status': event_ranking[i['message']], 'time': i['time']}

    counter = 0
    for e in email_dict:
        counter += 1
        if email_dict[e]['status'] == 0:
            email_sent_counter += 1
        elif email_dict[e]['status'] == 1:
            email_opened_counter += 1
        elif email_dict[e]['status'] == 2:
            clicked_link_counter += 1
        elif email_dict[e]['status'] == 3:
            submitted_data_counter += 1

    logger.info('Data submitted: {}'.format(submitted_data_counter))
    logger.info('Clicked Links: {}'.format(clicked_link_counter))
    logger.info('Emails Opened: {}'.format(email_opened_counter))
    logger.info('Emails Sent: {}'.format(email_sent_counter))
    logger.info('My Total: {}'.format(email_sent_counter + email_opened_counter + clicked_link_counter + submitted_data_counter))

    # Calculate percent of total for each category
    sent_percentage = (float(email_sent_counter) * 100 / float(total_emails))
    logger.debug('Sent Emails Percentage: {}%'.format(sent_percentage))

    opened_percentage = (float(email_opened_counter) * 100 / float(total_emails))
    logger.debug('Opened Emails: {}%'.format(opened_percentage))

    clicked_percentage = (float(clicked_link_counter) * 100 / float(total_emails))
    logger.debug('Clicked Links: {}%'.format(clicked_percentage))

    submitted_percentage = (float(submitted_data_counter) * 100 / float(total_emails))
    logger.debug('Submitted Data: {}%'.format(submitted_percentage))

    table_data = [['Events', 'Percent'], ['Emails Sent', '{}%'.format(str(sent_percentage))], ['Emails Opened', '{}%'.format(str(opened_percentage))], ['Clicked Links', '{}%'.format(str(clicked_percentage))], ['Submitted Data', '{}%'.format(str(submitted_percentage))]]

    table = AsciiTable(table_data, title='Results of GoPhish Campaign')

    table.justify_columns[0] = 'center'
    table.justify_columns[1] = 'center'

    click.echo(table.table)