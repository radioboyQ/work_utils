import configparser
import logging
from pprint import pprint

import click
from terminaltables import AsciiTable, SingleTable

from utils.cli import pass_context
from utils.lib.GoPhishAPI import *

# gophish_logger = logging.getLogger('utils.gophish-status')
logger = logging.getLogger(__name__)

@click.group(invoke_without_command=True, name='gophish')
@click.option('-a', '--api-key', help='Specify an API key other than the config file.', type=click.STRING)
@click.option('-h', '--host', help='Address or domain name where GoPhish server lives.')
@click.option('-p', '--port', help='Port to connect to.', type=click.IntRange(1,65535))
@click.option('-c', '--campaign-number', help='GoPhish campaign number to look up.', type=click.INT, required=True)
@pass_context
def cli(ctx, api_key, host, port, campaign_number):
    """Phishing Campaign Status"""
    ### Plan

    #### Configuration
    # Check what variables are still needed
    ## Read config file for those specific needs
    ### Error if any of the above values are not provided in the config file or CLI

    #### Get the data
    # Authenticate to the GoPhish server
    ## Capture auth failures
    # Request campaign data
    # Parse returned data into buckets
    ## Capture bad campaign data

    #### Prep data for display

    #### Display data
    # Print data to screen

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

    gophish_inst = GoPhish(api_key, host, port, verify=False)

    campaign_info = gophish_inst.get_campaigns(campaign_number)

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

    logger.debug('Data submitted: {}'.format(submitted_data_counter))
    logger.debug('Clicked Links: {}'.format(clicked_link_counter))
    logger.debug('Emails Opened: {}'.format(email_opened_counter))
    logger.debug('Emails Sent: {}'.format(email_sent_counter))
    logger.debug('My Total: {}'.format(email_sent_counter + email_opened_counter + clicked_link_counter + submitted_data_counter))

    # Calculate percent of total for each category
    sent_percentage = (float(email_sent_counter) * 100 / float(total_emails))
    logger.info('Sent Emails Percentage: {}%'.format(sent_percentage))

    opened_percentage = (float(email_opened_counter) * 100 / float(total_emails))
    logger.info('Opened Emails: {}%'.format(opened_percentage))

    clicked_percentage = (float(clicked_link_counter) * 100 / float(total_emails))
    logger.info('Clicked Links: {}%'.format(clicked_percentage))

    submitted_percentage = (float(submitted_data_counter) * 100 / float(total_emails))
    logger.info('Submitted Data: {}%'.format(submitted_percentage))

    table_data = [['Events', 'Percent'], ['Emails Sent', '{}%'.format(str(sent_percentage))], ['Emails Opened', '{}%'.format(str(opened_percentage))], ['Clicked Links', '{}%'.format(str(clicked_percentage))], ['Submitted Data', '{}%'.format(str(submitted_percentage))]]

    table = AsciiTable(table_data, title='Results of GoPhish Campaign')

    table.justify_columns[0] = 'center'
    table.justify_columns[1] = 'center'

    click.echo(table.table)
