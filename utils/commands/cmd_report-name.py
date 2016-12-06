# Standard Library

# Packages
import click
from lxml import etree

# My junk
from utils.cli import pass_context

@click.command(name='report-name')
@click.argument('nessus-file', type=click.Path(exists=False, file_okay=True, dir_okay=False, readable=True, resolve_path=True))
@pass_context
def cli(ctx, nessus_file):
    """Get the report's name from inside the file."""
    tree = etree.parse(nessus_file)
    report_name_str = None

    for node in tree.findall('.//Report'):
        report_name_str = node.attrib['name']
    if report_name_str is not None:
        ctx.logc('[*] The report\'s name is: {}'.format(report_name_str), fg='green')
    else:
        ctx.logc('[!] This file does not have a report name. Is it a \'.nessus\' file?', fg='red')