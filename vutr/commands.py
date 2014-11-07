import click
from operator import itemgetter
from os.path import expanduser
from .core import (add_keyword,
                   update_cves,
                   list_cves,
                   cve_url)

DATA_FILE_PATH = expanduser('~/.vutr_data.json')


@click.group()
def cli():
    pass


@cli.command("add")
@click.argument('keyword')
@click.argument('regex')
@click.option('-f', '--data-file',
              type=click.Path(writable=True),
              default=DATA_FILE_PATH)
def add(keyword, regex, data_file):
    """Add new keyword/pattern pair"""
    add_keyword(keyword, regex, data_file)
    click.echo('[!] keyword "{0}" added'.format(keyword))


@cli.command("list")
@click.argument('from_date', default="")
@click.option('-f', '--data-file',
              type=click.Path(readable=True),
              default=DATA_FILE_PATH)
def list_keywords(data_file, from_date):
    """List keywords"""
    for cve in sorted(list_cves(data_file, from_date),
                      key=itemgetter('date')):
        click.echo('{3}\t{1}\t{2}\t{0}'.format(cve['keyword'],
                                               cve_url(cve['id']),
                                               cve['score'],
                                               cve['date']))


@cli.command("update")
@click.option('-f', '--data-file',
              type=click.Path(writable=True, readable=True),
              default=DATA_FILE_PATH)
def update(data_file):
    """Check new CVEs"""
    update_cves(data_file)
