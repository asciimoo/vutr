import click
from sre_constants import error as regex_error
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
    try:
        add_keyword(keyword, regex, data_file)
    except regex_error, e:
        click.echo('[!] regex error: {0}'.format(e.message))
    except Exception, e:
        click.echo('[!] failed to add keyword: {0}'.format(e.message))
    else:
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
        click.echo('{0} {2} ({1})\n{3}\n{4}\n{5}\n'.format(cve['keyword'],
                                                           cve['score'],
                                                           cve['date'],
                                                           cve['id'],
                                                           cve_url(cve['id']),
                                                           cve['description']))


@cli.command("update")
@click.option('-f', '--data-file',
              type=click.Path(writable=True, readable=True),
              default=DATA_FILE_PATH)
def update(data_file):
    """Check new CVEs"""
    update_cves(data_file)
