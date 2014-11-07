import click
from os.path import expanduser
from .core import add_keyword, load_keywords, update_cves, cve_url

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
    """Add new keyword/regex pair"""
    add_keyword(keyword, regex, data_file)
    click.echo('[!] keyword "{0}" added'.format(keyword))


@cli.command("list")
@click.argument('from_date', default=None)
@click.option('-f', '--data-file',
              type=click.Path(readable=True),
              default=DATA_FILE_PATH)
def list_keywords(data_file, from_date=None):
    """List keywords"""
    keywords = load_keywords(data_file)
    for keyword, keyword_data in keywords.items():
        for cve, cve_details in keyword_data['cves'].items():
            if (not from_date
                or (cve_details['date'] >= from_date
                    or cve_details['date'].startswith(from_date))):
                click.echo('{3}\t{1}\t{2}\t{0}'.format(keyword,
                                                       cve_url(cve),
                                                       cve_details['score'],
                                                       cve_details['date']))


@cli.command("update")
@click.option('-f', '--data-file',
              type=click.Path(writable=True, readable=True),
              default=DATA_FILE_PATH)
def update(data_file):
    """Check new CVEs"""
    update_cves(data_file)
