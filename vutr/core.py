import json
from requests import get
import re

CVEDETAILS_FEED_URL = 'http://www.cvedetails.com/json-feed.php'\
    '?numrows=30'\
    '&vendor_id=0'\
    '&product_id=0'\
    '&version_id=0'\
    '&hasexp=1'\
    '&opec=1'\
    '&opov=1'\
    '&opcsrf=1'\
    '&opfileinc=1'\
    '&opgpriv=1'\
    '&opsqli=1'\
    '&opxss=1'\
    '&opdirt=1'\
    '&opmemc=1'\
    '&ophttprs=1'\
    '&opbyp=1'\
    '&opginf=1'\
    '&opdos=1'\
    '&orderby=1'\
    '&cvssscoremin=0'


def get_cves():
    # [u'update_date', u'cve_id', u'exploit_count', u'summary', u'url',
    # u'publish_date', u'cvss_score', u'cwe_id']
    return json.loads(get(CVEDETAILS_FEED_URL).text)


def load_keywords(keyword_file_path, compile_regex=False):
    with open(keyword_file_path) as keyword_file:
        keywords = json.load(keyword_file)

    if not compile_regex:
        return keywords

    for keyword_data in keywords.values():
        keyword_data['re'] = re.compile(keyword_data['regex'], re.I | re.U)

    return keywords


def save_keywords(keywords, keyword_file_path):
    for keyword_data in keywords.values():
        if 're' in keyword_data:
            keyword_data.pop('re')

    with open(keyword_file_path, 'w') as keyword_file:
        return json.dump(keywords, keyword_file, indent=2)


def create_keyword(regex_string):
    return {'regex': regex_string, 'cves': {}}


def add_keyword(name, regex, keyword_file_path):
    try:
        keywords = load_keywords(keyword_file_path)
    except:
        keywords = {}
    keywords[name] = create_keyword(regex)
    save_keywords(keywords, keyword_file_path)


def add_cve(cve, keyword_data):
    cve_data = {'date': cve['publish_date'], 'score': cve['cvss_score']}
    keyword_data['cves'][cve['cve_id']] = cve_data


def update_cves(keyword_file_path):
    keywords = load_keywords(keyword_file_path, compile_regex=True)
    cve_feed = get_cves()

    for cve in cve_feed:
        for keyword, keyword_data in keywords.items():
            if cve['cve_id'] in keyword_data['cves']:
                continue
            if keyword_data['re'].findall(cve['summary']):
                print("{0} ({2}) match with {1}".format(cve['cve_id'],
                                                        keyword,
                                                        cve['cvss_score']))
                print(cve['summary'])
                add_cve(cve, keyword_data)

    save_keywords(keywords, keyword_file_path)


def list_cves(data_file, from_date=None):
    """List keywords"""
    keywords = load_keywords(data_file)
    for keyword, keyword_data in keywords.items():
        for cve, cve_details in keyword_data['cves'].items():
            if (not from_date
                or (cve_details['date'] >= from_date
                    or cve_details['date'].startswith(from_date))):
                cve_details['id'] = cve
                cve_details['keyword'] = keyword
                yield cve_details


def cve_url(cve):
    return 'http://www.cvedetails.com/cve/{0}/'.format(cve)
