import json
from requests import get
import re

CVEDETAILS_FEED_URL = 'http://www.cvedetails.com/json-feed.php'\
    '?numrows=30'\
    '&vendor_id=0'\
    '&product_id=0'\
    '&version_id=0'\
    '&hasexp=0'\
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
    return get(CVEDETAILS_FEED_URL).json()


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


def load_data(data_file_path):
    with open(data_file_path) as data_file:
        return json.load(data_file)


def save_data(data, data_file_path):
    with open(data_file_path, 'w') as data_file:
        return json.dump(data, data_file, indent=2)


def create_keyword(regex_string):
    return {'regex': regex_string}


def create_data_structure():
    return {}


def add_keyword(name, regex, keyword_file_path):
    try:
        keywords = load_keywords(keyword_file_path)
    except:
        keywords = {}

    # test if paramter is a valid regex
    re.compile(regex)
    keywords[name] = create_keyword(regex)
    save_keywords(keywords, keyword_file_path)


def add_cve(cve, keyword, data):
    cve_data = {'date': cve['publish_date'],
                'score': cve['cvss_score'],
                'description': cve['summary']}
    data.setdefault(keyword, {}).setdefault(cve['cve_id'], cve_data)
    return data


def update_cves(keyword_file_path, data_file_path):
    keywords = load_keywords(keyword_file_path, compile_regex=True)
    try:
        prev_cves = load_data(data_file_path)
    except:
        prev_cves = create_data_structure()
    cve_feed = get_cves()

    for cve in cve_feed:
        for keyword in keywords:
            if cve['cve_id'] in prev_cves.get(keyword, {}):
                continue
            if keywords[keyword]['re'].findall(cve['summary']):
                print("{1}\t{0}\t{2}\t{3}".format(cve['cve_id'],
                                                  keyword,
                                                  cve['cvss_score'],
                                                  cve_url(cve['cve_id'])))
                add_cve(cve, keyword, prev_cves)

    save_data(prev_cves, data_file_path)


def list_cves(data_file, from_date=None):
    """List keywords"""
    keywords = load_data(data_file)
    for keyword, keyword_data in keywords.items():
        for cve, cve_details in keyword_data.items():
            if (not from_date
                or (cve_details['date'] >= from_date
                    or cve_details['date'].startswith(from_date))):
                cve_details['id'] = cve
                cve_details['keyword'] = keyword
                yield cve_details


def cve_url(cve):
    return 'http://www.cvedetails.com/cve/{0}/'.format(cve)
