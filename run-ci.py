#!/usr/bin/env python3
import os
import argparse
import logging
import configparser
import requests
import re

from enum import Enum
from github import Github
from urllib.request import urlretrieve

# Globals
logger = None

github_repo = None
github_pr = None
github_commits = None

pw_sid = None
pw_series = None
pw_series_patch_1 = None

PW_BASE_URL = "https://patchwork.kernel.org/api/1.1"

def requests_url(url):
    """ Helper function to requests WEB API GET with URL """

    resp = requests.get(url)
    if resp.status_code != 200:
        raise requests.HTTPError("GET {}".format(resp.status_code))

    return resp

def requests_post(url, headers, content):
    """ Helper function to post data to URL """

    resp = requests.post(url, content, headers=headers)
    if resp.status_code != 201:
        raise requests.HTTPError("POST {}".format(resp.status_code))

    return resp

def patchwork_get_series(sid):
    """ Get series detail from patchwork """

    url = PW_BASE_URL + "/series/" + sid
    req = requests_url(url)

    return req.json()

def patchwork_get_patch(patch_id: str):
    """ Get patch detsil from patchwork """

    url = PW_BASE_URL + "/patches/" + patch_id
    req = requests_url(url)

    return req.json()

def patchwork_get_sid(pr_title):
    """
    Parse PR title prefix and get PatchWork Series ID
    PR Title Prefix = "[PW_S_ID:<series_id>] XXXXX"
    """

    try:
        sid = re.search(r'^\[PW_SID:([0-9]+)\]', pr_title).group(1)
    except AttributeError:
        logging.error("Unable to find the series_id from title %s" % pr_title)
        sid = None

    return sid

def patchwork_post_checks(user, url, state, target_url, context, description):
    """
    Post checks(test results) to the patchwork site(url)
    """

    logger.debug("URL: %s" % url)

    headers = {}
    if 'PATCHWORK_TOKEN' in os.environ:
        token = os.environ['PATCHWORK_TOKEN']
        headers['Authorization'] = f'Token {token}'

    content = {
        'user': user,
        'state': state,
        'target_url': target_url,
        'context': context,
        'description': description
    }

    logger.debug("Content: %s" % content)

    req = requests_post(url, headers, content)

    return req.json()

class Verdict(Enum):
    PENDING = 0
    PASS = 1
    FAIL = 2
    ERROR = 3
    SKIP = 4
    WARNING = 5


def patchwork_state(verdict):
    """
    Convert verdict to patchwork state
    """
    if verdict == 'pending':
        return 0
    if verdict == 'pass':
        return 1
    if verdict == 'warning':
        return 2
    if verdict == 'fail':
        return 3

    return 0

def init_github(repo, pr_num):
    """
    Initialize github object
    """

    global github_repo
    global github_pr
    global github_commits
    global pw_sid
    global pw_series
    global pw_series_patch_1

    github_repo = Github(os.environ['GITHUB_TOKEN']).get_repo(repo)
    github_pr = github_repo.get_pull(pr_num)
    github_commits = github_pr.get_commits()

    pw_sid = patchwork_get_sid(github_pr.title)
    pw_series = patchwork_get_series(pw_sid)
    pw_series_patch_1 = patchwork_get_patch(str(pw_series['patches'][0]['id']))

def init_logging(verbose):
    """
    Initialize the logger and default level is INFO or DEBUG if @verbose
    is True
    """

    global logger

    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    if verbose:
        logger.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s:%(levelname)-8s:%(message)s')
    ch.setFormatter(formatter)

    logger.addHandler(ch)

    logger.info("Logger is initialized: level=%s",
                 logging.getLevelName(logger.getEffectiveLevel()))

def init_config(config_file, verbose=False):
    """
    Read @config_file and initialize the values if necessary
    """

    global config

    config = configparser.ConfigParser()

    config_full_path = os.path.abspath(config_file)
    if not os.path.exists(config_full_path):
        raise FileNotFoundError

    logger.info("Loading config file: %s" % config_full_path)
    config.read(config_full_path)

    # Display current config settings
    if verbose == True:
        for section in config.sections():
            logger.debug("[%s]" % section)
            for (key, val) in config.items(section):
                logger.debug("   %s : %s" % (key, val))

def parse_args():

    parser = argparse.ArgumentParser(
        description="Check patch style in the pull request")
    parser.add_argument('-l', '--show-test-list', action='store_true',
                        help='Display supported CI tests')
    parser.add_argument('-p', '--pr-num', required=True, type=int,
                        help='Pull request number')
    parser.add_argument('-r', '--repo', required=True,
                        help='Github repo in :owner/:repo')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Display debugging info')
    parser.add_argument('-u', '--user', type=int, required=True)
    parser.add_argument('-t', '--state', required=True)
    parser.add_argument('-c', '--context', required=True)
    parser.add_argument('-d', '--description', required=True)


    return parser.parse_args()

def main():

    args = parse_args()

    init_logging(args.verbose)

    #init_config(args.config_file, args.verbose)

    init_github(args.repo, args.pr_num)

    logger.debug("Submitting the result to Patchwork")
    pw_output = patchwork_post_checks(args.user,
                                          pw_series_patch_1['checks'],
                                          patchwork_state(args.state),
                                          github_pr.html_url,
                                          args.context,
                                          args.description)
    logger.debug("Submit result\n%s" % pw_output)

if __name__ == "__main__":
    main()
