#!/usr/bin/env python3
# rapidTriageIP.py -v 1.0
# Author- David Sullivan
#
# Take a repository of rapidTriage reports and lookup public IP addresses against a list of known malicious IPs
#
# Revision  1.0     -   03/08/2021- Initial creation of script
#
# To do:
#   - Add command line options
#   - Add support for looking up TOR exit nodes
#

# import modules
import re, ipaddress, os, requests

# disable insecure request warning
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# temp set a directory and output location manually
directory = r'C:\temp'
outfile = r'C:\temp\rapidTriage_IP_output.txt'

# create regex that looks for ip addresses
ip_regex = re.compile("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")


# scrape folders for rapidTriage output
def scrapeFolders(directory):
    # initialize list of files
    file_list = []

    # scrape each filename for rapidTriage output
    for folder_name, subfolders, filenames in os.walk(directory):
        for filename in filenames:
            if "rapidTriage.txt".lower() in filename.lower():
                file_list.append(folder_name + '\\' + filename)

    # return filelist for analysis
    return file_list


# scrape documents
def scrapeReport(report):
    # open the report
    file = open(report, 'r')
    file_string = file.readlines()
    file.close()

    # initialize list for discovered ip addresses
    ip_list = []

    # search document for ips with established public connections
    for line in file_string:
        if 'ESTABLISHED' in line:
            ips = re.findall(ip_regex, line)
            if ips:
                for ip in ips:
                    if not ipaddress.ip_address(ip).is_private:
                        ip_list.append(ip)

    # remove duplicate ips in list
    ip_list = set([ip for ip in ip_list])

    # return the list of ips for further analysis
    return ip_list


# scan the ips in the report against blocklist.de
def blockScan(ips):
    # initialize list for bad ip addresses and timed out addresses
    block_list = []
    not_scanned = []

    # iterate through ips for malicious responses
    for ip in ips:
        # create the request
        print('Checking ' + ip)
        block_request = requests.request('GET', r'http://api.blocklist.de/api.php?ip=%s' % ip, verify=False).text

        # split the response to check the number of reports, if greater than 0, log it
        if len(block_request) < 50:  # if the response is more than 50 characters, the site timed out
            split_request = block_request.split(': ')
            result = int(split_request[2].split(r'<br />')[0])
            block_list.append(ip) if result > 0 else None
        else:
            not_scanned.append(ip)

    # return lists of ips
    return block_list, not_scanned


# scrape the report for established public IP connections
def analyzeReports(reports):
    # initialize list for discovered ip addresses
    ip_list = []

    # create a list of results from the reports and add to master ip_list
    for report in reports:
        ips = scrapeReport(report)
        for ip in ips:
            ip_list.append(ip)

    # remove duplicate ips in list
    ip_list = sorted(set([ip for ip in ip_list]))

    # check ips against blocklist.de for known malicious activity
    block_list, not_scanned = blockScan(ip_list)

    # write report
    outputReport(ip_list, block_list, not_scanned)


# print a report for the results that includes the test type, the number of reports and the metrics desired
def outputReport(ips, reported, skipped):
    # initialize formatted output
    output = []

    # print the discovered ips
    output.append("----------------------------------------------------")
    output.append("All Discovered IPs")
    output.append("----------------------------------------------------")
    for ip in ips:
        output.append(ip)
    output.append('\n\n')

    # print ips reported in blocklist.de
    output.append("----------------------------------------------------")
    output.append("IPs reported to blocklist.de")
    output.append("----------------------------------------------------")
    if len(reported) > 0:
        for ip in reported:
            output.append(ip)
    else:
        output.append("None")
    output.append('\n\n')

    # print ips not looked up
    if len(skipped) > 0:
        output.append("----------------------------------------------------")
        output.append("IPs not looked up on blocklist.de")
        output.append("----------------------------------------------------")
        for ip in skipped:
            output.append(ip)
        output.append('\n\n')

    # write output
    file = open(outfile, "w")
    for line in output:
        file.write(line + '\n')
    file.close()


# main function, only code that can't be limited to a module should run here
if __name__ == "__main__":
    # run the folder scraper and return list to main
    file_list = scrapeFolders(directory)

    # scrape and analyze the discovered reports
    analyzeReports(file_list)
