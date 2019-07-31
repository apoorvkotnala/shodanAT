
# Shodan Automation Tool - By Apoorv

class bcolors:				
    OKWHITE="\033[0;37m"	
    OKBLUE = '\033[94m'		
    OKGREEN = '\033[92m'	
    WARNING = '\033[93m'	
    FAIL = '\033[91m'	       
    ENDC = '\033[0m'	       	

import argparse
from netaddr import IPNetwork
import os
import re
import shodan
import sys

def cli_parser():

    # Command line argument parser
    parser = argparse.ArgumentParser(
        add_help=False,
        description="Shodan Automation Tool - Searching Shodan via API. \n By : Apoorv")
    parser.add_argument(
        "-search", metavar="Apache server", default=False,
        help="when searching Shodan for a string.")
    parser.add_argument(
        "-f", metavar="ips.txt", default=None,
        help="Using THe Ips List - File containing IPs to search shodan for.")
    parser.add_argument(
        "-ip", metavar='217.140.75.46', default=False,
        help="Shodan Host Search against IP & return results from Shodan about a specific IP.")
    parser.add_argument(
        "-iprg", metavar='217.140.75.46/24', default=False,
        help="Used to return results from Shodan about a specific CIDR to IP range .")
    parser.add_argument(

        "--hostnameonly", action='store_true',
        help="[Optional] Only provide results with a Shodan stored hostname.")
    parser.add_argument(
        "--page", metavar='1', default=1,
        help="Page number of results to return (default 1 (first page)).")
    parser.add_argument(
        '-H','-h', '-?', '--h', '-help', '--help', action="store_true",
        help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.h:
        parser.print_help()
        sys.exit()

    return args.search, args.ip, args.iprg, args.hostnameonly, args.page, args.f


def create_shodan_object():
    # Add your shodan API key here

    api_key = "IFiM3vVSvyQOSv8fcCtwgZuV9agdnbYj"

    shodan_object = shodan.Shodan(api_key)

    return shodan_object


def shodan_iprg_search(shodan_search_object, shodan_search_iprg, input_file_ips):

    title()

    if shodan_search_iprg is not False:

        if not validate_iprg(shodan_search_iprg):
            print "[*] ERROR: Please provide valid iprg notation!"
            sys.exit()

        else:

            print "[*] Searching Shodan for info about " + shodan_search_iprg

            # Create iprg notated list
            network = IPNetwork(shodan_search_iprg)

    elif input_file_ips is not False:
        try:
            with open(input_file_ips, 'r') as ips_provided:
                network = ips_provided.readlines()
        except IOError:
            print "[*] ERROR: You didn't provide a valid input file."
            print "[*] ERROR: Please re-run and provide a valid file."
            sys.exit()

    # search shodan for each IP
    for ip in network:

        print "\n[+] Searching specifically for: " + str(ip)

        try:
            # Search Shodan
            host = shodan_search_object.host(ip)

            # Print general info
	    print("""IP: {} 
Organization: {} 
Operating System: {}""".format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))
	    print("\n")
	    # Print all banners
	    for item in host['data']:
        	print("""Port: {} 
Banner: {}""".format(item['port'], item['data']))

        except Exception, e:
            if str(e).strip() == "API access denied":
                print "You provided an invalid API Key!"
                print "Please provide a valid API Key and re-run!"
                sys.exit()
            elif str(e).strip() == "No information available for that IP.":
                print "No information is available for " + str(ip)
            else:
                print "[*]Unknown Error: " + str(e)


def shodan_ip_search(shodan_search_object, shodan_search_ip):

    title()

    if validate_ip(shodan_search_ip):

        print "[*] Searching Shodan for info about " + shodan_search_ip + "..."

        try:
            # Search Shodan
            host = shodan_search_object.host(shodan_search_ip)

            # Print general info
	    print("""IP: {} 
Organization: {} 
Operating System: {}""".format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')))
	    print("\n")
	    # Print all banners
	    for item in host['data']:
        	print("""Port: {} 
Banner: {}""".format(item['port'], item['data']))

        except Exception, e:
                if str(e).strip() == "API access denied":
                    print "You provided an invalid API Key!"
                    print "Please provide a valid API Key and re-run!"
                    sys.exit()
                elif str(e).strip() == "No information available for that IP.":
                    print "No information on Shodan about " +\
                        str(shodan_search_ip)
                else:
                    print "[*]Unknown Error: " + str(e)

    else:
        print "[*]ERROR: You provided an invalid IP address!"
        print "[*]ERROR: Please re-run and provide a valid IP."
        sys.exit()


def shodan_string_search(shodan_search_object, shodan_search_string,
                         hostname_only, page_to_return):

    title()

    # Try/catch for searching the shodan api
    print "[*] Searching Shodan...\n"

    try:
        # Time to search Shodan
        results = shodan_search_object.search(
            shodan_search_string, page=page_to_return)

        if not hostname_only:
                # Show the results
        	print('Results found: {}'.format(results['total']) + '\n')
        	for result in results['matches']:
                	print('IP: {}'.format(result['ip_str']))
               		print('Data: {}'.format(result['data']))
               		print('')

        else:
	    for result in results['matches']:
                print('IP: {}'.format(result['ip_str']))
                print('   Hostname: {}'.format(result['hostnames']))

    except Exception, e:
        if str(e).strip() == "API access denied":
            print "You provided an invalid API Key!"
            print "Please provide a valid API Key and re-run!"
            sys.exit()


def title():
    os.system('clear')
    print "+------------------------------------------------------------+"
    print "|                 - Shodan Automation Tool -                 |"
    print "+------------------------------------------------------------+"

    return


def validate_iprg(val_iprg):
    # This came from (Mult-line link for pep8 compliance)
    # http://python-iptools.googlecode.com/svn-history/r4
    # /trunk/iptools/__init__.py
    iprg_re = re.compile(r'^(\d{1,3}\.){0,3}\d{1,3}/\d{1,2}$')
    if iprg_re.match(val_iprg):
        ip, mask = val_iprg.split('/')
        if validate_ip(ip):
            if int(mask) > 32:
                return False
        else:
            return False
        return True
    return False


def validate_ip(val_ip):
    # This came from (Mult-line link for pep8 compliance)
    # http://python-iptools.googlecode.com/svn-history/r4
    # /trunk/iptools/__init__.py
    ip_re = re.compile(r'^(\d{1,3}\.){0,3}\d{1,3}$')
    if ip_re.match(val_ip):
        quads = (int(q) for q in val_ip.split('.'))
        for q in quads:
            if q > 255:
                return False
        return True
    return False


if __name__ == '__main__':

    # Parse command line options
    search_string, search_ip, search_iprg, search_hostnameonly,\
        search_page_number, search_file = cli_parser()

    # Create object used to search Shodan
    shodan_api_object = create_shodan_object()

    # Determine which action will be performed
    if search_string is not False:
        shodan_string_search(shodan_api_object, search_string,
                             search_hostnameonly, search_page_number)

    elif search_ip is not False:
        shodan_ip_search(shodan_api_object, search_ip)

    elif search_iprg is not False or search_file is not None:
        shodan_iprg_search(shodan_api_object, search_iprg, search_file)

    else:
     print(bcolors.WARNING + "Shodan Automation Tool" + bcolors.ENDC)
     print(bcolors.OKWHITE + "By : Apoorv\n" + bcolors.ENDC)
     print(bcolors.OKGREEN + "Usage: ./ShodanAT.py  [Options]\n" + bcolors.ENDC)
     print(bcolors.OKWHITE + "Ex: ./ShodanAT.py -h		  to display options & usage" + bcolors.ENDC)
     print(bcolors.OKWHITE + "Ex: ./ShodanAT.py --help 	  to display full options " + bcolors.ENDC)
     print(bcolors.OKWHITE + "Ex: ./ShodanAT.py -search Apache server 	 " + bcolors.ENDC)
     print(bcolors.OKWHITE + "Ex: ./ShodanAT.py -f 		  list of sites directory list ips.txt " + bcolors.ENDC)
     print(bcolors.OKWHITE + "Ex: ./ShodanAT.py --hostnameonly [Optional] Only provide results with a Shodan stored hostname. " + bcolors.ENDC)
     print(bcolors.OKWHITE + "Ex: ./ShodanAT.py --help         disply the full command's\n  " + bcolors.ENDC)
     print(bcolors.OKGREEN + "Options:         \n  " + bcolors.ENDC)
     print(bcolors.OKGREEN + "	  -f ips.txt" + bcolors.ENDC)
     print(bcolors.OKWHITE + "	   Shodan search with ips.txt list  " + bcolors.ENDC)
     print(bcolors.OKGREEN + "	  -search Apache server" + bcolors.ENDC)
     print(bcolors.OKWHITE + "	   Use this when searching Shodan for a string. " + bcolors.ENDC)
     print(bcolors.OKGREEN + "	  -ip x.x.x.x" + bcolors.ENDC)
     print(bcolors.OKWHITE + "	   Used to return results from Shodan about a specific IP. " + bcolors.ENDC)
     print(bcolors.OKGREEN + "	  -h " + bcolors.ENDC)
     print(bcolors.OKWHITE + "	   Help Menu " + bcolors.ENDC)
     print(bcolors.OKGREEN + "	  --help " + bcolors.ENDC)
     print(bcolors.OKWHITE + "	   See full Help Options \n" + bcolors.ENDC)

#END
