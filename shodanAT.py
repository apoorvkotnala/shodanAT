
# Shodan Automation Tool - By Apoorv	       	

import argparse
import netaddr
from netaddr import IPNetwork
import re
import shodan
import sys
import xlwt
from xlwt import Workbook
import datetime
from datetime import date

# Workbook is created 
wb = Workbook() 
# add_sheet is used to create sheet. 
sheet = wb.add_sheet('Sheet 1', cell_overwrite_ok=True) 
sheet.write(0, 0, 'External IP')
sheet.write(0, 1, 'DD-MM-YYYY')
sheet.write(0, 2, "Owner's Identity")
sheet.write(0, 3, 'Shodan Output')
sheet.write(0, 4, 'NMAP Output')

# CLI Parser for Terminal
def cli_parser():

    # Command line argument parser
    parser = argparse.ArgumentParser(add_help=False, description="Shodan Automation Tool - Searching Shodan via API. \n By : Apoorv")
    parser.add_argument("-search", metavar="Apache server", default=False, help="When searching Shodan for a string.")
    parser.add_argument("-f", metavar="ips.txt", default=None, help="Using The ips List - File containing IPs to search shodan for.")
    parser.add_argument("-ip", metavar='xx.xx.xx.xx', default=False, help="Shodan Host Search Shodan DB for the given IP.")
    parser.add_argument("--hostnameonly", action='store_true', help="[Optional] Only provide results with a Shodan stored hostname.")
    parser.add_argument("--savexl", action='store_true', help="[Optional] Saves the fetched data in a Excel File.")
    parser.add_argument('-H','-h', '-?', '--h', '-help', '--help', action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.h:
        parser.print_help()
        sys.exit()

    return args.search, args.ip, args.hostnameonly, args.f, args.savexl


# Create a Shodan Object Using API Key
def create_shodan_object():
    # Add your shodan API key here

    api_key = "IFiM3vVSvyQOSv8fcCtwgZuV9agdnbYj"

    shodan_object = shodan.Shodan(api_key)

    return shodan_object


# Shodan Search a Single IP Address
def shodan_ip_search(shodan_search_object, shodan_search_ip, savexl):

    title()

    if shodan_search_ip is not False:

        if not validate_ip(shodan_search_ip):
            print("[*] ERROR: Please provide valid ip notation!")
            sys.exit()

        else:

            print(bcolors.OKGREEN + "\n[+] Searching specifically for: " + str(shodan_search_ip) + bcolors.ENDC)

            if savexl:
                sheet.write(1, 0, shodan_search_ip)
                sheet.write(1, 1, date.today().strftime("%d/%m/%Y"))

            try:
                # Search Shodan
                host = shodan_search_object.host(shodan_search_ip)
                # Print general info
                print_data = "IP: {}\nOrganization: {}\nOperating System: {}".format(host['ip_str'], host.get('org', 'n/a'), host.get('os', 'n/a')) + "\n\n"
                if savexl:
            	    sheet.write(1, 2, "{}".format(host.get('org', 'n/a')))

                # Print all banners
                for item in host['data']:
                    print_data = print_data + "Port: {}\nBanner: {}".format(item['port'], item['data'])

                print(print_data)
                if savexl:
                    sheet.write(1, 3, print_data)

            except Exception as e:
                if str(e).strip() == "API access denied":
                    print("You provided an invalid API Key!")
                    print("Please provide a valid API Key and re-run!")
                    sys.exit()
                elif str(e).strip() == "No information available for that IP.":
                    print("No information is available for " + str(ip))
                else:
                    print("[*]Unknown Error: " + str(e))


# Shodan Search A File Containing IP Addresses
def shodan_ip_search_file(shodan_search_object, input_file_ips, savexl):

    title()

    if input_file_ips is not False:
        try:
            with open(input_file_ips, 'r') as ips_provided:
                network = ips_provided.readlines()
        except IOError:
            print("[*] ERROR: You didn't provide a valid input file.")
            print("[*] ERROR: Please re-run and provide a valid file.")
            sys.exit()

    # search shodan for each IP
    i=1
    for ip in network:
        print(bcolors.OKGREEN + "\n[+] Searching specifically for: " + str(ip) + bcolors.ENDC)
        if savexl:
            sheet.write(i, 0, ip)
            sheet.write(i, 1, date.today().strftime("%d/%m/%Y"))

        try:
            # Search Shodan
            host = shodan_search_object.host(ip)

            # Print general info
            print_data = ""
            print_data = "IP: {}\nOrganization: {}\nOperating System: {}".format(host['ip_str'], host.get('org','n/a'), host.get('os','n/a')) + "\n\n"
            if savexl:
            	sheet.write(i, 2, "{}".format(host.get('org', 'n/a')))
	    # Print all banners
            for item in host['data']:
                print_data = print_data + "Port: {}\nBanner: {}".format(item['port'], item['data'])

            print(print_data)
            if savexl:
                sheet.write(i, 3, print_data)

        except Exception as e:
            if str(e).strip() == "API access denied":
                print("You provided an invalid API Key!")
                print("Please provide a valid API Key and re-run!")
                sys.exit()
            elif str(e).strip() == "No information available for that IP.":
                print("No information is available for " + str(ip))
            else:
                print("[*]Unknown Error: " + str(e))
        i = i + 1     #increment the number for another ip entry


# String Search in Shodan Data Base
def shodan_string_search(shodan_search_object, shodan_search_string, hostname_only):

    title()

    # Try/catch for searching the shodan api
    print("[*] Searching Shodan...\n")

    try:
        # Time to search Shodan
        results = shodan_search_object.search(shodan_search_string, 1)

        if not hostname_only:
                # Show the results
                print('Results found: {}'.format(results['total']) + '\n')
                print('\nReturning Page 1 Results:\n')
                for result in results['matches']:
                    print('IP: {}'.format(result['ip_str']))
               	    print('Data: {}'.format(result['data']))

        else:
            print('\nReturning Page 1 Results :\n')
            for result in results['matches']:
                print('IP: {}'.format(result['ip_str']))
                print('   Hostname: {}'.format(result['hostnames']))

    except Exception as e:
        if str(e).strip() == "API access denied":
            print("You provided an invalid API Key!")
            print("Please provide a valid API Key and re-run!")
            sys.exit()


# Title Block
def title():
    print(bcolors.WARNING + "+------------------------------------------------------------------+" + bcolors.ENDC)
    print(bcolors.WARNING + "|                    - Shodan Automation Tool -                    |" + bcolors.ENDC)
    print(bcolors.WARNING + "+------------------------------------------------------------------+" + bcolors.ENDC)
    return


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


# Color Coding for CLI Terminal 
class bcolors:				
    OKWHITE="\033[0;37m"	
    OKBLUE = '\033[94m'		
    OKGREEN = '\033[92m'	
    WARNING = '\033[93m'	
    FAIL = '\033[91m'	       
    ENDC = '\033[0m'


# Main Function
if __name__ == '__main__':

    # Parse command line options
    search_string, search_ip, search_hostnameonly, search_file, savexl = cli_parser()

    # Create object used to search Shodan
    shodan_api_object = create_shodan_object()

    # Determine which action will be performed
    if search_string is not False:
        shodan_string_search(shodan_api_object, search_string, search_hostnameonly)

    elif search_ip is not False:
        shodan_ip_search(shodan_api_object, search_ip, savexl)
        if savexl:
            wb.save('REPORT.xls')

    elif search_file is not None:
        shodan_ip_search_file(shodan_api_object, search_file, savexl)
        if savexl:
            wb.save('REPORT.xls')

    else:
     print(bcolors.WARNING + "Shodan Automation Tool" + bcolors.ENDC)
     print(bcolors.OKWHITE + "By : Apoorv\n" + bcolors.ENDC)
     print(bcolors.OKGREEN + "Usage: ./ShodanAT.py  [Options]\n" + bcolors.ENDC)
     print(bcolors.OKWHITE + "Ex: ./ShodanAT.py -h" + bcolors.ENDC)
     print(bcolors.OKWHITE + "Ex: ./ShodanAT.py --help" + bcolors.ENDC)
     print(bcolors.OKWHITE + "Ex: ./ShodanAT.py -search apache server --hostnameonly[optional]" + bcolors.ENDC)
     print(bcolors.OKWHITE + "Ex: ./ShodanAT.py -f --savexl[optional] ips.txt " + bcolors.ENDC)
     print(bcolors.OKWHITE + "Ex: ./ShodanAT.py -ip \n  " + bcolors.ENDC)
     print(bcolors.OKGREEN + "Options:         \n  " + bcolors.ENDC)
     print(bcolors.OKGREEN + "	  -f ips.txt" + bcolors.ENDC)
     print(bcolors.OKWHITE + "	   Shodan search with ips.txt list  " + bcolors.ENDC)
     print(bcolors.OKGREEN + "	  -search apache server" + bcolors.ENDC)
     print(bcolors.OKWHITE + "	   Use this when searching Shodan for a string. " + bcolors.ENDC)
     print(bcolors.OKGREEN + "	  -ip x.x.x.x" + bcolors.ENDC)
     print(bcolors.OKWHITE + "	   Used to return results from Shodan about a specific IP. " + bcolors.ENDC)
     print(bcolors.OKGREEN + "	  -h " + bcolors.ENDC)
     print(bcolors.OKWHITE + "	   Help Menu " + bcolors.ENDC)
     print(bcolors.OKGREEN + "	  --help " + bcolors.ENDC)
     print(bcolors.OKWHITE + "	   See full Help Options \n" + bcolors.ENDC)
 
# END
