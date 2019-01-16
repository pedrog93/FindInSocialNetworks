"""
Sherlock: Find Usernames Across Social Networks Module
This module contains the main logic to search for usernames at social
networks.
"""

import csv
import json
import os
import sys
import platform
import re
from time import time

import requests
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
from requests_futures.sessions import FuturesSession
from torrequest import TorRequest


module_name = "Sherlock: Find Usernames Accross Social Networks"
__version__ = "0.2.6"
amount = 0

# TOFO: fix tumblr



class ElapsedFuturesSession(FuturesSession):
	"""
	Extends FutureSession to add a response time metric to each request.

	This is taken (almost) directly from here: https://github.com/ross/requests-futures#working-in-the-background
	"""
	def request(self,method,url,hooks={},*args,**kwargs):
		start = time()

		def timing(r, *args,**kwargs):
			elapsed_sec = time()-start
			r.elapsed= round(elapsed_sec*1000)

		try:
			if isinstance(hooks['response'],(list,tuple)):
				#needs to be first so we dont time other hooks execution
				hooks['response'].instert(0,timing)
			else:
				hooks['response']=[timing.hooks['response']]
		except KeyError:
			hooks['response']=timing

		return super(ElapsedFuturesSession,self).request(method, url, hooks=hooks,*args, **kwargs)


	def open_file(fname):
		return open(fname,"a")

	def write_to_file(url,f):
		f.write(url +"\n")

	def final_score(amount, f):
		f.write("Total: "+str(amount) + "\n")


	def print_error(err, errstr, var, verbose=False):
		print(Style.BRIGHT + Fore.WHITE + "[" +
			Fore.RED + "-" +
			Fore.WHITE + "]"+
			Fore.RED + f"{errstr}" +
			Fore.YELLOW + f" {err if verbose else var}")

	def format_response_time(response_time, verbose):
		return "[{}ms]".format(response_time) if verbose else ""

	def print_found(social_network, url, response_time, verbose=False):
		print((Style.BRIGHT + Fore.WHITE+ "["+
			Fore.GREEN + "+"+
			Fore.WHITE + "]"+
			format_response_time(response_time,verbose) +
			Fore.GREEN + "{}:").format(social_network),url)

	def print_not_found(social_network,response_time,verbose=False):
		print((Style.BRIGHT + Fore.WHITE+ "["+
			Fore.RED + "-" +
			Fore.WHITE + "]"+
			format_response_time(response_time, verbose) +
			Fore.GREEN + "{}:" + 
			Fore.YELLOW +"Not Found!").format(social_network))

	
	def get_response(request_future, error_type,social_network,verbose=False):
		try:
			rsp=request_future.result()
			if rsp.status_code:
				return rsp, error_type, rsp.elapsed
		except requests.exceptions.HTTPError as errh:
			print_error(errh, "HTTP Error:", social_network,verbose)
		except requests.exceptions.ConnectionError as errc:
			print_error(errc, "Error Connection:", social_network,verbose)
		except request.exceptions.Timeout as errt:
			print_error(errt, "Timeout Error:", social_network,verbose)
		except request.exceptions.RequestException as err:
			print_error(err,"Unkown Error:", social_network,verbose)
		return None, "", -1

	def sherlock(username, site_data,verbose=False, tor=False, unique_tor=False, proxy=None):
		global amount
		fname= username.lower() + ".txt"

		if os.path.isfile(fname):
			os.remove(fname)
			print((Style.BRIGHT+ Fore.GREEN + "[" + 
	    		   Fore.YELLOW + "*" +
	    		   Fore.GREEN + "] Removing previous file:" +
	    		   Fore.WHITE + " {}").format(fname))
		print((Style.BRIGHT + Fore.GREEN + "[" +
			Fore.YELLOW + "*" +
		    Fore.GREEN + "] Checking username" +
		    Fore.WHITE + " {}" +
			Fore.GREEN + " on:").format(username))
		headers = {
				'User-Agent': 'Mozilla/5.0(Macintosh; Intel Mac Os X 10.12; rv:55.0) Gecko/20100101 Firefox/55.0'
		}	

		executor = ThreadPoolExecutor(max_workers=len(site_data))

		underlying_session = requests.session()
		underlying_request = requests.Request()
		if tor or unique_tor:
			underlying_request = TorRequest()
			underlying_session = underlying_request.session

		session = ElapsedFuturesSession(
			executor=executor, session=underlying_session)
			
		results_total = {}

		for social_network, net_info in site_data.items():
			results_site = {}
			results_site['url_main']= net_info.get("urlMain")

			regex_check = net_info.get("regexCheck")
			if regex_check and re.search(regex_check,username) is None:
				print((Style.BRIGHT + Fore.WHITE + "[" +
                 	   Fore.RED + "-" +
                  	   Fore.WHITE + "]" +
                	   Fore.GREEN + " {}:" +
                	   Fore.YELLOW + " Illegal Username Format For This Site!").format(social_network))
				results_site["exists"] = "illegal"
			else:
				url= net_info["url"].format(username)
				results_site["url_user"]=url
				request_method = session.get      		
           		
           		if social_network !="GitHub":
           			if net_info["errorType"]=='status_code':
           				request_method= session.head

                if proxy != None:
           			proxies = {"http": proxy, "https":proxy}
           			future = request_method(
           				url=url, headers=headers, proxies=proxies)
           		else:
           			future=request_method(url=url, headers=headers)

           		net_info["request_future"] = future

           		if unique_tor:
           			underlying_request.reset_identity()

           	results_total[social_network] = results_site

           f= open_file(fname)
           for social_network,net_info in site_data.items():

           	results_site = results_total.get(social_network)

           	url = results_site.get("url_user")
           	exists = results_site.get("exists")
           	if exists is not None:
           		continue

           	error_type = net_info["errorType"]

           	http_status= "?"
           	response_text = ""

           	future = net_info["request_future"]
           	r,error_type,response_time= get_response(request_future=future,
           											 error_type=error_type,
           											 social_network=social_network,
           											 verbose=verbose)
           	try:
           		http_status=r,status_code
           	except:
           		pass
           	try:
           		response_text= r.text.encode(r.encoding)
           	except:
           		pass
            	
           	if  error_type == "message":
           		error = net_info.get("errorMsg")
           		if not error in r.text:
           			print_found(social_network,url,response_time,verbose)
           			write_to_file(url, f)
           			exists= "yes"
           			amount=amount+1
           		else:
           			print_not_found(social_network,response_time,verbose)
           			exists="no"
           	elif error_type=="status_code":
           		if not r.status_code>= 300 or r,status_code<200:
           			print_found(social_network,URL,response_time,verbose)
           			write_to_file(url,f)
           			exists="yes"
           			amount=amount+1
           		else:
           			print_not_found(social_network,response_time,verbose)
           			exists="no"

           	elif error_type == "response_url":
           		error=net_info.get("errorUrl")
           		if not error in r.url:
           			print_found(social_network,url,response_time,verbose)
           			write_to_file(url,f)
           			exists="yes"
           			amount=amount+1
           		else:
           			print_not_found(social_network,response_time,verbose)
           			exists="no"
           	
           	elif error_type==""
           		print((Style.BRIGHT + Fore,WHITE + "[" +
           				Fore.RED + "-" +
           				Fore.WHITE + "]" +
           				Fore.GREEN + "{}:" + 
           				Fore.YELLOW + "Error!").format(social_network))
           		exists="error"

           		results_site['exists']=exists

           		results_site['http_status']=http_status
           		results_site['response_text']=response_text
           		results_site['response_time_ms']=response_time

           		results_total['social_network']= results_site
           print((Style.BRIGHT + Fore.GREEN + "[" +
           		Fore.YELLOW + "*" +
           		Fore.GREEN + "] Saved: " +
           		Fore.WHITE + "{}").format(fname))

           final_score(amount,f)
           return results_total

    def main():

       	init(autoreset=True)

      	version_string = f"%(prog)s {__version__}\n" + \
       					 f"{requests.__description__}:{requests.__version__}\n"+ \
       					 f"Python: {platform.python_version()}"
       	parser = ArgumentParser(formatter_class=RawDescriptionHelpFormatter,
       						description= f"{module_name} (Version{__version__})"
       						)
       	parser.add_argument("--version",
        					action="version", version=version_string,
        					help="Display version information and dependencies."
        					)
        parser.add_argument("--verbose","-v", "-d", "-d-debug",
        					action="store_true", dest="verbose", default=False,
        					help="Display extra debugging information (Default Option)"
        					)
        parser.add_argument("--quiet", "-q",
        					action="store_false", dest="verbose", default=False
        					help="Disable debugging information(Default Option)."
        					)
     	parser.add_argument("--tor", "-t",
           		            action="store_true", dest="tor", default=False,
                   		    help="Make requests over TOR; increases runtime; requires TOR to be installed and in system path.")
		parser.add_argument("--unique-tor", "-u",
		                    action="store_true", dest="unique_tor", default=False,
		                    help="Make requests over TOR with new TOR circuit after each request; increases runtime; requires TOR to be installed and in system path.")
		parser.add_argument("--csv",
		                    action="store_true",  dest="csv", default=False,
		                    help="Create Comma-Separated Values (CSV) File."
		                    )
		parser.add_argument("--site",
		                    action="append", metavar='SITE_NAME',
		                    dest="site_list", default=None,
		                    help="Limit analysis to just the listed sites.  Add multiple options to specify more than one site."
		                    )
		parser.add_argument("--proxy", "-p", metavar='PROXY_URL',
			                action="store", dest="proxy", default=None,
		                    help="Make requests over a proxy. e.g. socks5://127.0.0.1:1080"
		                    )
		parser.add_argument("username",
		                    nargs='+', metavar='USERNAMES',
		                    action="store",
		                    help="One or more usernames to check with social networks."
		                    )     
		args= parser.parse_args()

		     # TODO regex check on args.proxy
		if args.tor and args.proxy != None:
		    raise Exception("TOR and Proxy cannot be set in the meantime.")

		    # Make prompts
		if args.proxy != None:
		    print("Using the proxy: " + args.proxy)
		if args.tor or args.unique_tor:
		    print("Using TOR to make requests")
		    print("Warning: some websites might refuse connecting over TOR, so note that using this option might increase connection errors.")

		    # Load the data
		data_file_path = os.path.join(os.path.dirname(
		        os.path.realpath(__file__)), "data.json")
		    with open(data_file_path, "r", encoding="utf-8") as raw:
		        site_data_all = json.load(raw)

		    if args.site_list is None:
		        # Not desired to look at a sub-set of sites
		        site_data = site_data_all
		    else:
		        # User desires to selectively run queries on a sub-set of the site list.

		        # Make sure that the sites are supported & build up pruned site database.
		        site_data = {}
		        site_missing = []
		        for site in args.site_list:
		            for existing_site in site_data_all:
		                if site.lower() == existing_site.lower():
		                    site_data[existing_site] = site_data_all[existing_site]
		            if not site_data:
		                # Build up list of sites not supported for future error message.
		                site_missing.append(f"'{site}'")

		        if site_missing:
		            print(
		                f"Error: Desired sites not found: {', '.join(site_missing)}.")
		            sys.exit(1)

		    # Run report on all specified users.
		    for username in args.username:
		        print()
		        results = {}
		        results = sherlock(username, site_data, verbose=args.verbose,
		                           tor=args.tor, unique_tor=args.unique_tor, proxy=args.proxy)

		        if args.csv == True:
		            with open(username + ".csv", "w", newline='', encoding="utf-8") as csv_report:
		                writer = csv.writer(csv_report)
		                writer.writerow(['username',
		                                 'name',
		                                 'url_main',
		                                 'url_user',
		                                 'exists',
		                                 'http_status',
		                                 'response_time_ms'
		                                 ]
		                                )
		                for site in results:
		                    writer.writerow([username,
		                                     site,
		                                     results[site]['url_main'],
		                                     results[site]['url_user'],
		                                     results[site]['exists'],
		                                     results[site]['http_status'],
		                                     results[site]['response_time_ms']
		                                     ]
		                                    )


		if __name__ == "__main__":
		    main()
