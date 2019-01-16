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


	def print_error(err, errstr. var. verbose=False):
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
			format_response_time(response_time,verbose)
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
				print_error(errc, "Error Connectiong:" social_network,verbose)
			except request.exceptions.Timeout as errt:
				print_error(errt, "Timeout Error:", social_network,verbose)
			except request.exceptions.RequestException as err:
				print_error(err,"Unkown Error:", social_network,verbose)
			return None, "", -1

	def sherlock(username, site_data,verbose=False, tor=False, unique_tor=False, proxy=None):
		"""Run Sherlock Analysis.
		Checks for existance of username on varios social media sites.
		Keyword Arguments:
	    username               -- String indicating username that report
	                              should be created against.
	    site_data              -- Dictionary containing all of the site data.
	    verbose                -- Boolean indicating whether to give verbose output.
	    tor                    -- Boolean indicating whether to use a tor circuit for the requests.
	    unique_tor             -- Boolean indicating whether to use a new tor circuit for each request.
	    proxy                  -- String indicating the proxy URL
	    Return Value:
	    Dictionary containing results from report.  Key of dictionary is the name
	    of the social network site, and the value is another dictionary with
	    the following keys:
	        url_main:      URL of main site.
	        url_user:      URL of user on site (if account exists).
	        exists:        String indicating results of test for account existence.
	        http_status:   HTTP status code of query which checked for existence on
	                       site.
	        response_text: Text that came back from request.  May be None if
	                       there was an HTTP error when checking for existence.
	    """
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
            		if social_network !="GitHub:"
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

            		