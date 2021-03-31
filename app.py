import requests
import sys
import time
import urllib.request, urllib.parse, urllib.error
from bs4 import BeautifulSoup
import re
import json
import traceback
from datetime import datetime
from lists import lists
import settings
import random
import lxml

class Evaluator:
    # initiate the class
    def __init__(self, target):
        self.target = target
        self.headers = settings.headers

    def delay():
        time.sleep(settings.delay_internal)

    # get data against McAfee Trusted Source
    def eval_1(self):
        self.delay()
        try:
            if self.target[1] == 'URL':
                # because it accept URL and domain, it doesn't matter whichone is passed to it
                target = self.target[0][0] if self.target[0][0] else self.target[0][1]
                print('\t[-] Checking against McAfee Trusted Source')
                api_url_1 = 'http://www.trustedsource.org/sources/index.pl'
                api_url_2 = 'https://www.trustedsource.org/en/feedback/url'
                session = requests.Session()
                session.headers.update(self.headers)
                r = session.get(api_url_1)
                soup = BeautifulSoup(r.text, 'html.parser')
                form = soup.find('form', {'class': 'contactForm'})
                e = form.find('input', {'name': 'e'}).get('value')
                c = form.find('input', {'name': 'c'}).get('value')

                self.headers['Referer'] = api_url_1
                payload = {'sid': (None, ''), 'e': (None, e), 'c': (None, c), 'p': (None, ''), 'action': (None, 'checksingle'),
                            'product': (None, '13-ts-3'), 'url': (None, target[0])}
                response = session.post(api_url_2, headers=self.headers, files=payload)
                soup = BeautifulSoup(response.content, 'html.parser')
                form = soup.find('form', {'class': 'contactForm'})
                results_table = soup.find('table', {'class': 'result-table'})
                td = results_table.find_all('td')
                return {'category':td[len(td) - 2].text[2:], 'risk':td[len(td) - 1].text}
            else:
                return {'category':'', 'risk':''}
        except Exception as error:
            print('\t\t[!] Error:  {0}'.format(error))
            return {'category':'ERROR', 'risk':'ERROR'}


    # get data against Scam Advisor
    def eval_2(self):
        self.delay()
        try:
            if self.target[1] == 'URL':
                print('\t[-] Checking against Scam Advisor')
                api_url = 'https://www.scamadviser.com/check-website/'
                session = requests.Session()
                response = session.get(api_url+self.target[0][1], headers=self.headers)
                soup = BeautifulSoup(response.content, 'html.parser')
                risk = soup.find('div', {'class': 'icon'})
                return {'category':'', 'risk':risk.contents[0].replace('\n', '')}
            else:
                return {'category':'', 'risk':''}
        except Exception as error:
            print('\t\t[!] Error:  {0}'.format(error))
            return {'category':'ERROR', 'risk':'ERROR'}


    # get data against Norton Safe Web
    def eval_3(self):
        self.delay()
        try:
            if self.target[1] == 'URL':
                print('\t[-] Checking against Norton Safe Web')
                api_url = 'https://safeweb.norton.com/report/show?url='
                session = requests.Session()
                response = session.get(api_url+self.target[0][1], headers=self.headers)
                soup = BeautifulSoup(response.content, 'html.parser')
                risk = soup.find('div', {'class': 'tAlignCr'}).find('b')
                community_risk = soup.find('div', {'class': 'community-text'}).find('label')
                return {'category':'', 'risk':risk.text, 'community_risk':community_risk.text}
            else:
                return {'category':'', 'risk':'', 'community_risk':''}
        except Exception as error:
            print('\t\t[!] Error:  {0}'.format(error))
            return {'category':'ERROR', 'risk':'ERROR', 'community_risk':'ERROR'}


    # get data against FortiGuard Web Filter
    def eval_4(self):
        self.delay()
        try:
            if self.target[1] == 'URL':
                print('\t[-] Checking against FortiGuard Web Filter')
                api_url = 'https://fortiguard.com/webfilter?q='
                self.headers['Origin'] = 'https://fortiguard.com'
                self.headers['Referer'] = 'https://fortiguard.com/webfilter'
                request = urllib.request.Request(api_url+self.target[0][1], headers=self.headers)
                response = urllib.request.urlopen(request).read().decode('utf-8')
                category = re.findall('Category: (.*?)" />', response, re.DOTALL)[0]
                return {'category':category, 'risk':''}
            else:
                return {'category':'', 'risk':''}
        except Exception as error:
            print('\t\t[!] Error:  {0}'.format(error))
            return {'category':'ERROR', 'risk':'ERROR'}


    # get data against Open DNS
    def eval_5(self):
        self.delay()
        try:
            if self.target[1] == 'URL':
                print('\t[-] Checking against Open DNS')
                api_url = 'https://domain.opendns.com/'
                request = urllib.request.Request(api_url+self.target[0][1], headers=self.headers)
                response = urllib.request.urlopen(request).read().decode('utf-8')
                category = re.findall('<span class="normal">((.|\n)*?)<\/span>', response, re.DOTALL)[0][0]
                category = 'NA' if ('Not yet decided' in category) else category
                return {'category':category.replace('\n','').replace('  ',''), 'risk':''}
            else:
                return {'category':'', 'risk':''}
        except Exception as error:
            print('\t\t[!] Error:  {0}'.format(error))
            return {'category':'ERROR', 'risk':'ERROR'}


    # get data against Cybercrime Tracker
    def eval_6(self):
        self.delay()
        try:
            target = self.target[0][1] if (self.target[1] == 'URL') else self.target[0]
            print('\t[-] Checking against Cybercrime Tracker')
            api_url = 'http://cybercrime-tracker.net/index.php?search='
            session = requests.Session()
            response = session.get(api_url+target, headers=self.headers)
            soup = BeautifulSoup(response.content, 'html.parser')
            if not soup.find('font', {'color': 'red'}):
                risks = soup.find('tbody').find_all('tr')
                categories = []
                for risk in risks:
                    category = risk.find_all('td')
                    categories.append(category[3].contents[0]) 
                return {'category':categories, 'risk':''}
            else:
                return {'category':'', 'risk':''}
        except Exception as error:
            print('\t\t[!] Error:  {0}'.format(error))
            return {'category':'ERROR', 'risk':'ERROR'}


    # get data against Threat Score
    def eval_7(self):
        self.delay()
        target = self.target[0][1] if (self.target[1] == 'URL') else self.target[0]
        print('\t[-] Checking against Threat Score')
        api_url = 'https://threatscore.cyberprotect.cloud/api/score/'
        try:
            session = requests.Session()
            response = session.get(api_url+target, headers=self.headers)
            result = response.json()
            categories = []
            if 'score' in result.keys():
                for analysis in result['score']['analysis']:
                    if 'taxonomy' in analysis.keys():
                        categories.append(analysis['taxonomy']['value'])
                return {'category':categories, 'risk':result['score']['value']}
            else:
                return {'category':'', 'risk':''}
        except Exception as error:
            print('\t\t[!] Error:  {0}'.format(error))
            return {'category':'ERROR', 'risk':'ERROR'}


    # get data against SANS Internet Storm Center
    def eval_8(self):
        self.delay()
        if (self.target[1] == 'IPv4'):
            print('\t[-] Checking against SANS Internet Storm Center')
            api_url = 'https://isc.sans.edu/api/ip/'
            try:
                session = requests.Session()
                response = session.get(api_url+self.target[0]+'?json', headers=self.headers)
                result = response.json()
                categories = []
                if 'ip' in result.keys():
                    result = 0 if (result['ip']['count'] == None) else result['ip']['count']
                    return {'category':'', 'risk':result}
                else:
                    return {'category':'', 'risk':''}
            except Exception as error:
                print('\t\t[!] Error:  {0}'.format(error))
                return {'category':'ERROR', 'risk':'ERROR'}
        else:
            return {'category':'', 'risk':''}


    # get data against Threat Crowd
    # https://github.com/AlienVault-OTX/ApiV2
    def eval_9(self):
        self.delay()
        if (self.target[1] == 'URL'):
            target = self.target[0][1]
            api_portion = 'domain/report/'
        else:
            target = self.target[0]
            api_portion = 'ip/report/'
        print('\t[-] Checking against Threat Crowd')
        api_url = 'https://www.threatcrowd.org/searchApi/v2/'
        try:
            session = requests.Session()
            response = session.get(api_url+api_portion, headers=self.headers, params={'domain': target, 'ip': target})
            result = response.json()
            if 'votes' in result.keys():
                # -1 malicious, 0 unknown, 1 not malicious
                return {'category':'', 'risk':result['votes']}
            else:
                return {'category':'', 'risk':''}
        except Exception as error:
            print('\t\t[!] Error:  {0}'.format(error))
            print(traceback.format_exc())
            return {'category':'ERROR', 'risk':'ERROR'}


    # get data against Joe Sandbox Cloud
    def eval_10(self):
        self.delay()
        target = self.target[0][0] if (self.target[1] == 'URL') else self.target[0]
        print('\t[-] Checking against Joe Sandbox Cloud')
        api_url = 'https://www.joesandbox.com/search?q='
        try:
            session = requests.Session()
            response = session.get(api_url+target, headers=self.headers)
            soup = BeautifulSoup(response.content, 'html.parser')
            if soup.find('div', {'class': 'slider-wrapper'}):
                risk = soup.find('div', {'class': 'slider-wrapper'}).find('img', alt=True)['alt']
                category = soup.find('div', {'class': 'threat-label'}).contents[0]
                return {'category':category, 'risk':risk}
            else:
                return {'category':'', 'risk':''}
        except Exception as error:
            print('\t\t[!] Error:  {0}'.format(error))
            print(traceback.format_exc())
            return {'category':'ERROR', 'risk':'ERROR'}


    # get data against Stop Forum Spam
    def eval_11(self):
        self.delay()
        if (self.target[1] == 'IPv4'):
            print('\t[-] Checking against Stop Forum Spam')
            api_url = 'http://api.stopforumspam.org/api?ip='
            try:
                session = requests.Session()
                response = session.get(api_url+self.target[0]+'&json', headers=self.headers)
                return {'category':'', 'risk':json.loads(response.text)['ip']['appears']}
            except Exception as error:
                print('\t\t[!] Error:  {0}'.format(error))
                return {'category':'ERROR', 'risk':'ERROR'}
        else:
            return {'category':'', 'risk':''}


    # get data against Nerd
    def eval_12(self):
        self.delay()
        if (self.target[1] == 'IPv4'):
            print('\t[-] Checking against Nerd')
            api_url = 'https://nerd.cesnet.cz/nerd/ip/'
            try:
                session = requests.Session()
                response = session.get(api_url+self.target[0], headers=self.headers)
                soup = BeautifulSoup(response.content, 'html.parser')
                if soup.find('div', {'class': 'tags'}):
                    categories = []
                    tags = soup.find('div', {'class': 'tags'}).find_all('span', {'class': 'tag'})
                    for tag in tags:
                        categories = tag.contents[0].replace('\r', '').replace('\n', '').replace(' ', '')
                    # the worst is 1.0 and the best is 0.0
                    risk = soup.find('span', {'class': 'rep'}).contents[0]
                    risk = risk if ('-' not in risk) else 0
                    return {'category':categories, 'risk':float(risk)}
                else:
                    return {'category':'', 'risk':''}
            except Exception as error:
                print('\t\t[!] Error:  {0}'.format(error))
                print(traceback.format_exc())
                return {'category':'ERROR', 'risk':'ERROR'}
        else:
            return {'category':'', 'risk':''}


    # get data against Artists Against 419
    def eval_13(self):
        self.delay()
        target = self.target[0][0] if (self.target[1] == 'URL') else self.target[0]
        print('\t[-] Checking against Artists Against 419')
        api_url = 'https://db.aa419.org/fakebankslist.php?psearch='
        try:
            session = requests.Session()
            response = session.get(api_url+target, headers=self.headers)
            soup = BeautifulSoup(response.content, 'html.parser')
            risk = soup.find_all('span', {'class': 'phpmaker'})
            risk = [span.get_text() for span in risk]
            if ('No records found' in risk):
                return {'category':'', 'risk':''}
            elif any('Records' in r for r in risk):
                riks = [r for r in risk if 'Records' in r]
                # bigger number, higher risk; it shows the number of appearance in its DB
                risk = int(riks[0].split(' ')[-1])
                # if rows in the table contains any category
                if soup.find('tr', {'class': 'ewTableAltRow'}).find_all('td')[-1].find_all('a'):
                    categories = []
                    projects = soup.find('tr', {'class': 'ewTableAltRow'}).find_all('td')[-1].find_all('a')
                    for project in projects:
                        categories.append(project.contents[0])
                    return {'category':'Scam ({0})'.format(' - '.join(categories)), 'risk':risk}
                else:
                    return {'category':'Scam', 'risk':risk}
        except Exception as error:
            print('\t\t[!] Error:  {0}'.format(error))
            print(traceback.format_exc())
            return {'category':'ERROR', 'risk':'ERROR'}


    # get data against Bluecoat (Norton)
    def eval_14(self):
        # self.delay()
        target = self.target[0][1] if (self.target[1] == 'URL') else self.target[0]
        print('\t[-] Checking against Bluecoat')
        api_url = 'https://sitereview.bluecoat.com/resource/lookup'
        try:
            session = requests.Session()
            cookies = {'XSRF-TOKEN': '308f5687-4b6f-235c-4a6d-2741b95014a4'}
            self.headers['X-XSRF-TOKEN'] = '308f5687-4b6f-235c-4a6d-2741b95014a4'
            self.headers['Accept'] = 'application/json, text/plain, */*'
            self.headers['Content-Type'] = 'application/json; charset=utf-8'
            self.headers['Referer'] = 'https://sitereview.bluecoat.com/'
            data = {'captcha': '',
                    'key': '',
                    'phrase': 'RXZlbiBpZiB5b3UgYXJlIG5vdCBwYXJ0IG9mIGEgY29tbWVyY2lhbCBvcmdhbml6YXRpb24sIHNjcmlwdGluZyBhZ2FpbnN0IFNpdGUgUmV2aWV3IGlzIHN0aWxsIGFnYWluc3QgdGhlIFRlcm1zIG9mIFNlcnZpY2U=',
                    'source': 'new lookup',
                    'url': target
            }
            response = session.post(api_url, headers=self.headers, cookies=cookies, json=data)
            result = json.loads(response.content)
            # -1 means it is malicious
            risk = -1 if result['securityCategory'] else 1
            if result['categorization']:
                categories = []
                for category in result['categorization']:
                    categories.append(category['name'])
                return {'category':categories, 'risk':risk}
            else:
                return {'category':'', 'risk':risk}
        except Exception as error:
            print('\t\t[!] Error:  {0}'.format(error))
            print(traceback.format_exc())
            return {'category':'ERROR', 'risk':'ERROR'}


    # get data against Cisco Talos Intelligence
    def eval_15(self):
        # self.delay()
        target = self.target[0][0] if (self.target[1] == 'URL') else self.target[0]
        print('\t[-] Cisco Talos Intelligence')
        try:
            session = requests.Session()
            self.headers['cookie'] = '__cfduid=de2347cf2dff531a8691cde4f2d09dba81602870231; cf_clearance=7aa4256378fa05cd6b4336279f5b1a7183acb345-1602870248-0-1za4dcf588zc42070cczeb5bed6e-150; _talos_website_session=NnhBKzA0anV1bS91WlpIa1FOTWJXK0hZd3IyZlIxejM2cGZZM1VOcldzRzlDSGVpcGNhbnJBaTArekZwaVc3YUIzQ2dYNHNDN0xCZXhnYXVIY3Vpbko2TExqTUZDTWFhT1YyMmRlSDJ5U2tsN2ltNWJ5RnBIWUV0QmZLcUV6dXJTSHlHQ3hTOFBjTWpOZ0VTOFpuZDhnUFRyR1NwOHUrZTlsQmdoVDQwdXpRcC8wUG5mNkFnQ2Fma3lPbkxRbXhEbGt0dFIxRnozVGVnWlBvOWlTVzJtc0k5bWlSVWJjVURoMWY5eVQ4cUZMaz0tLU1vekoweS9QZ0g3bnNDNmRDNzNadEE9PQ%3D%3D--fb72e04c29a0a1bad7c9bd24ce0b44e55a191d90'
            self.headers['Accept'] = 'application/json, text/plain, */*'
            self.headers['Content-Type'] = 'application/json; charset=utf-8'
            self.headers['Referer'] = 'https://talosintelligence.com/reputation_center/lookup?search='
            if self.target[1] == 'URL':
                api_url = 'https://talosintelligence.com/sb_api/remote_lookup'
                data = {'hostname':'SDSv3', 'query_string':'/score/single/json?url='+target}
                response = session.get(url=api_url, headers=self.headers, params=data)
                result = json.loads(response.content)
                category = result['categories'] + result['threat_categories']
                risk = '_'.join(result['threat_score'])
            else:
                api_url = 'https://talosintelligence.com/sb_api/query_lookup'
                data = {'query':'/api/v2/details/ip/', 'query_entry':target, 'offset':'0', 'order':'ip asc'}
                response = session.get(url=api_url, headers=self.headers, params=data)
                result = json.loads(response.content)
                category = result['category']
                risk = float(result['email_score']) + float(result['web_score'])
            print({'category':category, 'risk':risk})
            return {'category':category, 'risk':risk}
        except Exception as error:
            print('\t\t[!] Error:  {0}'.format(error))
            print(traceback.format_exc())
            return {'category':'ERROR', 'risk':'ERROR'}


    # get data against Trend Micro
    def eval_16(self):
        # self.delay()
        target = self.target[0][0] if (self.target[1] == 'URL') else self.target[0]
        print('\t[-] Checking against Trend Micro', target)
        api_url = 'https://global.sitesafety.trendmicro.com/'
        try:
            session = requests.Session()
            self.headers['Host'] = 'global.sitesafety.trendmicro.com'
            self.headers['Origin'] = 'https://global.sitesafety.trendmicro.com'
            self.headers['Referer'] = 'https://global.sitesafety.trendmicro.com/index.php'
            self.headers['Accept'] = '*/*'
            self.headers['Content-Type'] = 'application/x-www-form-urlencoded'
            response = session.get(api_url, headers=self.headers)
            response = session.post('https://global.sitesafety.trendmicro.com/lib/idn.php', headers=self.headers, data={'URL':target})
            response = session.post('https://global.sitesafety.trendmicro.com/result.php', headers=self.headers, data={'urlname':target,'getinfo':'Check Now'})
            soup = BeautifulSoup(response.content, 'html.parser').find('div', {'class':'tab-content'})
            if 'prove that you are not a robot' in soup.find('div', {'class': 'whiterow'}).contents:
                print('\t\t[!] Error: Captcha is required.')
                return {'category':'ERROR-Captcha', 'risk':'ERROR-Captcha'}
            category = soup.find('div', {'class': 'labeltitlesmallresult'})
            risk = soup.find('div', {'class': 'labeltitleresult'})
            if category and risk:
                return {'category':category.contents[0], 'risk':risk.contents[0]}
            else:
                return {'category':'', 'risk':''}
        except Exception as error:
            print('\t\t[!] Error:  {0}'.format(error))
            print(traceback.format_exc())
            return {'category':'ERROR', 'risk':'ERROR'}


    # get data against PhishTank
    def eval_17(self):
        # self.delay()
        if (self.target[1] == 'URL'):
            print('\t[-] Checking against PhishTank')
            api_url = 'https://checkurl.phishtank.com/checkurl/index.php?url='
            try:
                session = requests.Session()
                response = session.get(api_url+self.target[0][0], headers=self.headers)
                soup = BeautifulSoup(response.content, 'lxml')
                result = soup.find_all('in_database')
                if 'true' in result:
                    return {'category':'Spam', 'risk':len(result)}
                else:
                    return {'category':'', 'risk':0}
            except Exception as error:
                print('\t\t[!] Error:  {0}'.format(error))
                print(traceback.format_exc())
                return {'category':'ERROR', 'risk':'ERROR'}
        else:
            return {'category':'', 'risk':''}
    

    # get data against lists
    # lists are defined in lists.py
    def eval_lists(self):
        results = {}
        for list in lists:
            if ('URL' in list['type']) and ('URL' in target[1]):
                tar = target[0][0]
            elif ('Domain' in list['type']) and ('URL' in target[1]):
                tar = target[0][1]
            elif ('IPv4' in list['type']) and ('IPv4' in target[1]):
                tar = target[0]
            elif ('IPv6' in list['type']) and ('IPv6' in target[1]):
                tar = target[0]
            else:
                continue
            try:
                if not list['data']:
                    self.delay()
                    # convert the non-array URLs to array
                    list['url'] = [list['url']] if (type(list['url']) is str) else list['url']
                    for l in list['url']:
                        list['data'] += requests.get(l, allow_redirects=True).text
                if tar in list['data']:
                    results[list['name']] = {'category':list['category'], 'risk':'listed'}
                else:
                    results[list['name']] = {'category':'', 'risk':''}
            except Exception as error:
                print('\t\t[!] Error:  {0}'.format(error))
                print(traceback.format_exc())
                return {'category':'ERROR', 'risk':'ERROR'}
        return results


if __name__ == '__main__':
    results = {}
    targets = [#'octvt.xyz/V3/five/PvqDq929BSx_A_D_M1n_a.php',
            #    'https://www.google.nl/maps/@52.084736,4.3057152,13z?hl=en', 
            #    'https://app.box.com/s/rdobxcyrhp1cdxwej3pfeyvngfh3lwag', 
            #    '136710.txtplug.com', 
            #    '54.253.227.154',
            #    '142.4.203.42',
            #    'https://www.thyspuppies.com',
            #    'https://www.castroboxer.com',
                'https://mail.mymp3remix.in/',
                'http://n26-mobile.it/',
            #    '10cms.com',
            #    '94.23.62.116',
            #    'https://dafa.io'
            #    'http://pochtarefund-xeq0uz.aakkp.xyz/lloyds',
            #   '49.12.47.176/sAMMyKiNGoFSCAmMERs/PvqDq929BSx_A_D_M1n_a.php'

               ]
    
    for target in targets:
        # time.sleep(settings.delay)
        # get the type of the target and sanitize it
        # regex order: IPv4, IPv6, URL
        # read more: https://github.com/namnamir/hack/blob/main/regex.md
        regex = ['^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$',
                 '^([0-9a-fA-F]){1,4}(:([0-9a-fA-F]){1,4}){7}$',
                 '(http[s]?:\/\/)?(?i)([0-9a-z-]*@)?(([0-9a-z-]+\.)*([0-9a-z-]{1,256})+(\.[0-9a-z-]{2,})+){1}(:\d*)*([\/|?]+[-a-zA-Z0-9()@:%_\+.~#?&\/=]*)*'
                ]
        if re.match(regex[0], target):
            target = [re.findall(regex[0], target)[0], 'IPv4']
        elif re.match(regex[1], target):
            target = [re.findall(regex[1], target)[0], 'IPv6']
        elif re.match(regex[2], target):
            # get parts of the URL and assemble the needed parts
            url = re.findall(regex[2], target)[0]
            # target format: [('http://sub1.sub2.main.tld:80/path/rest', 'sub1.sub2.main.tld'), 'URL']
            target = [(url[0]+url[2]+url[6]+url[7], url[2]), 'URL']
        else:
            target = ''

        # continue if the target is either an IPv4/6 or URL/domain
        if target:
            # define the key of the list
            key = target[0] if ('URL' not in target[1]) else (target[0][0] if target[0][0] else target[0][1])
            print('[+] Evaluate {0}:'.format(key))
            e = Evaluator(target)
            # initiate the list with the key
            results[key] = {}
            # write data in the list
            results[key] = {
                # 'McAfee Trusted Source': e.eval_1(),
                # 'Scam Advisor': e.eval_2(),
                # 'Norton Safe Web': e.eval_3(),
                # 'FortiGuard Web Filter': e.eval_4(),
                # 'Open DNS': e.eval_5(),
                # 'Cybercrime Tracker': e.eval_6(),
                # 'Threat Score': e.eval_7(),
                # 'SANS Internet Storm': e.eval_8(),
                # 'Threat Crowd': e.eval_9(),
                # 'Joe Sandbox': e.eval_10(),
                # 'Stop Forum Spam': e.eval_11(),
                # 'Nerd': e.eval_12(),
                # 'Artists Against 419': e.eval_13(),
                # 'Bluecoat': e.eval_14(),
                # 'Cisco Talos': e.eval_15(),
                # 'Trend Micro': e.eval_16(),
                'PhishTank': e.eval_17(),
            }
            # update results with blacklist items
            # results.update(filter(lambda x: x[1]!='', eval_lists(key).items()))   
    # print(results)
