#from urlparse import urlparse
#import urllib2
#import re
#from urllib.parse import urlparse,urlencode
#import urllib.request as u
#from xml.dom import minidom
#import csv
#import pygeoip
#import datetime
#import whois
try:
    import threading
    import multiprocessing
except:
    raise Exception('Requiring threading or multiprocessing module!')
try:
    import re
except ImportError:
    raise Exception('Requiring re Module!')
try:
    import time
    import tldextract
    import json
    from urllib.parse import urlparse, urlencode
    import urllib.request as u
    import codecs
    import requests
    import pyxdameraulevenshtein as lev
    from bs4 import BeautifulSoup,SoupStrainer
except ImportError:
    raise Exception('Requiring Module!')
try:
    from xml.dom import minidom
except ImportError:
    raise Exception('Requiring xml Module!')
try:
    import pygeoip
except ImportError:
    raise Exception('Requiring pygeoip Module!')
try:
    import datetime
except ImportError:
    raise Exception('Requiring datetime Module!')
try:
    import whois
except ImportError:
    raise Exception('Requiring whois Module!')
try:
    import math
except ImportError:
    raise Exception('Requiring math Module!')
try:
    import string
except ImportError:
    raise Exception('Requiring string Module!')

opener = u.build_opener()
opener.addheaders = [('User-agent', 'Mozilla/5.0')]

class Url(object):

    def __init__(self, url):
        self.LevDist = LevenshteinDist()
        self.url = url
        self._host = Host()
        self._domain = Domain()
        self._tld = Tld()

    @property
    def url(self):
        return self.__url

    @url.setter
    def url(self, url=None):
        if url is not None:
            short_url = urlparse(url)
            if 'bit.ly' == short_url.netloc or 'goo.gl' == short_url.netloc or 'tinyurl.com' == short_url.netloc or 'ow.ly' == short_url.netloc or 'ls.gd' == short_url.netloc or 'buff.ly' == short_url.netloc or 'adf.ly' == short_url.netloc or 't.co' == short_url.netloc or 'db.tt' == short_url.netloc or 'cur.lv' == short_url.netloc:
                try:
                    short = requests.head(url)
                    if short.status_code == 302 or short.status_code == 200:
                        self.__url = '?'
                    else:
                        real_url = short.headers['Location']
                        self.__url = real_url
                except:
                    raise Exception('Connection Failed!')
            else:
                self.__url = url
        else:
            raise Exception('Url is None!')

    @staticmethod
    def range_bytes():
        return range(256)

    @staticmethod
    def range_printable():
        return (ord(c) for c in string.printable)

    def feature_extract(self):
        Featuree = []
        if self.url == '?':
            Featuree.append('?')
            return Featuree
        else:
            self.obj = urlparse(self.url)
            self.host = self.obj.netloc
            self.path = self.obj.path
            self.tokens_words = re.split('\W+', self.url)
            if self._host.Check_IPaddress(self.host) == 0:
                _parsedHost = tldextract.extract(self.host)
                self.domain = _parsedHost.registered_domain
                self.subdomains = _parsedHost.subdomain
                suffx = _parsedHost.suffix
                self.tld = suffx.split('.')[-1] if suffx.find('.') >= 1 else suffx


            Featuree.append(self.url)
            Featuree.append(1 if self.obj.scheme == 'https' else 0)
            tttt = time.time()
            ra, rb = self._host.sitepopularity(self.host)
            Featuree.append(ra)
            Featuree.append(rb)
            Featuree.append(self.Tokenise(self.url))
            Featuree.append(self.Tokenise(self.host))
            Featuree.append(self.Tokenise(self.path))
            Featuree.append(float(Featuree[6]/Featuree[4]) if Featuree[4] != 0 else 0)
            Featuree.append(self._host.Check_IPaddress(self.host))
            Featuree.append(sum(len(i) for i in self.subdomains))
            Featuree.append(self.URLEntropy(self.range_printable))
            Featuree.append(self._tld.tldCheck(self.tld))
            pa, pb = self.punctuation()
            Featuree.append(pa)
            Featuree.append(pb)
            Featuree.append(self.Security_sensitive())
            Featuree.append(self._domain.ipBlacklist('ip', self.host, 'ip-address') if Featuree[8] == 1 else self._domain.ipBlacklist('domain', self.host.split(':')[0], 'domain'))
            Featuree.append(self._host.getASN(self.host))
            Featuree.append(self.web_content_features())
            Featuree.append(self.safebrowsing())
            da, db = self._domain.domainRegDate(self.domain)[:2] if Featuree[8] != 1 else [-1, 0]
            Featuree.append(da)
            Featuree.append(db)
            Featuree.append(len(self.LevDist.run(self.domain)) if Featuree[8] != 1 else -1)
            print('All:',int(time.time()-tttt))
            return Featuree

    def sameDom(self):
        if self._host.Check_IPaddress(self.host) == 0:
            try:
                __sameDom = self.LevDist.run(self.domain)
                return __sameDom
            except:
                raise Exception('Error!')
        else:
            return 0

    #URL'S CLASS
    def URLEntropy(self, iterator=range_bytes):
        entropy = 0
        for x in iterator():
            p_x = float(self.url.count(chr(x))) / len(self.url)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy
    # URL'S CLASS
    def punctuation(self):
        countp = count = 0
        punct = ['.', '!', '#', '$', '%', '&', ',', ';', '’', '@', '-']
        for p in punct:
            if p == '@' or p == '-':
                count += self.url.count(p)
            countp += self.url.count(p)
        return [countp, count]
    #URL'S CLASS
    def safebrowsing(self):
        api_key = "AIzaSyAE4JrIOF0H77CYoRB2V4FSqVuqYvex5Ns"
        name = "PhishDetector"
        ver = "1.0"

        req = {}
        req["client"] = name
        req["key"] = api_key
        req["appver"] = ver
        req["pver"] = "3.1"
        req["url"] = self.url

        try:
            params = urlencode(req)
            req_url = "https://sb-ssl.google.com/safebrowsing/api/lookup?" + params
            res = u.urlopen(req_url)
            if res.code == 204:
                return 0
            elif res.code == 200:
                return 1
            elif res.code == 204 or res.code == 400 or res.code == 401:
                return -1
            else:
                return -2
        except:
            return -1
    # URL'S CLASS
    def web_content_features(self):
        #wfeatures = {}
        try:
            sess = requests.Session()
            req = sess.get(self.url)

            soup = BeautifulSoup(req.content, "lxml")

            #wfeatures['page_title'] = soup.find('title').get_text()
            #wfeatures['a_tag_no'] = 1 if len(soup.find_all('a', href=True)) > 0 else 0
            #wfeatures['img_tag_no'] = 1 if len(soup.find_all('img')) > 0 else 0
            #wfeatures['form_tag_no'] = 1 if len(soup.find_all('form')) > 0 else 0
            #wfeatures['input_tag_no'] = 1 if len(soup.find_all('input', {'type': 'text'})) > 0 or len(soup.find_all('input', {'type': 'password'})) > 0 else 0
            #wfeatures['meta_tags_no'] = 1 if len(soup.find_all('meta')) > 0 else 0
            #wfeatures['iframe_tag_no'] = 1 if len(soup.find_all('iframe')) > 0 else 0
            #wfeatures['link_tag_no'] = 1 if len(soup.find_all('link')) > 0 else 0
            total = 1 if len(soup.find_all('a', href=True)) > 0 else 0
            total += 1 if len(soup.find_all('img')) > 0 else 0
            total += 1 if len(soup.find_all('form')) > 0 else 0
            total += 1 if len(soup.find_all('input', {'type': 'text'})) > 0 or len(soup.find_all('input', {'type': 'password'})) > 0 else 0
            total += 1 if len(soup.find_all('meta')) > 0 else 0
            total += 1 if len(soup.find_all('iframe')) > 0 else 0
            total += 1 if len(soup.find_all('link')) > 0 else 0
            #total = (wfeatures['a_tag_no'] + wfeatures['img_tag_no'] + wfeatures['form_tag_no'] + wfeatures['input_tag_no'] + wfeatures['meta_tags_no'] + wfeatures['iframe_tag_no'] + wfeatures['link_tag_no'])
            if total == 7 or total == 6:
                default_val = 5
            elif 1 <= total < 6:
                default_val = 3
            else:
                default_val = 1
            return default_val
        except:
            return -1
    # URL'S CLASS
    def Security_sensitive(self):
        sec_sen_words = ['confirm', 'account', 'banking', 'secure', 'webscr', 'login', 'signin', 'submit',
                         'update', 'logon', 'wp', 'cmd', 'admin']
        cnt = 0
        for ele in sec_sen_words:
            if ele in self.tokens_words:
                cnt += 1

        return cnt

    # URL'S CLASS - PATH, HOST
    def Tokenise(self, txt):
        try:
            token_word = re.split('\W+', txt)
            sum_len = 0
            for ele in token_word:
                l = len(ele)
                sum_len += l
            return sum_len
        except:
            return 0


class Host(object):
    # HOST'S CLASS
    def sitepopularity(self, host):
        xmlpath = 'http://data.alexa.com/data?cli=10&dat=snbamz&url=' + host
        try:
            soup = BeautifulSoup(requests.get(xmlpath).content, 'lxml')
            try:
                rr = soup.reach['rank']
            except:
                rr = -1
            try:
                cr = soup.country['rank']
            except:
                cr = -1
            return [int(rr), int(cr)]
        except:
            return [-2, -2]
    # HOST'S CLASS
    def Check_IPaddress(self, host):
        is_valid = re.match('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', host)
        if is_valid:
            return 1
        else:
            return 0
    # HOST'S CLASS
    def getASN(self, host):
        try:
            g = pygeoip.GeoIP('/Users/mac/PycharmProjects/URL_Finder/Input/GeoIPASNum.dat')
            asn = int(g.org_by_name(host).split()[0][2:])
            if asn != 0:
                return 1
        except:
            return -1

class Tld(object):
    def tldCheck(self, tld):
        try:
            session = requests.Session()
            resp = session.get('http://www.iana.org/domains/root/db')

            strainer = SoupStrainer('table', attrs={'id': 'tld-table'})
            soup = BeautifulSoup(resp.content, 'lxml', parse_only=strainer)
            #x = soup.find('table', {'id': 'tld-table'})
            tlds = [anchor.text for anchor in soup.find_all('a')]
            for tldss in tlds:
                tldss = tldss.split('.')
                if tld == codecs.decode(tldss[1].encode('utf8')):
                    return 1
            return 0
        except:
            return -1

class Domain(object):
    # DOMAİN'S CLASS
    def domainRegDate(self, domain):
        now = datetime.datetime.now()
        try:
            response = whois.whois(domain)
            if response.creation_date is None and response.registrar is None:
                return [-1, 0]
            elif response.creation_date is not None and response.registrar is None:
                resp = response.creation_date[0] if type(response.creation_date) is list else response.creation_date
                timedelta = now - resp
                return [timedelta.days, 0]
            elif response.creation_date is None and response.registrar is not None:
                return [-1, 1]
            elif response.creation_date is not None and response.registrar is not None:
                _resp = response.creation_date[0] if type(response.creation_date) is list else response.creation_date
                timedelta = now - _resp
                return [timedelta.days, 1]
        except:
            return [-2, -2]
    # DOMAİN'S CLASS
    def ipBlacklist(self, iod, ip_or_domain, post):
        try:
            parameters = {iod: ip_or_domain, 'apikey': '0b9235ea994ae701f2a4a06d6a125517568c4527671d11da81083fe372714b72'}
            urll = 'https://www.virustotal.com/vtapi/v2/' + post + '/report'
            urll = urll + '?' + urlencode(parameters)
            response = u.urlopen(urll).read()
            response_dict = json.loads(response.decode('utf-8'))
            if response_dict['response_code'] == 1:
                return 1
            return 0

        except:
            return -1

class LevenshteinDist(object):
    def __init__(self):
        self.lst_1 = self.domaintxt()
        self.data = []

    def run(self, domain=None):
        #t = multiprocessing.Pool()
        #rs = t.map(self.levdist, self.lst_1)
        #return rs
        if domain is None:
            raise Exception('Domain is None!')
        else:
            manager = multiprocessing.Manager()
            rr = manager.list()
            prcs = multiprocessing.Process(target=self.levdist, args=(self.lst_1, domain, rr,))
            prcs.start()
            prcs.join()
            return rr

    def domaintxt(self):
        dct = {}
        try:
            with open('/Users/mac/PycharmProjects/URL_Finder/Input/url_250k.txt', 'r') as ff:
                file = ff.readlines()
                file = list(map(lambda s: s.strip(), file))
                dct['lst_0'] = file[:100000]
            return dct['lst_0']
        except IOError:
            raise IOError('File Opening Error!')

    def levdist(self, listofdom, domain, return_dict):
        for j in listofdom:
            val = float((1.0 - lev.normalized_damerau_levenshtein_distance(domain, j)) * 100)
            if val >= 80.0:
                return_dict.append(j)

class Url(object):
    nf = -1
    Feature = {}
    def __init__(self, url=None):
        if url is not None:
            self.url = url
            self.obj = urlparse(self.url)
            self.host = self.obj.netloc
            self.path = self.obj.path
            self.tokens_words = re.split('\W+', self.url)
            self.dom = ''
            self.domain = ''
            self.subdomains = ''
            self.tld = ''
            self.lev_dist = LevenshteinDist(self.domain)
        else:
            raise Exception('Url is None!')


    @staticmethod
    def range_bytes():
        return range(256)

    @staticmethod
    def range_printable():
        return (ord(c) for c in string.printable)

    def feature_extract(self):

        self.Feature['URL'] = self.url
        self.Feature['Protocol'] = 1 if self.obj.scheme == 'https' else 0
        self.Feature['rank_host'],  self.Feature['rank_country'] = self.sitepopularity()
        self.Feature['Url_Path_Ratio'] = float(self.Feature['Length_of_path']/self.Feature['Length_of_url'])
        self.Feature['Length_of_subdomains'] = sum(len(i) for i in self.subdomains)
        self.Feature['Entropy_of_Url'] = self.URLEntropy(self.range_printable)
        self.Feature['Tld_Check'] = self.tldCheck()
        self.Feature['No_of_punctuation'], self.Feature['No_of_at'] = self.punctuation()
        self.Feature['Length_of_url'],  self.Feature['token_count'] = self.Tokenise(self.url)
        self.Feature['Length_of_host'],  self.Feature['host_token_count'] = self.Tokenise(self.host)
        self.Feature['Length_of_path'],  self.Feature['path_token_count'] = self.Tokenise(self.path)
        self.Feature['sec_sen_word_cnt'] = self.Security_sensitive()
        self.Feature['IPaddress_presence'] = self.Check_IPaddress()
        self.Feature['IP_Blacklist'] = self.ipBlacklist('ip', self.host, 'ip-address') if self.Feature['IPaddress_presence'] == 1 else self.ipBlacklist('domain', self.host.split(':')[0], 'domain')
        self.Feature['ASNno'] = self.getASN()
        self.Feature['Web_Content'] = self.web_content_features()
        self.Feature['safebrowsing'] = self.safebrowsing()
        self.Feature['domain_reg_date'], self.Feature['Registrar'] = self.domainRegDate()
        self.Feature['Lev_Dist_Count'] = self.lev_dist
        return self.Feature

    def tldCheck(self):
        try:
            text = requests.get('http://www.iana.org/domains/root/db').text
            soup = BeautifulSoup(text)
            x = soup.find('table', {'id': 'tld-table'})
            tlds = [anchor.text for anchor in x.find_all('a')]
            for i, tldss in enumerate(tlds):
                tldss = tldss.split('.')
                if codecs.decode(tldss[1].encode('utf8')) == self.tld:
                    return 1
            return 0
        except:
            return -1

    def URLEntropy(self, iterator=range_bytes):
        entropy = 0
        for x in iterator():
            p_x = float(self.url.count(chr(x))) / len(self.url)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def punctuation(self):
        countp = count = 0
        punct = ['.', '!', '#', '$', '%', '&', ',', ';', '’', '@', '-']
        for p in punct:
            if p == '@' or p == '-':
                count += self.url.count(p)
            countp += self.url.count(p)
        return [countp, count]

    def safebrowsing(self):
        api_key = "AIzaSyAE4JrIOF0H77CYoRB2V4FSqVuqYvex5Ns"
        name = "PhishDetector"
        ver = "1.0"

        req = {}
        req["client"] = name
        req["key"] = api_key
        req["appver"] = ver
        req["pver"] = "3.1"
        req["url"] = self.url

        try:
            params = urlencode(req)
            req_url = "https://sb-ssl.google.com/safebrowsing/api/lookup?" + params
            res = u.urlopen(req_url)
            if res.code == 204:
                return 0
            elif res.code == 200:
                return 1
            elif res.code == 204 or res.code == 400 or res.code == 401:
                return -1
            else:
                return -2
        except:
            return -1

    def web_content_features(self):
        wfeatures = {}
        count = 0
        try:
            req = requests.get(self.url)
            soup = BeautifulSoup(req.content, 'html.parser')

            wfeatures['page_title'] = soup.find('title').get_text()
            wfeatures['a_tag_no'] = 1 if len(soup.find_all('a', href=True)) > 0 else 0
            wfeatures['img_tag_no'] = 1 if len(soup.find_all('img')) > 0 else 0
            wfeatures['form_tag_no'] = 1 if len(soup.find_all('form')) > 0 else 0
            wfeatures['input_tag_no'] = 1 if len(soup.find_all('input', {'type': 'text'})) > 0 or len(soup.find_all('input', {'type': 'password'})) > 0 else 0
            wfeatures['meta_tags_no'] = 1 if len(soup.find_all('meta')) > 0 else 0
            wfeatures['iframe_tag_no'] = 1 if len(soup.find_all('iframe')) > 0 else 0
            wfeatures['link_tag_no'] = 1 if len(soup.find_all('link')) > 0 else 0

        except:
            default_val = self.nf

            wfeatures['page_title'] = default_val
            wfeatures['a_tag_no'] = default_val
            wfeatures['img_tag_no'] = default_val
            wfeatures['form_tag_no'] = default_val
            wfeatures['input_tag_no'] = default_val
            wfeatures['meta_tags_no'] = default_val
            wfeatures['iframe_tag_no'] = default_val
            wfeatures['js_sec_no'] = default_val

        return wfeatures

    def getASN(self):
        try:
            g = pygeoip.GeoIP('/Users/mac/PycharmProjects/URL_Finder/Input/GeoIPASNum.dat')
            asn = int(g.org_by_name(self.host).split()[0][2:])
            if asn != 0:
                return 1
        except:
            return self.nf

    def ipBlacklist(self, iod, ip_or_domain,post):
        try:
            parameters = {iod: ip_or_domain, 'apikey': '0b9235ea994ae701f2a4a06d6a125517568c4527671d11da81083fe372714b72'}
            urll = 'https://www.virustotal.com/vtapi/v2/' + post + '/report'
            urll = urll + '?' + urlencode(parameters)
            response = u.urlopen(urll).read()
            response_dict = json.loads(response.decode('utf-8'))
            if response_dict['response_code'] == 1:
                return 1
            else:
                return 0

        except:
            return -1

    def Check_IPaddress(self):
        is_valid = re.match('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', self.host)
        if is_valid:
            return 1
        else:
            _parsedHost = tldextract.extract(self.host)
            #self.dom = self.host.rsplit('.', 2)
            self.domain = _parsedHost.domain #self.dom[-2] + '.' + self.dom[-1]
            self.subdomains = _parsedHost.subdomain #self.dom[0].split('.')
            suffx = _parsedHost.suffix #self.dom[-1]
            self.tld = suffx.split('.')[-1] if suffx.find('.') >= 1 else suffx
            return 0

    def sitepopularity(self):
        xmlpath = 'http://data.alexa.com/data?cli=10&dat=snbamz&url=' + self.host
        try:
            xml = u.urlopen(xmlpath)
            dom = minidom.parse(xml)
            rank_host = dom.getElementsByTagName('REACH')
            rank_country = dom.getElementsByTagName('COUNTRY')
            if rank_host and rank_country:
                for rankh in rank_host:
                    hostRank = rankh.getAttribute('RANK')
                    for rankc in rank_country:
                        countryRank = rankc.getAttribute('RANK')
                        return [hostRank, countryRank]
            else:
                return [-1, -1]
        except:
            return [-2, -2]

    def Security_sensitive(self):
        sec_sen_words = ['confirm', 'account', 'banking', 'secure', 'webscr', 'login', 'signin', 'submit',
                         'update', 'logon', 'wp', 'cmd', 'admin']
        cnt = 0
        for ele in sec_sen_words:
            if ele in self.tokens_words:
                cnt += 1

        return cnt

    def domainRegDate(self):
        now = datetime.datetime.now()
        try:
            response = whois.query(self.domain)
            if response.creation_date == 'none' and response.registrar == 'none':
                return [-1, 0]
            elif response.creation_date and response.registrar == 'none':
                timedelta = now - response.creation_date
                return [timedelta.days, 0]
            elif response.creation_date == 'none' and response.registrar:
                return [-1, 1]
            elif response.creation_date and response.registrar:
                timedelta = now - response.creation_date
                return [timedelta.days, 1]
        except:
            return [-2, -2]

    def Tokenise(self, txt):
        try:
            if txt == '':
                return [0, 0]
            token_word = re.split('\W+', txt)
            no_ele = sum_len = 0
            for ele in token_word:
                l = len(ele)
                sum_len += l
                if l > 0:
                    no_ele += 1
            return [sum_len, no_ele]
        except:
            return [0, 0]


class Host(Url):
    pass

class Path(Url):
    pass

class Domain(Host):
    pass

class LevenshteinDist(object):
    def __init__(self, domain=None):
       if domain is not None:
           self.domain = domain
           self.lst_1 = self.domaintxt()
           self.data = {}
           prcs_1 = multiprocessing.Process(target=self.levdist, args=(self.lst_1,))
        #prcs_2 = multiprocessing.Process(target=self.levdist, args=(self.lst_2,))
           prcs_1.start()
        #prcs_2.start()
           prcs_1.join()
        #prcs_2.join()
       else:
           raise Exception('Domain is None!')

    def domaintxt(self):
        dct = {}
        try:
            with open('/Users/mac/PycharmProjects/URL_Finder/Input/url_250k.txt', 'r') as ff:
                file = ff.readlines()
                file = list(map(lambda s: s.strip(), file))
                dct['lst_0'] = file[:100000]
                #dct['lst_1'] = file[50000:100000]
            return dct['lst_0']
        except IOError:
            raise IOError('File Opening Error!')

    def levdist(self, listofdom):
        counter = 0
        for j in listofdom:
            self.data[j] = (1.0 - lev.normalized_damerau_levenshtein_distance(self.domain, j)) * 100
        for key, value in self.data.items():
            if float(value) >= 80.0:
                counter += 1
        return counter

def Tokenise(url):
    if url == '':
        return [0, 0, 0]
    token_word = re.split('\W+', url)
    # print token_word
    no_ele = sum_len = largest = 0
    for ele in token_word:
        l = len(ele)
        sum_len += l
        if l > 0:  ## for empty element exclusion in average length
            no_ele += 1
        if largest < l:
            largest = l
    try:
        return [float(sum_len) / no_ele, no_ele, largest]
    except:
        return [0, no_ele, largest]


'''def find_ele_with_attribute(dom, ele, attribute):
    for subelement in dom.getElementsByTagName(ele):
        if subelement.hasAttribute(attribute):
            return subelement.attributes[attribute].value
    return nf'''

#URL rank query
def sitepopularity(host):
    xmlpath = 'http://data.alexa.com/data?cli=10&dat=snbamz&url=' + host
    # print xmlpath
    try:
        xml = u.urlopen(xmlpath)
        dom = minidom.parse(xml)
        rank_host = dom.getElementsByTagName('REACH')
        rank_country = dom.getElementsByTagName('COUNTRY')
        if rank_host and rank_country:
            for rankh in rank_host:
                hostRank = rankh.getAttribute('RANK')
                for rankc in rank_country:
                    countryRank = rankc.getAttribute('RANK')
            return [hostRank, countryRank]
        else:
            return -1
    except Exception as e:
        return e


def Security_sensitive(tokens_words):
    sec_sen_words = ['confirm', 'account', 'banking', 'secure', 'ebayisapi', 'webscr', 'login', 'signin', 'submit', 'update', 'logon', 'wp', 'cmd', 'admin']
    cnt = 0
    for ele in sec_sen_words:
        if (ele in tokens_words):
            cnt += 1

    return cnt


def exe_in_url(url):
    if url.find('.exe') != -1:
        return 1
    return 0


def Check_IPaddress(tokens_words):
    cnt = 0
    for ele in tokens_words:
        if str(ele).isnumeric():

            cnt += 1
        else:
            if cnt >= 4:
                return 1
            else:
                cnt = 0
    if cnt >= 4:
        return 1
    return 0


def getASN(host):
    try:
        g = pygeoip.GeoIP('GeoIPASNum.dat')
        asn = int(g.org_by_name(host).split()[0][2:])
        return asn
    except:
        return nf


def web_content_features(url):
    wfeatures = {}
    total_cnt = 0
    try:
        source_code = str(opener.open(url))
        # print source_code[:500]

        wfeatures['src_html_cnt'] = source_code.count('<html')
        wfeatures['src_hlink_cnt'] = source_code.count('<a href=')
        wfeatures['src_iframe_cnt'] = source_code.count('<iframe')
        # suspicioussrc_ javascript functions count

        wfeatures['src_eval_cnt'] = source_code.count('eval(')
        wfeatures['src_escape_cnt'] = source_code.count('escape(')
        wfeatures['src_link_cnt'] = source_code.count('link(')
        wfeatures['src_underescape_cnt'] = source_code.count('underescape(')
        wfeatures['src_exec_cnt'] = source_code.count('exec(')
        wfeatures['src_search_cnt'] = source_code.count('search(')

        for key in wfeatures:
            if key != 'src_html_cnt' and key != 'src_hlink_cnt' and key != 'src_iframe_cnt':
                total_cnt += wfeatures[key]
        wfeatures['src_total_jfun_cnt'] = total_cnt

    except Exception as e:
        print("Error" + str(e) + " in downloading page " + url)
        default_val = nf

        wfeatures['src_html_cnt'] = default_val
        wfeatures['src_hlink_cnt'] = default_val
        wfeatures['src_iframe_cnt'] = default_val
        wfeatures['src_eval_cnt'] = default_val
        wfeatures['src_escape_cnt'] = default_val
        wfeatures['src_link_cnt'] = default_val
        wfeatures['src_underescape_cnt'] = default_val
        wfeatures['src_exec_cnt'] = default_val
        wfeatures['src_search_cnt'] = default_val
        wfeatures['src_total_jfun_cnt'] = default_val

    return wfeatures

#Checking safety of web pages
def safebrowsing(url):
    api_key = "AIzaSyAE4JrIOF0H77CYoRB2V4FSqVuqYvex5Ns"
    name = "PhishDetector"
    ver = "1.0"

    req = {}
    req["client"] = name
    req["key"] = api_key
    req["appver"] = ver
    req["pver"] = "3.1"
    req["url"] = url  # change to check type of url

    try:
        params = urlencode(req)
        req_url = "https://sb-ssl.google.com/safebrowsing/api/lookup?" + params
        res = u.urlopen(req_url)
        # print res.code
        # print res.read()
        if res.code == 204:
            # print "safe"
            return 0
        elif res.code == 200:
            # print "The queried URL is either phishing, malware or both, see the response body for the specific type."
            return 1
        elif res.code == 204:
            print("The requested URL is legitimate, no response body returned.")
        elif res.code == 400:
            print("Bad Request The HTTP request was not correctly formed.")
        elif res.code == 401:
            print("Not Authorized The apikey is not authorized")
        else:
            print(
                "Service Unavailable The server cannot handle the request. Besides the normal server failures, it could also indicate that the client has been throttled by sending too many requests")
    except:
        return -1
def domainRegDate(domain):
    now = datetime.datetime.now()
    try:
        response = whois.query(domain)
        if response.creation_date == 'none' and response.registrar == 'none':
            return [-1,'none']
        elif response.creation_date and response.registrar == 'none':
            timedelta = now - response.creation_date
            return [timedelta.days, 'none']
        elif response.creation_date == 'none' and response.registrar:
            return [-1, 'yes']
        elif response.creation_date and response.registrar:
            timedelta = now - response.creation_date
            return [timedelta.days, 'yes']
    except Exception as e:
        return e

def feature_extract(url_input):
    Feature = {}
    tokens_words = re.split('\W+', url_input)  # Extract bag of words stings delimited by (.,/,?,,=,-,_)
    # print tokens_words,len(tokens_words)

    # token_delimit1=re.split('[./?=-_]',url_input)
    # print token_delimit1,len(token_delimit1)

    obj = urlparse(url_input)
    host = obj.netloc
    path = obj.path
    domain = host.rsplit('.', -1)
    domain = domain[-2] + '.' + domain[-1]

    Feature['URL'] = url_input

    Feature['rank_host'], Feature['rank_country'] = sitepopularity(host)

    Feature['host'] = obj.netloc
    Feature['path'] = obj.path

    Feature['Length_of_url'] = len(url_input)
    Feature['Length_of_host'] = len(host)
    Feature['No_of_dots'] = url_input.count('.')

    Feature['avg_token_length'], Feature['token_count'], Feature['largest_token'] = Tokenise(url_input)
    Feature['avg_domain_token_length'], Feature['domain_token_count'], Feature['largest_domain'] = Tokenise(host)
    Feature['avg_path_token'], Feature['path_token_count'], Feature['largest_path'] = Tokenise(path)

    Feature['sec_sen_word_cnt'] = Security_sensitive(tokens_words)
    Feature['IPaddress_presence'] = Check_IPaddress(tokens_words)

    # print host
    # print getASN(host)
    # Feature['exe_in_url']=exe_in_url(url_input)
    Feature['ASNno'] = getASN(host)
    Feature['safebrowsing'] = safebrowsing(url_input)
    #wfeatures=web_content_features(url_input)
        
        #for key in wfeatures:
         #   Feature[key]=wfeatures[key]

    # debug
    # for key in Feature:
    #     print key +':'+str(Feature[key])
    return Feature
"""


