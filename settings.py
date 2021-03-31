import random


# Delay (in seconds)
delay = random.uniform(3, 50)
delay_internal = random.uniform(1, 5)

# Date format
date_format = '%Y-%m-%d %H:%M:%S'

# Generate random headers
headers = {
        'User-Agent': random.choice([
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.67 Safari/537.36 Edg/87.0.664.52',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
                'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)',
                'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36',
                'Mozilla/5.0 (X11; Linux i686 on x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.67 Safari/537.36 OPR/56.0.3051.104',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.62 Safari/537.36 OPR/54.0.2952.64',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0.2) Gecko/20100101 Firefox/58.0.2',
                'Mozilla/5.0 (Windows NT 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.67 Safari/537.36 OPR/56.0.3051.104',
                'Mozilla/5.0 (X11; Linux i686 on x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.80 Safari/537.36 OPR/57.0.3098.116',
                'Mozilla/5.0 (X11; Linux i686 on x86_64; rv:51.0) Gecko/20100101 Firefox/51.0',
                'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.98 Safari/537.36',
                'Mozilla/5.0 (Windows NT 6.0; WOW64; rv:65.0) Gecko/20100101 Firefox/65.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1; rv:52.1.0) Gecko/20100101 Firefox/52.1.0',
                'Mozilla/5.0 (Windows NT 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.75 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36',
                'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.67 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.162 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.1805 Safari/537.36',
                'Mozilla/5.0 (Windows NT 6.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.84 Safari/537.36',
                'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
                'Mozilla/5.0 (Windows NT 6.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.158 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:77.0) Gecko/20100101 Firefox/77.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) Gecko/20100101 Firefox/77.0',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36',
        ]),
        'Accept': random.choice([
                'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'application/json, text/plain, */*',
                '*/*'
        ]),
        'Accept-Language': random.choice([
                'en-US,en;q=0.9',
                'en-GB,en;q=0.5',
                'en-US;q=0.5,en;q=0.3',
                'es-ES,es;q=0.9,en;q=0.8',
                'en_US'
        ]),
        'Accept-Encoding': random.choice([
                'gzip, deflate, br',
                'gzip, deflate, bz',
                'gzip, deflate',
                'br;q=1.0, gzip;q=0.8, *;q=0.1',
                'gzip'
        ]),
        'Cache-Control': random.choice([
                'max-age=0',
                'no-cache',
                'private',
                'no-store',
                'no-store, max-age=0',
                'public, max-age=604800, immutable',
                'max-age=0, must-revalidate'
        ]),
        'Referer': random.choice([
                'https://mozilla.org/en-US/',
                'https://google.com',
                'https://mail.google.com',
                'https://bing.com',
                'https://yahoo.com'
        ]),
        'Sec-Fetch-Dest': random.choice([
                'audio',
                'audioworklet',
                'document',
                'embed',
                'empty',
                'font',
                'image',
                'manifest',
                'object',
                'paintworklet',
                'report',
                'script',
                'serviceworker',
                'sharedworker',
                'style',
                'track',
                'video',
                'worker',
                'xslt',
                'nested-document'
        ]),
        'Sec-Fetch-Mode': random.choice([
                'cors',
                'navigate',
                'nested-navigate',
                'no-cors',
                'same-origin',
                'websocket'
        ]),
        'Sec-Fetch-Site': random.choice([
                'cross-site',
                'same-origin',
                'same-site',
                'none'
        ]),
        'Sec-Fetch-User': random.choice(['?0', '?1']),
        'Upgrade-Insecure-Requests': random.choice(['1']),
        'Connection': random.choice(['keep-alive']),
        'DNT': random.choice(['0', '1']),
    }

# List of the proxies
# using proxies reduce the speed significantly
proxies = {
    'https':'103.255.53.98:56031',
    'https':'188.166.52.211:80',
    'https':'167.179.98.15:8080',
    'https':'191.101.39.29:80',
}
