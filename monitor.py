import requests
import time
from bs4 import BeautifulSoup

def scan_website(url):
    try:
        start = time.time()
        response = requests.get(url, timeout=10)  # Timeout for faster response
        end = time.time()
        load_time = round(end - start, 2)

        # Check if website title exists
        soup = BeautifulSoup(response.text, 'html.parser')
        title = soup.title.string if soup.title else 'No title available'

        # Check for suspicious keywords in the website's HTML (security-related)
        suspicious_keywords = ['eval(', 'document.write', 'base64']
        found_issues = [kw for kw in suspicious_keywords if kw in response.text]

        # Check if there were any issues (status code, load time, security alerts)
        alert = False
        if found_issues or response.status_code != 200 or load_time > 3:
            alert = True

        return {
            'url': url,
            'title': title,
            'status_code': response.status_code,
            'load_time': load_time,
            'security_alerts': found_issues,
            'alert': alert
        }
    except requests.exceptions.Timeout:
        return {'url': url, 'error': 'Timeout occurred'}
    except requests.exceptions.RequestException as e:
        return {'url': url, 'error': str(e)}
