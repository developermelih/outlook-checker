import requests
import json
import re
from urllib.parse import urlparse, parse_qs, urlencode, quote
import hashlib
import base64
import secrets

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

class OutlookLogin:
    def __init__(self, email):
        self.email = email
        self.session = requests.Session()
        
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Upgrade-Insecure-Requests': '1',
            'sec-ch-ua': '"Not(A:Brand";v="8", "Chromium";v="144", "Google Chrome";v="144"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
        })
        
        self.client_id = '9199bf20-a13f-4107-85dc-02114787ef48'
        self.redirect_uri = 'https://outlook.live.com/mail/'
        self.scope = 'https://outlook.office.com/.default openid profile offline_access'
        self.cobrandid = 'ab0455a0-8d03-46b9-b18b-df2f57b9e44c'
        
        self.flow_token = None
        self.original_request = None
        self.canary = None
        
    def generate_code_verifier(self):
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
    
    def generate_code_challenge(self, verifier):
        sha256 = hashlib.sha256(verifier.encode('utf-8')).digest()
        return base64.urlsafe_b64encode(sha256).decode('utf-8').rstrip('=')
    
    def generate_nonce(self):
        return secrets.token_urlsafe(16)
    
    def extract_flow_token_from_html(self, html):
        flow_token_patterns = [
            r'flowToken["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'name=["\']flowToken["\']\s+value=["\']([^"\']+)["\']',
            r'<input[^>]*name=["\']flowToken["\'][^>]*value=["\']([^"\']+)["\']',
        ]
        
        for pattern in flow_token_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        if HAS_BS4:
            try:
                soup = BeautifulSoup(html, 'html.parser')
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string:
                        match = re.search(r'flowToken["\']?\s*[:=]\s*["\']([^"\']+)["\']', script.string)
                        if match:
                            return match.group(1)
                
                flow_input = soup.find('input', {'name': 'flowToken'})
                if flow_input and flow_input.get('value'):
                    return flow_input['value']
            except:
                pass
        
        return None
    
    def extract_original_request_from_html(self, html):
        patterns = [
            r'originalRequest["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'name=["\']originalRequest["\']\s+value=["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        if HAS_BS4:
            try:
                soup = BeautifulSoup(html, 'html.parser')
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string:
                        match = re.search(r'originalRequest["\']?\s*[:=]\s*["\']([^"\']+)["\']', script.string)
                        if match:
                            return match.group(1)
            except:
                pass
        
        return None
    
    def extract_canary_from_html(self, html):
        patterns = [
            r'canary["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            r'name=["\']canary["\']\s+value=["\']([^"\']+)["\']',
            r'<input[^>]*name=["\']canary["\'][^>]*value=["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1)
        
        if HAS_BS4:
            try:
                soup = BeautifulSoup(html, 'html.parser')
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string:
                        match = re.search(r'canary["\']?\s*[:=]\s*["\']([^"\']+)["\']', script.string)
                        if match:
                            return match.group(1)
                
                canary_input = soup.find('input', {'name': 'canary'})
                if canary_input and canary_input.get('value'):
                    return canary_input['value']
            except:
                pass
        
        return None
    
    def step1_oauth_authorize(self):
        code_verifier = self.generate_code_verifier()
        code_challenge = self.generate_code_challenge(code_verifier)
        nonce = self.generate_nonce()
        
        state_data = {
            "id": nonce,
            "meta": {"interactionType": "redirect"}
        }
        state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode().rstrip('=')
        
        params = {
            'client_id': self.client_id,
            'scope': self.scope,
            'redirect_uri': self.redirect_uri,
            'response_type': 'code',
            'response_mode': 'fragment',
            'client_info': '1',
            'prompt': 'select_account',
            'nonce': nonce,
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_method': 'S256',
            'cobrandid': self.cobrandid,
            'fl': 'dob,flname,wld',
            'claims': json.dumps({
                "access_token": {
                    "xms_cc": {
                        "values": ["CP1"]
                    }
                }
            })
        }
        
        url = 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize'
        
        response = self.session.get(url, params=params, allow_redirects=False)
        
        if response.status_code == 200:
            html = response.text
            self.flow_token = self.extract_flow_token_from_html(html)
            self.original_request = self.extract_original_request_from_html(html)
            self.canary = self.extract_canary_from_html(html)
        
        return response, code_verifier
    
    def step2_get_credential_type(self):
        if not self.canary:
            raise ValueError("Canary değeri step1_oauth_authorize aşamasında çekilemedi. İşlem devam edemez.")
        
        url = 'https://login.microsoftonline.com/common/GetCredentialType?mkt=tr-TR'
        
        headers = {
            'accept': 'application/json',
            'content-type': 'application/json; charset=UTF-8',
            'canary': self.canary,
            'client-request-id': secrets.token_hex(16),
            'hpgact': '1800',
            'hpgid': '1104',
            'origin': 'https://login.microsoftonline.com',
            'referer': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        }
        
        original_request = self.original_request or ""
        flow_token = self.flow_token or ""
        
        payload = {
            "username": self.email,
            "isOtherIdpSupported": True,
            "checkPhones": False,
            "isRemoteNGCSupported": True,
            "isCookieBannerShown": False,
            "isFidoSupported": True,
            "originalRequest": original_request,
            "country": "TR",
            "forceotclogin": False,
            "isExternalFederationDisallowed": False,
            "isRemoteConnectSupported": False,
            "federationFlags": 0,
            "isSignup": False,
            "flowToken": flow_token,
            "isAccessPassSupported": True,
            "isQrCodePinSupported": True
        }
        
        response = self.session.post(url, json=payload, headers=headers)
        
        if response.status_code == 200:
            try:
                return response.json()
            except:
                return None
        
        return None
    
    def step3_login_live_oauth(self, oauth_params):
        url = 'https://login.live.com/oauth20_authorize.srf'
        
        oauth_params['username'] = self.email
        oauth_params['login_hint'] = self.email
        
        response = self.session.get(url, params=oauth_params, allow_redirects=False)
        
        return response
    
    def check_email(self):
        try:
            response, code_verifier = self.step1_oauth_authorize()
            
            credential_info = self.step2_get_credential_type()
            
            if credential_info:
                return credential_info
            
            location = response.headers.get('Location', '')
            if 'login.live.com' in location:
                parsed = urlparse(location)
                oauth_params = parse_qs(parsed.query)
                oauth_params_flat = {k: v[0] if isinstance(v, list) else v for k, v in oauth_params.items()}
                response = self.step3_login_live_oauth(oauth_params_flat)
            
            return response.json() if response and hasattr(response, 'json') else None
            
        except Exception as e:
            return {"error": str(e)}

if __name__ == "__main__":
    email = "example@outlook.com"
    
    login = OutlookLogin(email)
    result = login.check_email()

    if isinstance(result, dict) and "IfExistsResult" in result:
        if result["IfExistsResult"] == 5:
            print("Taranan Mail: " + email + " => Dolu")
        elif result["IfExistsResult"] == 1:
            print("Taranan Mail: " + email + " => Boş")
        else:
            print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))
