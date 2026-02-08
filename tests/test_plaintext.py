"""
test_plaintext.py
Simulate cleartext credential transmission.
"""

import requests
from requests.auth import HTTPBasicAuth


def test_http_basic_auth():
    """
    Send HTTP request with Basic Auth to trigger detection.
    """
    try:
        # This will transmit credentials in base64 (still cleartext)
        response = requests.get(
            "http://httpbin.org/basic-auth/user/password",
            auth=HTTPBasicAuth('testuser', 'testpassword123'),
            timeout=5
        )
        print(f"Request sent. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed (may still trigger detection): {e}")


def test_form_post():
    """
    Send HTTP form with password field.
    """
    try:
        response = requests.post(
            "http://httpbin.org/post",
            data={"username": "admin", "password": "secret123"},
            timeout=5
        )
        print(f"Form POST sent. Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Request failed (may still trigger detection): {e}")


if __name__ == "__main__":
    print("Sending HTTP Basic Auth request...")
    test_http_basic_auth()
    
    print("\nSending HTTP Form POST with password...")
    test_form_post()
