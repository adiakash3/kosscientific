import http.client as ht
import json
from kosscientific.settings import sms_credential
from django.conf import settings
import requests


def send_sms(message, mobile_number):
    """ send sms to given number """
    if settings.CAN_SEND_SMS:
        if not mobile_number:
            raise Exception('mobile number required')

        api = sms_credential.get('api')
        auth_key = sms_credential.get('auth_key')
        mobile_number = mobile_number
        message = message
        sender = sms_credential.get('sender')
        route = sms_credential.get('route')
        country = sms_credential.get('country')
        final_sms_api_format = '{}?authkey={}&mobiles={}&message={}&sender={}&route={}&country={}'.format(
            api, auth_key, mobile_number, message, sender, route, country
        )

        try:
            sms_response = requests.get(final_sms_api_format)
            return 'success', sms_response.text
        except Exception as e:
            raise Exception('{}'.format(e)) 
    else:
        raise Exception('sms function is disabled by admin')


def send_otp_sms(message, mobile_number, otp):
    """ send otp sms"""
    if settings.CAN_SEND_SMS:
        if not mobile_number:
            raise Exception('mobile number required')
        country = sms_credential.get('country')
        api = sms_credential.get('otp_api')
        auth_key = sms_credential.get('auth_key')
        mobile_number = str(country) + str(mobile_number)
        message = message
        sender = sms_credential.get('sender')
        otp_expiry = sms_credential.get('otp_expiry')

        final_otp_sms_api_format = '{}?authkey={}&mobiles={}&message={}&sender={}&otp={}&otp_expiry={}'.format(
            api, auth_key, int(mobile_number), message, sender, otp, otp_expiry
        )

        try:
            sms_response = requests.get(final_otp_sms_api_format)
            result = json.loads(sms_response.text)
            if result['type'] == 'error':
                raise Exception('{}'.format(result['message'])) 
            return 'success', result
        except Exception as e:
            return 'error', None
    else:
        raise Exception('sms function is disabled by admin')


def send_mass_sms(message, mobile_number_list):
    """
    send mass sms
    """
    if settings.CAN_SEND_SMS:
        if not mobile_number_list:
            raise Exception('mobile number required')

        API = "https://api.msg91.com/api/v2/sendsms"
        auth_key = sms_credential.get('auth_key')
        message = message
        sender = sms_credential.get('sender')
        route = sms_credential.get('route')
        country = sms_credential.get('country')

        body = {
            "sender": sender,
            "route": route,
            "country": country,
            "unicode": "0",
            "sms": [
                {
                    "message": message,
                    "to": mobile_number_list
                }
            ]
        }

        try:
            headers = {
                'authkey': auth_key,
                'content-type': "application/json"
            }
            sms_response = requests.post(API, data=json.dumps(body), headers=headers)
            return 'success', sms_response
        except Exception as e:
            return 'error', None
    else:
        raise Exception('sms function is disabled by admin')
