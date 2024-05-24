#!/usr/bin/env python
# coding: utf-8
import base64
import re


def base64_url_decode_no_padding(input_string):
    # Add padding if necessary to make the length a multiple of 4
    padding_needed = len(input_string) % 4
    if padding_needed:
        input_string += "=" * (4 - padding_needed)
    
    # Decode Base64 URL-encoded string
    decoded_bytes = base64.urlsafe_b64decode(input_string)
    
    # Return decoded bytes
    return decoded_bytes


def base64_url_encode(data):
    # Convert the string to bytes
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Perform Base64 URL-safe encoding
    encoded_bytes = base64.urlsafe_b64encode(data)

    # Decode the bytes to UTF-8 and remove padding characters
    encoded_string = encoded_bytes.decode('utf-8').rstrip('=')

    return encoded_string


def extract_claims(payload):
    pat_sub = re.compile('"sub"\s*:\s*"[\w]+"\s*[,}]')
    pat_nonce = re.compile('"nonce"\s*:\s*"[\w]+"\s*[,}]')
    pat_expiry = re.compile('"exp"\s*:\s*\d+\s*[,}]')
    return {
        'sub': pat_sub.findall(payload)[0],
        'nonce': pat_nonce.findall(payload)[0],
        'exp': pat_expiry.findall(payload)[0],
    }


def to_b64_index(ind):
    # 1st byte: 6 bits go into 1st byte, 2 bits go into 2nd byte, OFFSET 0
    # 2nd byte: 4 bits go into 2nd byte, 4 bits go into 3rd byte, OFFSET 2
    # 3rd byte: 2 bits go into 3rd byte, 6 bits go into 4th byte, OFFSET 4
    whole, remainder = ind // 3, ind % 3
    return whole * 4 + remainder


def clean_value(raw_value):
    value = raw_value
    value = re.sub('[,}\s]*$', '', value)
    value = re.sub('^\s*', '', value)
    return value


def prepare_claim_args(payload, name):
    claims = extract_claims(payload)
    claim = claims[name]
    index_in_payload = payload.index(claim)
    index_b64 = to_b64_index(index_in_payload)
    end_64 = to_b64_index(index_in_payload + len(claim) + 1)
    claim_name, claim_value = claim.split(':')
    claim_name = clean_value(claim_name)
    claim_value = clean_value(claim_value)
    return {
        name + '_claim': claim,
        name + '_claim_length': len(claim),
        name + '_index_b64': index_b64,
        name + '_length_b64': end_64 - index_b64,
        name + '_name_length': len(claim_name),
        name + '_colon_index': claim.index(':'),
        name + '_value_index': claim.index(claim_value),
        name + '_value_length': len(claim_value),
    }



def parse_jwt(jwt):
    header_b64, payload_b64, signature_b64 = jwt.split('.')
    payload_start_index = len(header_b64) + 1
    payload = base64_url_decode_no_padding(payload_b64).decode('utf-8')
    return {
        'payload_start_index': payload_start_index,
        **prepare_claim_args(payload, 'sub'),
        **prepare_claim_args(payload, 'nonce'),
        **prepare_claim_args(payload, 'exp'),
    }



jwt = "<your-test-jwt>"


print(parse_jwt(jwt))
