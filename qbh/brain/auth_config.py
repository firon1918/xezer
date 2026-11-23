"""Credential references only; no raw passwords or session tokens in YAML."""
from copy import deepcopy
import re
from urllib.parse import urlsplit

ALLOWED = {'name', 'role', 'login_url', 'login_method', 'login_fields', 'login_format',
           'verify_url', 'subject_field', 'token_field', 'session_ttl_seconds',
           'refresh_url', 'refresh_method', 'refresh_token_field', 'refresh_format',
           'csrf_cookie', 'csrf_header',
           'totp_secret_env', 'totp_secret_vault_ref', 'totp_field',
           'totp_digits', 'totp_period', 'totp_algorithm'}


def origin(url):
    if not isinstance(url, str) or not url:
        raise ValueError("invalid_auth_url")
    parts = urlsplit(url)
    if parts.scheme not in {'http', 'https'} or not parts.hostname or parts.username or parts.password:
        raise ValueError('invalid_auth_url')
    try:
        port = parts.port or (443 if parts.scheme == 'https' else 80)
    except ValueError:
        raise ValueError('invalid_auth_url') from None
    return f'{parts.scheme}://{parts.hostname.lower()}:{port}'


def validate_contexts(value):
    if not isinstance(value, list):
        raise ValueError('auth_contexts_must_be_list')
    result, names = [], set()
    for item in value:
        if not isinstance(item, dict) or item.keys() - ALLOWED:
            raise ValueError('unsupported_auth_context_fields')
        item = deepcopy(item)
        for key in ('name', 'role'):
            if not isinstance(item.get(key), str) or not re.fullmatch(r'[A-Za-z0-9_.-]{1,80}', item[key]):
                raise ValueError('invalid_auth_context_name_or_role')
        if item['name'] in names:
            raise ValueError('duplicate_auth_context_name')
        names.add(item['name'])
        login_origin = origin(item.get('login_url', ''))
        item.setdefault('login_method', 'POST')
        if item['login_method'] not in {'GET', 'POST'}:
            raise ValueError('unsupported_login_method')
        fields = item.get('login_fields')
        if not isinstance(fields, dict) or not fields:
            raise ValueError('credential_references_required')
        field_names = set()
        for key, reference in fields.items():
            if not isinstance(key, str):
                raise ValueError('credential_reference_name_required')
            suffix = '_env' if key.endswith('_env') else '_vault_ref' if key.endswith('_vault_ref') else ''
            if not suffix:
                raise ValueError('inline_credentials_forbidden')
            name = key[:-len(suffix)]
            if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,79}', name) or name in field_names:
                raise ValueError('duplicate_or_invalid_login_field')
            field_names.add(name)
            if suffix == '_env' and (not isinstance(reference, str) or not re.fullmatch(r'[A-Z_][A-Z0-9_]*', reference)):
                raise ValueError('invalid_credential_env_reference')
            if suffix == '_vault_ref' and (type(reference) is not int or reference < 1):
                raise ValueError('invalid_credential_vault_reference')
        item.setdefault('login_format', 'json')
        if item['login_format'] not in {'json', 'form', 'basic'}:
            raise ValueError('invalid_login_format')
        if item['login_format'] == 'basic' and field_names != {'username', 'password'}:
            raise ValueError('basic_auth_requires_username_and_password_references')
        if item.get('verify_url') and origin(item['verify_url']) != login_origin:
            raise ValueError('verification_origin_must_match_login')
        item.setdefault('subject_field', 'user.id')
        item.setdefault('token_field', 'access_token')
        for key in ('subject_field', 'token_field'):
            if not isinstance(item[key], str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]{0,100}', item[key]):
                raise ValueError('invalid_auth_response_field')
        ttl = item.setdefault('session_ttl_seconds', 900)
        if type(ttl) is not int or ttl < 1 or ttl > 86400:
            raise ValueError('invalid_session_ttl')
        if item.get('refresh_url'):
            if origin(item['refresh_url']) != login_origin:
                raise ValueError('refresh_origin_must_match_login')
            item.setdefault('refresh_method', 'POST')
            if item['refresh_method'] not in {'GET', 'POST'}:
                raise ValueError('unsupported_refresh_method')
            item.setdefault('refresh_format', 'json')
            if item['refresh_format'] not in {'json', 'form'}:
                raise ValueError('invalid_refresh_format')
            item.setdefault('refresh_token_field', 'refresh_token')
            if not isinstance(item['refresh_token_field'], str) or not re.fullmatch(
                    r'[A-Za-z_][A-Za-z0-9_.]{0,100}', item['refresh_token_field']):
                raise ValueError('invalid_auth_response_field')
        elif any(k in item for k in ('refresh_method', 'refresh_format', 'refresh_token_field')):
            raise ValueError('refresh_options_require_refresh_url')
        if ('csrf_cookie' in item) != ('csrf_header' in item):
            raise ValueError('csrf_cookie_and_header_required_together')
        if 'csrf_cookie' in item:
            if not isinstance(item['csrf_cookie'], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', item['csrf_cookie']):
                raise ValueError('invalid_csrf_cookie_name')
            if not isinstance(item['csrf_header'], str) or not re.fullmatch(r'[A-Za-z0-9-]{1,80}', item['csrf_header']):
                raise ValueError('invalid_csrf_header_name')
        if ('totp_secret_env' in item) == ('totp_secret_vault_ref' in item):
            if 'totp_secret_env' in item or 'totp_secret_vault_ref' in item:
                raise ValueError('exactly_one_totp_secret_reference_required')
        if 'totp_secret_env' in item:
            reference = item['totp_secret_env']
            if not isinstance(reference, str) or not re.fullmatch(r'[A-Z_][A-Z0-9_]*', reference):
                raise ValueError('invalid_credential_env_reference')
        if 'totp_secret_vault_ref' in item:
            reference = item['totp_secret_vault_ref']
            if type(reference) is not int or reference < 1:
                raise ValueError('invalid_credential_vault_reference')
        if 'totp_secret_env' in item or 'totp_secret_vault_ref' in item:
            item.setdefault('totp_field', 'otp')
            if not isinstance(item['totp_field'], str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]{0,79}', item['totp_field']):
                raise ValueError('invalid_totp_field')
            digits = item.setdefault('totp_digits', 6)
            if type(digits) is not int or not 6 <= digits <= 8:
                raise ValueError('invalid_totp_digits')
            period = item.setdefault('totp_period', 30)
            if type(period) is not int or not 15 <= period <= 120:
                raise ValueError('invalid_totp_period')
            algorithm = item.setdefault('totp_algorithm', 'SHA1')
            if algorithm not in {'SHA1', 'SHA256', 'SHA512'}:
                raise ValueError('invalid_totp_algorithm')
        elif any(k in item for k in ('totp_field', 'totp_digits', 'totp_period', 'totp_algorithm')):
            raise ValueError('totp_options_require_secret_reference')
        result.append(item)
    return result
