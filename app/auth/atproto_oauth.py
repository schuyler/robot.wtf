"""ATProto OAuth: PAR, DPoP, token exchange, refresh, revocation.

Adapted from bluesky-social/cookbook (CC-0).
"""

from urllib.parse import urlparse
from typing import Any, Tuple
import time
import json
from requests import Response
from authlib.jose import JsonWebKey
from authlib.common.security import generate_token
from authlib.jose import jwt
from authlib.oauth2.rfc7636 import create_s256_code_challenge
import urllib.request

from app.auth.atproto_security import is_safe_url, hardened_http, _ALLOW_HTTP_PDS


def is_valid_authserver_meta(obj: dict, url: str) -> bool:
    fetch_url = urlparse(url)
    issuer_url = urlparse(obj["issuer"])
    assert issuer_url.hostname == fetch_url.hostname
    if not _ALLOW_HTTP_PDS:
        assert issuer_url.scheme == "https"
        assert issuer_url.port is None
    assert issuer_url.path in ["", "/"]
    assert issuer_url.params == ""
    assert issuer_url.fragment == ""

    assert "code" in obj["response_types_supported"]
    assert "authorization_code" in obj["grant_types_supported"]
    assert "refresh_token" in obj["grant_types_supported"]
    assert "S256" in obj["code_challenge_methods_supported"]
    assert "none" in obj["token_endpoint_auth_methods_supported"]
    assert "private_key_jwt" in obj["token_endpoint_auth_methods_supported"]
    assert "ES256" in obj["token_endpoint_auth_signing_alg_values_supported"]
    assert "atproto" in obj["scopes_supported"]
    assert obj["authorization_response_iss_parameter_supported"] is True
    assert obj["pushed_authorization_request_endpoint"] is not None
    assert obj["require_pushed_authorization_requests"] is True
    assert "ES256" in obj["dpop_signing_alg_values_supported"]
    if "require_request_uri_registration" in obj:
        assert obj["require_request_uri_registration"] is True
    assert obj["client_id_metadata_document_supported"] is True

    return True


def resolve_pds_authserver(url: str) -> str:
    assert is_safe_url(url)
    with hardened_http.get_session() as sess:
        resp = sess.get(f"{url}/.well-known/oauth-protected-resource")
    resp.raise_for_status()
    assert resp.status_code == 200
    authserver_url = resp.json()["authorization_servers"][0]
    return authserver_url


def fetch_authserver_meta(url: str) -> dict:
    assert is_safe_url(url)
    with hardened_http.get_session() as sess:
        resp = sess.get(f"{url}/.well-known/oauth-authorization-server")
    resp.raise_for_status()

    authserver_meta = resp.json()
    assert is_valid_authserver_meta(authserver_meta, url)
    return authserver_meta


def client_assertion_jwt(
    client_id: str, authserver_url: str, client_secret_jwk: JsonWebKey
) -> str:
    client_assertion = jwt.encode(
        {"alg": "ES256", "kid": client_secret_jwk["kid"]},
        {
            "iss": client_id,
            "sub": client_id,
            "aud": authserver_url,
            "jti": generate_token(),
            "iat": int(time.time()),
            "exp": int(time.time()) + (1 * 60),
        },
        client_secret_jwk,
    ).decode("utf-8")
    return client_assertion


def authserver_dpop_jwt(
    method: str, url: str, nonce: str, dpop_private_jwk: JsonWebKey
) -> str:
    dpop_pub_jwk = json.loads(dpop_private_jwk.as_json(is_private=False))
    body = {
        "jti": generate_token(),
        "htm": method,
        "htu": url,
        "iat": int(time.time()),
        "exp": int(time.time()) + 30,
    }
    if nonce:
        body["nonce"] = nonce
    dpop_proof = jwt.encode(
        {"typ": "dpop+jwt", "alg": "ES256", "jwk": dpop_pub_jwk},
        body,
        dpop_private_jwk,
    ).decode("utf-8")
    return dpop_proof


def parse_www_authenticate(data: str) -> Tuple[str, dict]:
    scheme, _, params = data.partition(" ")
    items = urllib.request.parse_http_list(params)
    opts = urllib.request.parse_keqv_list(items)
    return scheme, opts


def is_use_dpop_nonce_error_response(resp: Response) -> bool:
    if resp.status_code not in [400, 401]:
        return False
    www_authenticate = resp.headers.get("WWW-Authenticate")
    if www_authenticate:
        try:
            scheme, params = parse_www_authenticate(www_authenticate)
            if scheme.lower() == "dpop" and params.get("error") == "use_dpop_nonce":
                return True
        except Exception:
            pass
    try:
        json_body = resp.json()
        if isinstance(json_body, dict) and json_body.get("error") == "use_dpop_nonce":
            return True
    except Exception:
        pass
    return False


def auth_server_post(
    authserver_url: str,
    client_id: str,
    client_secret_jwk: JsonWebKey,
    dpop_private_jwk: JsonWebKey,
    dpop_authserver_nonce: str,
    post_url: str,
    post_data: dict,
) -> Tuple[str, Response]:
    client_assertion = client_assertion_jwt(
        client_id, authserver_url, client_secret_jwk
    )
    post_data |= {
        "client_id": client_id,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": client_assertion,
    }

    dpop_proof = authserver_dpop_jwt(
        "POST", post_url, dpop_authserver_nonce, dpop_private_jwk
    )

    assert is_safe_url(post_url)
    with hardened_http.get_session() as sess:
        resp = sess.post(post_url, data=post_data, headers={"DPoP": dpop_proof})

    if is_use_dpop_nonce_error_response(resp):
        dpop_authserver_nonce = resp.headers["DPoP-Nonce"]
        print(f"retrying with new auth server DPoP nonce: {dpop_authserver_nonce}")
        dpop_proof = authserver_dpop_jwt(
            "POST", post_url, dpop_authserver_nonce, dpop_private_jwk
        )
        with hardened_http.get_session() as sess:
            resp = sess.post(post_url, data=post_data, headers={"DPoP": dpop_proof})

    return dpop_authserver_nonce, resp


def send_par_auth_request(
    authserver_url: str,
    authserver_meta: dict,
    login_hint: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    client_secret_jwk: JsonWebKey,
    dpop_private_jwk: JsonWebKey,
) -> Tuple[str, str, str, Any]:
    par_url = authserver_meta["pushed_authorization_request_endpoint"]
    state = generate_token()
    pkce_verifier = generate_token(48)

    code_challenge = create_s256_code_challenge(pkce_verifier)
    code_challenge_method = "S256"

    par_body = {
        "response_type": "code",
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "state": state,
        "redirect_uri": redirect_uri,
        "scope": scope,
    }
    if login_hint:
        par_body["login_hint"] = login_hint

    assert is_safe_url(par_url)
    dpop_authserver_nonce, resp = auth_server_post(
        authserver_url=authserver_url,
        client_id=client_id,
        client_secret_jwk=client_secret_jwk,
        dpop_private_jwk=dpop_private_jwk,
        dpop_authserver_nonce="",
        post_url=par_url,
        post_data=par_body,
    )

    return pkce_verifier, state, dpop_authserver_nonce, resp


def initial_token_request(
    auth_request: dict,
    code: str,
    client_id: str,
    redirect_uri: str,
    client_secret_jwk: JsonWebKey,
) -> Tuple[dict, str]:
    authserver_url = auth_request["authserver_iss"]

    authserver_meta = fetch_authserver_meta(authserver_url)

    params = {
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
        "code": code,
        "code_verifier": auth_request["pkce_verifier"],
    }

    token_url = authserver_meta["token_endpoint"]
    dpop_private_jwk = JsonWebKey.import_key(
        json.loads(auth_request["dpop_private_jwk"])
    )

    assert is_safe_url(token_url)
    dpop_authserver_nonce, resp = auth_server_post(
        authserver_url=authserver_url,
        client_id=client_id,
        client_secret_jwk=client_secret_jwk,
        dpop_private_jwk=dpop_private_jwk,
        dpop_authserver_nonce=auth_request["dpop_authserver_nonce"],
        post_url=token_url,
        post_data=params,
    )

    resp.raise_for_status()
    token_body = resp.json()

    return token_body, dpop_authserver_nonce


def refresh_token_request(
    user: dict,
    client_id: str,
    client_secret_jwk: JsonWebKey,
) -> Tuple[dict, str]:
    authserver_url = user["authserver_iss"]

    authserver_meta = fetch_authserver_meta(authserver_url)

    params = {
        "grant_type": "refresh_token",
        "refresh_token": user["refresh_token"],
    }

    token_url = authserver_meta["token_endpoint"]
    dpop_private_jwk = JsonWebKey.import_key(json.loads(user["dpop_private_jwk"]))
    dpop_authserver_nonce = user["dpop_authserver_nonce"]

    assert is_safe_url(token_url)
    dpop_authserver_nonce, resp = auth_server_post(
        authserver_url=authserver_url,
        client_id=client_id,
        client_secret_jwk=client_secret_jwk,
        dpop_private_jwk=dpop_private_jwk,
        dpop_authserver_nonce=dpop_authserver_nonce,
        post_url=token_url,
        post_data=params,
    )

    if resp.status_code not in [200, 201]:
        print(f"Token Refresh Error: {resp.json()}")

    resp.raise_for_status()
    token_body = resp.json()

    return token_body, dpop_authserver_nonce


def revoke_token_request(
    user: dict,
    client_id: str,
    client_secret_jwk: JsonWebKey,
):
    authserver_url = user["authserver_iss"]

    authserver_meta = fetch_authserver_meta(authserver_url)

    dpop_private_jwk = JsonWebKey.import_key(json.loads(user["dpop_private_jwk"]))
    dpop_authserver_nonce = user["dpop_authserver_nonce"]

    revoke_url = authserver_meta.get("revocation_endpoint")
    if not revoke_url:
        print("revocation_endpoint not in authserver_meta, doing nothing")
        return

    assert is_safe_url(revoke_url)
    for token_type in ["access_token", "refresh_token"]:
        dpop_authserver_nonce, resp = auth_server_post(
            authserver_url=authserver_url,
            client_id=client_id,
            client_secret_jwk=client_secret_jwk,
            dpop_private_jwk=dpop_private_jwk,
            dpop_authserver_nonce=dpop_authserver_nonce,
            post_url=revoke_url,
            post_data={
                "token": user[token_type],
                "token_type_hint": token_type,
            },
        )

        resp.raise_for_status()
