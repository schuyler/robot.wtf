#!/usr/bin/env python3
"""Generate ATProto OAuth confidential client JWK pair."""
import json
import secrets

from authlib.jose import JsonWebKey

key = JsonWebKey.generate_key("EC", "P-256", is_private=True)
kid = secrets.token_urlsafe(8)

priv = key.as_dict(is_private=True)
priv.update({"kid": kid, "use": "sig", "alg": "ES256"})

pub = key.as_dict(is_private=False)
pub.update({"kid": kid, "use": "sig", "alg": "ES256"})

with open("/srv/data/client_jwk.json", "w") as f:
    json.dump(priv, f, indent=2)
with open("/srv/data/client_jwk_pub.json", "w") as f:
    json.dump(pub, f, indent=2)
