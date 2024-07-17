import base64
import json
import secrets
from datetime import datetime, timedelta, timezone
from urllib.request import urlopen

import requests
from jose import jwt

from odoo import api, fields, models, tools
from odoo.http import request


class AuthOauthProvider(models.Model):
    _inherit = "auth.oauth.provider"

    flow = fields.Selection(
        [
            ("oauth2", "OAuth2"),
            ("oidc_implicit", "OpenID Connect (implicit flow)"),
            ("oidc_auth_code", "OpenID Connect (authorization code flow)"),
        ],
        string="Auth Flow",
        required=True,
        default="access_token",
    )

    validation_endpoint = fields.Char(required=False)
    token_endpoint = fields.Char()
    jwks_uri = fields.Char("JWKS URL")
    jwt_assertion_aud = fields.Char(
        "Client Assertion JWT Aud Claim",
        help="Leave blank to use token endpoint for Client Assertion Aud.",
    )

    client_authentication_method = fields.Selection(
        [
            ("client_secret_basic", "Client Secret (Basic)"),
            ("client_secret_post", "Client Secret (Post)"),
            # ("client_secret_jwt", "Signed Client Secret (JWT)"), # Not implemented
            ("private_key_jwt", "Private Key JWT"),
            ("none", "None"),
        ],
        required=True,
        default="client_secret_post",
    )
    client_secret = fields.Char()
    client_private_key = fields.Binary(attachment=False)

    code_verifier = fields.Char(
        "PKCE Code Verifier", default=lambda self: secrets.token_urlsafe(32)
    )

    token_map = fields.Char(
        default=(
            "sub:user_id "
            "name:name "
            "email:email "
            "phone_number:phone "
            "birthdate:birthdate "
            "gender:gender "
            "address:address "
            "picture:picture"
        )
    )

    extra_authorize_params = fields.Text(
        help="Extra Parameters to be passed to Auth endpoint. "
        'To be given as JSON. Example: {"param":"value"}',
    )

    verify_at_hash = fields.Boolean(default=True)

    date_format = fields.Char(
        help="Format to be used to parse dates returned by this OIDC Provider",
        default="%Y/%m/%d",
    )

    def oidc_get_tokens(self, params):
        self.ensure_one()
        if self.flow == "oidc_auth_code":
            return self._oidc_get_tokens_auth_code_flow(params)
        elif self.flow == "oidc_implicit":
            return self._oidc_get_tokens_implicit_flow(params)
        else:
            # TBD
            return (None, None)

    def _oidc_get_tokens_implicit_flow(self, params):
        return params.get("access_token"), params.get("id_token")

    def _oidc_get_tokens_auth_code_flow(self, params, oidc_redirect_uri=None):
        code = params.get("code")
        if not oidc_redirect_uri:
            oidc_redirect_uri = request.httprequest.base_url

        if self.client_authentication_method == "none":
            token_request_data = dict(
                client_id=self.client_id,
                grant_type="authorization_code",
                code=code,
                code_verifier=self.code_verifier,
                redirect_uri=oidc_redirect_uri,
            )
            response = requests.post(
                self.token_endpoint, data=token_request_data, timeout=10
            )
            response.raise_for_status()
            response_json = response.json()
            return response_json.get("access_token"), response_json.get("id_token")
        if self.client_authentication_method == "client_secret_basic":
            token_request_auth = (self.client_id, self.client_secret)
            token_request_data = dict(
                client_id=self.client_id,
                grant_type="authorization_code",
                code=code,
                code_verifier=self.code_verifier,
                redirect_uri=oidc_redirect_uri,
            )
            response = requests.post(
                self.token_endpoint,
                auth=token_request_auth,
                data=token_request_data,
                timeout=10,
            )
            response.raise_for_status()
            response_json = response.json()
            return response_json.get("access_token"), response_json.get("id_token")
        if self.client_authentication_method == "client_secret_post":
            token_request_data = dict(
                client_id=self.client_id,
                client_secret=self.client_secret,
                grant_type="authorization_code",
                code=code,
                code_verifier=self.code_verifier,
                redirect_uri=oidc_redirect_uri,
            )
            response = requests.post(
                self.token_endpoint, data=token_request_data, timeout=10
            )
            response.raise_for_status()
            response_json = response.json()
            return response_json.get("access_token"), response_json.get("id_token")
        if self.client_authentication_method == "private_key_jwt":
            private_key_jwt = self.create_private_key_jwt()
            token_request_data = dict(
                client_id=self.client_id,
                client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                client_assertion=private_key_jwt,
                grant_type="authorization_code",
                code=code,
                code_verifier=self.code_verifier,
                redirect_uri=oidc_redirect_uri,
            )
            response = requests.post(
                self.token_endpoint, data=token_request_data, timeout=10
            )
            response.raise_for_status()
            response_json = response.json()
            return response_json.get("access_token"), response_json.get("id_token")
        return None

    def create_private_key_jwt(self):
        secret = base64.b64decode(self.with_context(bin_size=False).client_private_key)
        token = jwt.encode(
            {
                "iss": self.client_id,
                "sub": self.client_id,
                "aud": self.jwt_assertion_aud or self.token_endpoint,
                "exp": datetime.now(timezone.utc) + timedelta(hours=1),
                "iat": datetime.now(timezone.utc),
            },
            secret,
            algorithm="RS256",
        )
        return token

    @tools.ormcache("self.jwks_uri")
    def oidc_get_jwks(self):
        r = requests.get(self.jwks_uri, timeout=10)
        r.raise_for_status()
        response = r.json()
        return response

    def oidc_get_response_type(self):
        self.ensure_one()
        if self.flow == "oidc_auth_code":
            return "code"
        elif self.flow == "oidc_implicit":
            return "id_token token"
        else:
            return "token"

    def oidc_get_validation_dict(self, access_token, id_token, params):
        self.ensure_one()
        validation = self.env["res.users"]._auth_oauth_validate(self.id, access_token)
        validation = self.combine_tokens(access_token, id_token, validation)
        validation = self.map_validation_values(validation)
        return validation

    @api.model
    def combine_token_dicts(self, *token_dicts) -> dict:
        res = None
        for token_dict in token_dicts:
            if token_dict:
                if not res:
                    res = token_dict
                else:
                    res.update(token_dict)
        return res

    @api.model
    def combine_tokens(self, *tokens) -> dict:
        return self.combine_token_dicts(
            *[
                jwt.get_unverified_claims(token) if isinstance(token, str) else token
                for token in tokens
                if token
            ]
        )

    def verify_access_token(self, access_token):
        self.ensure_one()
        jwt.decode(
            access_token,
            self.oidc_get_jwks(),
        )
        return access_token

    def verify_id_token(self, id_token, access_token):
        self.ensure_one()
        jwt.decode(
            id_token,
            self.oidc_get_jwks(),
            audience=self.client_id,
            access_token=access_token,
            options={"verify_at_hash": self.verify_at_hash},
        )
        return id_token

    def map_validation_values(self, validation):
        res = {}
        if self.token_map and self.token_map.strip():
            if self.token_map.endswith("*:*"):
                res = validation
            for pair in self.token_map.strip().split(" "):
                if pair:
                    from_key, to_key = (k.strip() for k in pair.split(":", 1))
                    res[to_key] = validation.get(from_key, "")
        return res

    def oidc_signup_find_existing_partner(self, validation):
        """
        Should return partner object if already exists.
        Supposed to be overriden by child classes.
        """
        return None

    def oidc_signup_process_login(self, validation):
        oauth_uid = validation["user_id"]
        if "login" not in validation:
            validation["login"] = validation.get(
                "email", f"provider_{self.id}_user_{oauth_uid}"
            )

    def oidc_signup_process_name(self, validation):
        if "name" not in validation:
            validation["name"] = validation.get("email")

    def oidc_signup_process_gender(self, validation):
        gender = validation.get("gender", "").capitalize()
        if gender:
            validation["gender"] = gender

    def oidc_signup_process_birthdate(self, validation):
        if validation.get("birthdate"):
            validation["birthdate"] = datetime.strptime(
                validation["birthdate"], self.date_format
            ).date()

    def oidc_signup_process_email(self, validation):
        if "email" not in validation:
            validation["email"] = None

    def oidc_signup_process_phone(self, validation):
        pass

    def oidc_signup_process_picture(self, validation):
        picture = validation.pop("picture", None)
        if picture:
            with urlopen(picture, timeout=20) as response:
                validation["image_1920"] = base64.b64encode(response.read())

    def oidc_signup_process_other_fields(self, validation):
        for key, value in validation.items():
            if key in self.env["res.partner"]._fields:
                if isinstance(value, dict) or isinstance(value, list):
                    validation[key] = json.dumps(value)
            else:
                validation.pop(key)
