import base64
import hashlib
import json
import logging
import secrets

from werkzeug.urls import url_encode, url_quote_plus

from odoo.http import request

from odoo.addons.auth_oauth.controllers.main import OAuthLogin

_logger = logging.getLogger(__name__)


class OpenIDLogin(OAuthLogin):
    def list_providers(
        self,
        domain=(("enabled", "=", True),),
        redirect=None,
        base_url=None,
        oidc_redirect_uri="/auth_oauth/signin",
        db_name=None,
    ):
        if base_url is None:
            base_url = request.httprequest.url_root.rstrip("/")
        if db_name is None:
            db_name = request.session.db
        if redirect is None:
            redirect = request.params.get("redirect") or "/web"
        if not redirect.startswith(("//", "http://", "https://")):
            redirect = base_url + redirect
        if not oidc_redirect_uri.startswith(("//", "http://", "https://")):
            oidc_redirect_uri = base_url + oidc_redirect_uri

        providers = request.env["auth.oauth.provider"].sudo().search_read(domain)
        for provider in providers:
            state = dict(d=db_name, p=provider["id"], r=url_quote_plus(redirect))
            params = dict(
                response_type=self.oidc_get_response_type(provider),
                client_id=provider["client_id"],
                redirect_uri=oidc_redirect_uri,
                scope=provider["scope"],
                state=json.dumps(state, separators=(",", ":")),
            )
            flow = provider.get("flow")
            if flow in ("id_token", "auth_code"):
                params.update(
                    dict(
                        nonce=secrets.token_urlsafe(),
                        code_challenge=base64.urlsafe_b64encode(
                            hashlib.sha256(
                                provider["code_verifier"].encode("ascii")
                            ).digest()
                        ).rstrip(b"="),
                        code_challenge_method="S256",
                    )
                )
            extra_auth_params = json.loads(
                provider.get("extra_authorize_params") or "{}"
            )
            params.update(extra_auth_params)
            provider["auth_link"] = f"{provider['auth_endpoint']}?{url_encode(params)}"
        return providers

    def oidc_get_response_type(self, provider):
        return (
            request.env["auth.oauth.provider"]
            .sudo()
            .browse(provider["id"])
            .oidc_get_response_type()
        )
