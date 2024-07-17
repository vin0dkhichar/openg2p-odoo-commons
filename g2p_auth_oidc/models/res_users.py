import json
import logging

import requests
import werkzeug.http
from jose import jwt

from odoo import api, models
from odoo.exceptions import AccessDenied, UserError

from odoo.addons.auth_signup.models.res_users import SignupError

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"

    @api.model
    def auth_oauth(self, provider, params):
        oauth_provider = self.env["auth.oauth.provider"].sudo().browse(provider)

        if not oauth_provider.flow.startswith("oidc"):
            return super().auth_oauth(provider, params)

        access_token, id_token = oauth_provider.oidc_get_tokens(params)
        if not access_token:
            _logger.error("No access_token in response.")
            raise AccessDenied()
        if not id_token:
            _logger.error("No id_token in response.")
            # Not exiting when there is no ID Token.
            # raise AccessDenied()
        oauth_provider.verify_access_token(access_token)
        if id_token:
            oauth_provider.verify_id_token(id_token, access_token)

        validation = oauth_provider.oidc_get_validation_dict(
            id_token, access_token, params
        )

        login = self._auth_oauth_signin(provider, validation, params)
        if not login:
            raise AccessDenied()
        return (self.env.cr.dbname, login, access_token)

    @api.model
    def _auth_oauth_signin(self, provider, validation, params):
        oauth_uid = validation["user_id"]
        try:
            oauth_user = self.search(
                [("oauth_uid", "=", oauth_uid), ("oauth_provider_id", "=", provider)]
            )
            if not oauth_user:
                raise AccessDenied()
            assert len(oauth_user) == 1
            # TODO: Handle data updates
            # TODO: Handle role updates
            oauth_user.write({"oauth_access_token": params["access_token"]})
            return oauth_user.login
        except AccessDenied as access_denied_exception:
            if self.env.context.get("no_user_creation"):
                return None
            state = json.loads(params["state"])
            token = state.get("t")
            values = self._generate_signup_values(provider, validation, params)
            try:
                login, _ = self.signup(values, token)
                return login
            except (SignupError, UserError) as e:
                raise access_denied_exception from e

    def _auth_oauth_rpc(self, endpoint, access_token):
        # This method is recreated to suit that application/jwt response type
        if (
            self.env["ir.config_parameter"]
            .sudo()
            .get_param("auth_oauth.authorization_header")
        ):
            response = requests.get(
                endpoint,
                headers={"Authorization": "Bearer %s" % access_token},
                timeout=10,
            )
        else:
            response = requests.get(
                endpoint, params={"access_token": access_token}, timeout=10
            )

        if response.ok:  # nb: could be a successful failure
            if response.headers.get("content-type"):
                if "application/jwt" in response.headers["content-type"]:
                    # TODO: Improve the following
                    return jwt.get_unverified_claims(response.text)
                if "application/json" in response.headers["content-type"]:
                    return response.json()
        auth_challenge = werkzeug.http.parse_www_authenticate_header(
            response.headers.get("WWW-Authenticate")
        )
        if auth_challenge.type == "bearer" and "error" in auth_challenge:
            return dict(auth_challenge)

        return {"error": "invalid_request"}

    @api.model
    def _generate_signup_values(self, provider, validation, params):
        oauth_provider = self.env["auth.oauth.provider"].sudo().browse(provider)

        oauth_provider.oidc_signup_process_email(validation)
        oauth_provider.oidc_signup_process_login(validation)

        oauth_uid = validation["user_id"]
        login = validation["login"]

        partner = oauth_provider.oidc_signup_find_existing_partner(validation)
        if partner:
            validation = {
                "login": login,
                "partner_id": partner.id,
                "oauth_provider_id": provider,
                "oauth_uid": oauth_uid,
                "oauth_access_token": params["access_token"],
                "active": True,
            }
            return validation

        oauth_provider.oidc_signup_process_name(validation)
        oauth_provider.oidc_signup_process_gender(validation)
        oauth_provider.oidc_signup_process_birthdate(validation)
        oauth_provider.oidc_signup_process_phone(validation)
        oauth_provider.oidc_signup_process_picture(validation)
        oauth_provider.oidc_signup_process_other_fields(validation)

        validation.update(
            {
                "login": login,
                "oauth_provider_id": provider,
                "oauth_uid": oauth_uid,
                "oauth_access_token": params["access_token"],
                "active": True,
            }
        )
        return validation
