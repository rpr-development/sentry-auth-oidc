from __future__ import annotations

from collections.abc import Callable

from django.http import HttpRequest

import time

import requests
from sentry.auth.exceptions import IdentityNotValid
from sentry.auth.provider import MigratingIdentityId
from sentry.auth.providers.oauth2 import OAuth2Callback, OAuth2Login, OAuth2Provider
from sentry.auth.services.auth.model import RpcAuthProvider
from sentry.organizations.services.organization.model import RpcOrganization
from sentry.plugins.base.response import DeferredResponse

from .constants import (
    AUTHORIZATION_ENDPOINT,
    CLIENT_ID,
    CLIENT_SECRET,
    DATA_VERSION,
    ISSUER,
    SCOPE,
    TOKEN_ENDPOINT,
    USERINFO_ENDPOINT,
)
from .views import FetchUser, oidc_configure_view


class OIDCLogin(OAuth2Login):
    authorize_url = AUTHORIZATION_ENDPOINT
    client_id = CLIENT_ID
    scope = SCOPE

    def __init__(self, client_id, domains=None, authorize_url=None, scope=None):
        self.domains = domains
        if authorize_url:
            self.authorize_url = authorize_url
        if scope:
            self.scope = scope
        super().__init__(client_id=client_id)

    def get_authorize_params(self, state, redirect_uri):
        params = super().get_authorize_params(state, redirect_uri)
        # TODO(dcramer): ideally we could look at the current resulting state
        # when an existing auth happens, and if they're missing a refresh_token
        # we should re-prompt them a second time with ``approval_prompt=force``
        params["approval_prompt"] = "force"
        params["access_type"] = "offline"
        return params


class OIDCProvider(OAuth2Provider):
    name = ISSUER
    key = "oidc"

    def __init__(self, domain=None, domains=None, version=None, role_attribute_path=None, role_strict_mode=False, sso_client_id=None, sso_client_secret=None, sso_authorization_endpoint=None, sso_token_endpoint=None, sso_userinfo_endpoint=None, sso_scope=None, **config):
        if domain:
            if domains:
                domains.append(domain)
            else:
                domains = [domain]
        self.domains = domains
        # if a domain is not configured this is part of the setup pipeline
        # this is a bit complex in Sentry's SSO implementation as we don't
        # provide a great way to get initial state for new setup pipelines
        # vs missing state in case of migrations.
        if domains is None:
            version = DATA_VERSION
        else:
            version = None
        self.version = version
        # JMESPath expression to determine the Sentry role from the userinfo response.
        # Example: contains(permissions, 'sentry.admin') && 'admin' || contains(permissions, 'sentry.member') && 'member'
        self.role_attribute_path = role_attribute_path or ""
        # If strict mode is enabled, login is denied when the expression yields no valid role
        self.role_strict_mode = bool(role_strict_mode)
        # OIDC connection settings — DB config takes priority over sentry.conf.py constants
        self.sso_client_id = sso_client_id or None
        self.sso_client_secret = sso_client_secret or None
        self.sso_authorization_endpoint = sso_authorization_endpoint or None
        self.sso_token_endpoint = sso_token_endpoint or None
        self.sso_userinfo_endpoint = sso_userinfo_endpoint or None
        self.sso_scope = sso_scope or None
        super().__init__(**config)

    def get_client_id(self):
        return self.sso_client_id or CLIENT_ID

    def get_client_secret(self):
        return self.sso_client_secret or CLIENT_SECRET

    def get_configure_view(
        self,
    ) -> Callable[[HttpRequest, RpcOrganization, RpcAuthProvider], DeferredResponse]:
        return oidc_configure_view

    def get_auth_pipeline(self):
        return [
            OIDCLogin(
                domains=self.domains,
                client_id=self.get_client_id(),
                authorize_url=self.sso_authorization_endpoint or AUTHORIZATION_ENDPOINT,
                scope=self.sso_scope or SCOPE,
            ),
            OAuth2Callback(
                access_token_url=self.sso_token_endpoint or TOKEN_ENDPOINT,
                client_id=self.get_client_id(),
                client_secret=self.get_client_secret(),
            ),
            FetchUser(domains=self.domains, version=self.version),
        ]

    def get_refresh_token_url(self):
        return self.sso_token_endpoint or TOKEN_ENDPOINT

    def build_config(self, state):
        return {
            "domains": [state["domain"]],
            "version": DATA_VERSION,
            # Access control & role mapping
            "role_attribute_path": self.role_attribute_path,
            "role_strict_mode": self.role_strict_mode,
            # Connection settings
            "sso_client_id": self.sso_client_id or "",
            "sso_client_secret": self.sso_client_secret or "",
            "sso_authorization_endpoint": self.sso_authorization_endpoint or "",
            "sso_token_endpoint": self.sso_token_endpoint or "",
            "sso_userinfo_endpoint": self.sso_userinfo_endpoint or "",
            "sso_scope": self.sso_scope or "",
        }

    def get_user_info(self, bearer_token):
        endpoint = self.sso_userinfo_endpoint or USERINFO_ENDPOINT
        bearer_auth = "Bearer " + bearer_token
        retry_codes = [429, 500, 502, 503, 504]
        for retry in range(10):
            if 10 < retry:
                return {}
            r = requests.get(
                endpoint + "?schema=openid",
                headers={"Authorization": bearer_auth},
                timeout=20.0,
            )
            if r.status_code in retry_codes:
                wait_time = 2**retry * 0.1
                time.sleep(wait_time)
                continue
            return r.json()

    def _evaluate_role(self, user_info):
        """
        Evaluates the JMESPath expression against the full userinfo response.

        The expression can use any field from userinfo, including
        'permissions' (list), 'groups' (list), 'email', etc.

        Example expression:
            contains(permissions, 'sentry.admin') && 'admin'
            || contains(permissions, 'sentry.member') && 'member'

        Valid Sentry roles: owner, manager, admin, member, contributor
        """
        if not self.role_attribute_path:
            return None

        import jmespath

        valid_roles = {"owner", "manager", "admin", "member", "contributor"}

        try:
            result = jmespath.search(self.role_attribute_path, user_info)
        except jmespath.exceptions.JMESPathError as e:
            logger.warning("Invalid role_attribute_path expression: %s — %s", self.role_attribute_path, e)
            return None

        if isinstance(result, str) and result in valid_roles:
            return result

        if result and not isinstance(result, str):
            logger.warning("role_attribute_path did not return a string: %r", result)

        return None

    def build_identity(self, state):
        data = state["data"]
        user_data = state["user"]

        bearer_token = data["access_token"]
        user_info = self.get_user_info(bearer_token)

        # Evaluate JMESPath expression to determine the Sentry role
        role = self._evaluate_role(user_info)

        # Strict mode: deny login if the expression yields no valid role
        if self.role_strict_mode and self.role_attribute_path and role is None:
            raise IdentityNotValid(
                "Login denied: no valid Sentry role found via role attribute path."
            )

        # XXX(epurkhiser): We initially were using the email as the id key.
        # This caused account dupes on domain changes. Migrate to the
        # account-unique sub key.
        user_id = MigratingIdentityId(id=user_data["sub"], legacy_id=user_data["email"])

        identity = {
            "id": user_id,
            "email": user_info.get("email"),
            "name": user_info.get("name"),
            "data": self.get_oauth_data(data),
            "email_verified": user_info.get("email_verified"),
        }

        if role:
            identity["role"] = role

        return identity
