from pathlib import Path

import netauth
from buildbot.plugins import util
from buildbot.www import resource
from buildbot.www.avatar import AvatarBase
from buildbot.www.auth import UserInfoProviderBase, bytes2unicode, unicode2bytes
from twisted.internet import defer
from twisted.cred.error import UnauthorizedLogin

__version__ = "0.1.0"

__all__ = ["BuildbotNetAuth"]


class BuildbotNetAuth(util.CustomAuth, AvatarBase, UserInfoProviderBase):
    """
    NetAuth authentication, user info, and avatar provider

    :param conf: path to a NetAuth config file, optional
    :param domain: domain to use for email addresses (default: netauth server domain
        with one subdomain stripped, for example: ``netauth.example.com -> example.com``)
    :param kwargs: all other keyword arguments are passed to the NetAuth instance
    """

    name = "netauth"

    def __init__(self, *, conf: Path | None = None, domain: str | None = None, **kwargs):
        kwargs["service_name"] = "buildbot"

        if conf is not None:
            self.netauth = netauth.NetAuth.with_config(conf, **kwargs)
        else:
            self.netauth = netauth.NetAuth(**kwargs)

        if domain:
            self.domain = domain
        else:
            self.domain = ".".join(self.netauth.server.split(".")[1:])

        super().__init__(userInfoProvider=self)

    def requestAvatarId(self, cred):
        if self.check_credentials(cred.username, cred.password):
            return defer.succeed(cred.username + unicode2bytes(f"@{self.domain}"))
        return defer.fail(UnauthorizedLogin())

    def check_credentials(self, username: str, password: str) -> bool:
        try:
            self.netauth.auth_entity(username, password)
            return True
        except netauth.error.UnauthenticatedError:
            return False

    def getUserInfo(self, username):
        username = bytes2unicode(username)

        if not username:
            return defer.fail(ValueError("username not found"))

        username = username.removesuffix(f"@{self.domain}")

        try:
            entity = self.netauth.entity_info(username)

            if entity is None:
                return defer.fail(ValueError("entity not found"))

            id = entity.id
            email = f"{id}@{self.domain}"
            if (meta := entity.meta) is not None:
                full_name = meta.display_name or meta.legal_name or id
                groups = meta.groups or []
            else:
                full_name = entity.id
                groups = []

            return defer.succeed(
                {
                    "email": email,
                    "full_name": full_name,
                    "groups": groups,
                }
            )
        except netauth.error.NetAuthRpcError as e:
            return defer.fail(e)

    def getUserAvatar(self, email, username, size, defaultAvatarUrl):
        username = bytes2unicode(username)
        if username and username.endswith(f"@{self.domain}"):
            username = username.removesuffix(f"@{self.domain}")
            try:
                kv = self.netauth.entity_kv_get(username, "avatar")
                avatar = kv.get("avatar")
                if avatar:
                    raise resource.Redirect(avatar[0])
            except netauth.error.NetAuthRpcError:
                pass
