## buildbot-netauth

NetAuth authentication, user info, and avatar plugin for buildbot

### Usage

1. Install the plugin, for example: `pip install buildbot-netauth`

2. In your `buildmaster.cfg`, add:

```py
from buildbot.plugins import util

netauth = util.BuildbotNetAuth(conf=Path("/etc/netauth/config.toml"))

# in your buildmaster config object
c["www"]["auth"] = netauth
c["www"]["avatar_methods"] = [netauth, ...]
```

### Notes

The plugin looks at the following metadata on NetAuth entities:

- entity ID: used as an "email" in the format `entity_id@domain`. `domain` is the base domain of the NetAuth server, but is overridable.
- entity display name or legal name: if set, will be used for the `full_name` buildbot user property in that fallback order
- entity group membership: used for the `groups` buildbot user property and can be used for buildbot authz, for example:

```py
from buildbot.plugins import util

c["www"]["authz"] = util.Authz(
    allowRules=[
        util.AnyEndpointMatcher(role="ops", defaultDeny=False),
        util.AnyControlEndpointMatcher(role="ops"),
    ],
    roleMatchers=[
        util.RolesFromGroups(groupPrefix="build-"),
    ]
)
```
