# Notifications

asn-blocker sends a notification when a run fails, when the sanity check stops a run, when a watched IP would be
blocked, and when networks start to qualify under **Attackers** or are added as automatic rules. Each one links to
the run or page it is about.

Set it up under **Settings → Notifications** for [ntfy](https://ntfy.sh), [Gotify](https://gotify.net) or a JSON
webhook. **Send test** checks the values before they are saved; **Save** only works after a successful test.

Watched IPs (**Exemptions → Watched IPs**) are addresses that must stay reachable, such as your phone or a
monitoring service. They are checked after every run.

## ntfy with access control

For a self-hosted ntfy with `auth-default-access: deny-all`:

```bash
docker exec ntfy ntfy user add asn-blocker
docker exec ntfy ntfy access asn-blocker asn-blocker write-only   # user, topic, permission
docker exec ntfy ntfy token add asn-blocker                      # prints tk_…
docker exec ntfy ntfy access <your-user> asn-blocker read-only    # the account your phone subscribes with
```

In asn-blocker: URL `https://ntfy.example.com/asn-blocker`, format *ntfy*, access token `tk_…`. The token is sent as
`Authorization: Bearer`, is never shown again and is dropped if the URL is changed to another server. If ntfy is on
the same Docker network, use the internal address (`http://ntfy:80/asn-blocker`); a proxy route behind SSO would
reject the request.

## Gotify

URL `https://gotify.example.com/message`, the application token as access token.
