# Access to the web UI

The UI decides what your server blocks, so it must not be reachable from the internet without a login. Ports
published with `ports:` also bypass host firewalls such as UFW. That is why the container publishes no port and is
reached through the Docker network.

## Behind a reverse proxy with SSO (recommended)

1. Attach asn-blocker to a Docker network your proxy can reach and point a route with authentication at
   `http://asn-blocker:8080`.
2. Open the UI through that route and choose **Reverse proxy with SSO** during setup.
   - **Trusted proxies** is filled in with the proxy the request came from, by container name where Docker knows it
     (for example `gerbil.pangolin`). A name keeps working when the proxy container is recreated with a new IP.
     Every trusted address may send any username, so never trust a whole shared Docker network.
   - **Header with username** is the header your proxy sets after login. It must be one the proxy always removes
     from incoming requests: `Remote-User` for Pangolin (Badger 1.2.1 or newer), or the user header from
     `authResponseHeaders` for Authentik or Authelia forward auth (`X-authentik-username`, `Remote-User`).

Setup checks that the current request meets both conditions, so a typo cannot lock you out. Requests carrying the
username header twice are rejected. Don't add bypass rules without authentication for this route.

The UI keeps one long-lived request per open tab for live updates (`/api/events`). nginx honours the
`X-Accel-Buffering: no` header the app sends; Traefik and Pangolin need no setting.

If sign-in fails, the **No access** page shows the address the request came from and the headers it received.
Trust a proxy again with:

```bash
docker exec asn-blocker python -m app.cli trust-proxy gerbil            # container name, IP or CIDR
docker exec asn-blocker python -m app.cli untrust-proxy 172.18.0.11/32  # remove an old entry
```

## Built-in login

Without an SSO proxy, choose **Built-in login**: a username and a password of at least 12 characters. Sessions last
12 hours, and sign-in is throttled after 5 failed attempts. Put a TLS-terminating proxy in front of it anyway.

## SSH tunnel for a first test

Publish the port on localhost only:

```yaml
    ports: ["127.0.0.1:18080:8080"]
```

```bash
ssh -L 18080:127.0.0.1:18080 user@your-server   # then open http://localhost:18080
```

Choose **Built-in login** in this case. Proxy mode can only be set up through the proxy itself.

## Network isolation

asn-blocker only needs to reach the CrowdSec LAPI and to be reached by your proxy. If your proxy network also hosts
other services, use two dedicated networks instead:

```bash
docker network create asnb-proxy && docker network connect asnb-proxy <proxy-container>
docker network create asnb-lapi  && docker network connect asnb-lapi crowdsec
```

Attach asn-blocker to both (`external: true`) and run the `connect` commands again when those containers are
recreated.

If the LAPI cannot be reached at all, asn-blocker can run `cscli` in the CrowdSec container through the Docker socket
instead (**Settings → CrowdSec connection**). Mounting `/var/run/docker.sock` gives anyone who controls the app root
on the host, so use the LAPI whenever possible.
