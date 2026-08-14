# North-South

**Platform:** CyLab Security Academy (picoCTF)
**Category:** Web Exploitation
**Difficulty:** Medium
**Flag:** `picoCTF{g30_b453d_r0u71n9_90cabc04}`

## Summary

The challenge provides its full Nginx configuration, which routes requests based on the
requester's country as determined by the `ngx_http_geoip2_module` against a MaxMind
GeoLite2-Country database. Only requests whose source IP resolves to Iceland (`IS`) reach the
upstream holding the flag; everyone else gets a decoy response. Since the geoip2 lookup is bound
to the real client IP with no reverse-proxy trust configured, header spoofing (`X-Forwarded-For`,
etc.) has no effect. The only way to satisfy the check is to actually originate the request from
an IP that genuinely geolocates to Iceland, which a Tor circuit restricted to an Icelandic exit
relay provides for free.

## Discovery

The relevant nginx config:

```nginx
geoip2 /etc/nginx/GeoLite2-Country.mmdb {
    auto_reload 5m;
    $geoip2_data_country_code default=ZZ country iso_code;
}

upstream north { server 127.0.0.1:8000; }
upstream south { server 127.0.0.1:9000; }

server {
    listen 80;
    location / {
        if ($geoip2_data_country_code = IS) {
            proxy_pass http://south;
        }
        proxy_pass http://north;
    }
}
```

No `$variable` argument is given to the `geoip2` directive, so per the module's default it
sources the lookup IP from `$remote_addr`, the actual TCP peer address. There is no
`real_ip_header`/`set_real_ip_from` configuration anywhere in the file, so nothing tells nginx to
trust a forwarded-for style header instead. Confirmed empirically: sending requests with
`X-Forwarded-For` set to several real Icelandic ISP ranges made no difference to the response
(still routed to `north`, the "No flag in this region!" page), ruling out header spoofing.

## Proof of Concept

Install Tor and restrict its exit node selection to Iceland specifically:

```
sudo apt-get install -y tor
echo -e "\nExitNodes {is}\nStrictNodes 1" | sudo tee -a /etc/tor/torrc
sudo systemctl start tor@default
```

Once bootstrapped, route the request through Tor's local SOCKS proxy instead of a direct
connection:

```
curl -s --socks5-hostname 127.0.0.1:9050 http://TARGET/
```

The response now comes from the `south` upstream:

```
<p>picoCTF{g30_b453d_r0u71n9_90cabc04}</p>
```

## Root Cause

IP-based geolocation access control assumes the requester's network-layer source address
reliably reflects their real-world location, but any client willing to route traffic through an
exit point physically or administratively located in the target region defeats the check
entirely, with no application-layer trickery needed at all. This is the same limitation that
affects real-world geofencing (streaming region locks, geo-restricted content, etc.): commodity
VPNs and Tor both offer exit nodes in specific countries for exactly this purpose.

## CWE / OWASP

- **CWE-290**: Authentication Bypass by Spoofing (of a location-based access decision)
- **OWASP A01:2021**: Broken Access Control
