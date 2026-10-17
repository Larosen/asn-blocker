"""Network arithmetic: cut exemptions out of ranges."""
import ipaddress


def parse(values):
    out = []
    for v in values:
        try:
            out.append(ipaddress.ip_network(str(v).strip(), strict=False))
        except ValueError:
            pass
    return out


def collapse(nets):
    v4 = [n for n in nets if n.version == 4]
    v6 = [n for n in nets if n.version == 6]
    return sorted(ipaddress.collapse_addresses(v4)) + sorted(ipaddress.collapse_addresses(v6))


def _intervals(nets):
    """Sorted, merged [start, end] integer intervals."""
    out = []
    for n in sorted(nets, key=lambda n: int(n.network_address)):
        s, e = int(n.network_address), int(n.broadcast_address)
        if out and s <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


def _to_nets(s, e, version):
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    return list(ipaddress.summarize_address_range(cls(s), cls(e)))


def subtract(source, exempt):
    """source minus exempt, result collapsed. One linear sweep over merged intervals – the cost grows with the
    number of ranges and holes, not with their product."""
    result = []
    for ver in (4, 6):
        src = _intervals([n for n in source if n.version == ver])
        ex = _intervals([n for n in exempt if n.version == ver])
        j = 0
        for s, e in src:
            while j < len(ex) and ex[j][1] < s:
                j += 1
            k, cur = j, s
            while k < len(ex) and ex[k][0] <= e:
                if ex[k][0] > cur:
                    result += _to_nets(cur, ex[k][0] - 1, ver)
                cur = max(cur, ex[k][1] + 1)
                k += 1
            if cur <= e:
                result += _to_nets(cur, e, ver)
    return collapse(result)


def contains(cidrs, ip):
    a = ipaddress.ip_address(ip)
    return [c for c in cidrs if a in ipaddress.ip_network(c)]
