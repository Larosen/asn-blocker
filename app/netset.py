"""Netz-Arithmetik: Ausnahmen aus Ranges herausschneiden."""
import bisect
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


def subtract(source, exempt):
    """source minus exempt, Ergebnis zusammengefasst."""
    exempt = collapse(exempt)
    result = []
    for ver in (4, 6):
        ex = [n for n in exempt if n.version == ver]
        starts = [int(n.network_address) for n in ex]
        ends = [int(n.broadcast_address) for n in ex]
        for src in collapse([n for n in source if n.version == ver]):
            s, e = int(src.network_address), int(src.broadcast_address)
            i = max(bisect.bisect_right(starts, s) - 1, 0)
            rem = [src]
            while i < len(ex) and starts[i] <= e:
                if ends[i] >= s:
                    nxt = []
                    for r in rem:
                        if not r.overlaps(ex[i]):
                            nxt.append(r)
                        elif not ex[i].supernet_of(r):
                            nxt.extend(r.address_exclude(ex[i]))
                    rem = nxt
                i += 1
            result.extend(rem)
    return collapse(result)


def contains(cidrs, ip):
    a = ipaddress.ip_address(ip)
    return [c for c in cidrs if a in ipaddress.ip_network(c)]
