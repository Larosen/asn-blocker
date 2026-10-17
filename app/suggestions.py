"""Curated starting points for users who don't know where to begin. Every list is reviewed in the import preview
before anything is added, and the user picks the action. ASNs verified against the bgp.tools ASN list."""

LISTS = [
    {
        "id": "cloud",
        "title": "Large cloud platforms",
        "description": "Compute of the big cloud providers – a common source of scrapers, scanners and bots.",
        "warning": "Also blocks legitimate services running there: uptime monitors, webhooks (e.g. GitHub, Stripe), "
                   "API clients and Let's Encrypt HTTP-01 validation. Prefer captcha for web-only services.",
        "action": "captcha",
        "asns": [
            (16509, "Amazon AWS"), (14618, "Amazon AWS"), (8075, "Microsoft Azure"), (396982, "Google Cloud"),
            (19527, "Google Cloud"), (31898, "Oracle Cloud"), (45102, "Alibaba Cloud"), (45090, "Tencent Cloud"),
            (132203, "Tencent"), (36351, "IBM Cloud"), (136907, "Huawei Cloud"),
        ],
    },
    {
        "id": "vps",
        "title": "VPS and dedicated server hosting",
        "description": "Inexpensive virtual and dedicated servers, frequently used for brute force, scanning and "
                       "credential stuffing.",
        "warning": "Self-hosters and VPN providers also run servers here – add VPN exemptions and protect networks "
                   "you use yourself before applying.",
        "action": "ban",
        "asns": [
            (14061, "DigitalOcean"), (20473, "Vultr"), (63949, "Akamai Connected Cloud (Linode)"), (16276, "OVHcloud"),
            (24940, "Hetzner"), (51167, "Contabo"), (40021, "Contabo US"), (12876, "Scaleway"), (47583, "Hostinger"),
            (36352, "HostPapa (ColoCrossing)"), (19318, "InterServer"), (36007, "Kamatera"), (60781, "Leaseweb NL"),
            (16265, "Leaseweb"), (62240, "Clouvider"), (29802, "HIVELOCITY"), (53667, "FranTech (BuyVM)"),
            (23470, "ReliableSite"), (40676, "Psychz Networks"),
        ],
    },
    {
        "id": "bytedance",
        "title": "ByteDance crawlers",
        "description": "Networks of the Bytespider crawler, known for ignoring robots.txt.",
        "warning": "Only crawlers run here; TikTok users connect through their own internet providers.",
        "action": "ban",
        "asns": [(396986, "ByteDance"), (138699, "TikTok / ByteDance")],
    },
]
