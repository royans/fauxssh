import socket
import requests
import json
import logging

try:
    import whois
except ImportError:
    whois = None

from ssh_honeypot.core.logging_setup import log
from ssh_honeypot.core.config import config


class IPEnricher:
    def __init__(self):
        self.ip_api_url = "http://ip-api.com/json/{ip}?fields=status,message,country,city,isp,org,as,hosting,query"
        if not whois:
            log.warning(
                "[Enricher] 'python-whois' not installed. Whois lookups disabled."
            )

    def get_reverse_dns(self, ip):
        try:
            # Connects to your local DNS server, not the target IP (Passive-ish)
            result = socket.gethostbyaddr(ip)
            return result[0]
        except Exception:
            return None

    def get_geoip_and_isp(self, ip):
        # Using ip-api.com (Free for non-commercial use, 600 req/hr limit handled by caller)
        try:
            url = self.ip_api_url.format(ip=ip)
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return data
        except Exception as e:
            log.debug(f"[Enricher] GeoIP failed for {ip}: {e}")
        return None

    def get_whois_data(self, ip):
        if not whois:
            return None
        try:
            w = whois.whois(ip)
            # Whois data is often messy/unstructured. We try to grab the most relevant fields.
            return {"registrar": w.registrar, "org": w.org, "emails": w.emails}
        except Exception as e:
            # Frequent timeouts/failures are expected
            return None

    def analyze_network_type(self, geoip_data):
        """
        Heuristic to guess if this is a Home connection, Cloud Server, or Corporate.
        """
        if not geoip_data:
            return "Unknown"

        isp = (geoip_data.get("isp") or "").lower()
        org = (geoip_data.get("org") or "").lower()
        asn = (geoip_data.get("as") or "").lower()
        hosting = geoip_data.get("hosting", False)

        # 1. Check for known Cloud/Hosting providers
        cloud_keywords = [
            "amazon",
            "google",
            "microsoft",
            "digitalocean",
            "linode",
            "oracle",
            "alibaba",
            "hetzner",
            "ovh",
            "vps",
            "hosting",
        ]
        if hosting or any(k in isp or k in org for k in cloud_keywords):
            return "DATACENTER"

        # 2. Check for Residential ISPs
        residential_keywords = [
            "comcast",
            "verizon",
            "at&t",
            "spectrum",
            "charter",
            "cox",
            "telecom",
            "broadband",
            "fios",
        ]
        if any(k in isp or k in org for k in residential_keywords):
            return "RESIDENTIAL"

        # 3. Education
        if "university" in org or "college" in org or "education" in isp:
            return "ACADEMIC"

        return "CORPORATE"

    def enrich_ip(self, ip, db=None):
        """
        Orchestrates the enrichment. Returns dict suitable for DB.
        """
        if not db:
            from ssh_honeypot.core.database import get_db_backend

            db = get_db_backend()

        # Global Rate Limit Check (25% Safeguard)
        l_rpm = config.get("throttling", "global", "ip_api", "rpm") or 10
        l_rph = config.get("throttling", "global", "ip_api", "rph") or 200
        l_rpd = config.get("throttling", "global", "ip_api", "rpd") or 1000

        allowed, reason = db.check_api_rate_limit(
            "ip_api", "GLOBAL", l_rpm, l_rph, l_rpd
        )
        if not allowed:
            log.warning(f"[Enricher] Global Rate Limit Block: {reason}")
            return None

        log.info(f"[Enricher] Enriching {ip}...")
        db.record_api_usage("ip_api", "GLOBAL")

        rdns = self.get_reverse_dns(ip)
        geo = self.get_geoip_and_isp(ip)
        whois_data = self.get_whois_data(ip)

        # Merge raw data for storage
        raw_data = {"rdns": rdns, "geo": geo, "whois": whois_data}

        result = {
            "hostname": rdns,
            "city": geo.get("city") if geo else None,
            "country": geo.get("country") if geo else None,
            "isp": geo.get("isp") if geo else None,
            "org": geo.get("org") if geo else None,
            "asn": geo.get("as") if geo else None,
            "latitude": geo.get("lat") if geo else None,
            "longitude": geo.get("lon") if geo else None,
            "network_type": self.analyze_network_type(geo),
            "raw_data": raw_data,
        }

        return result
