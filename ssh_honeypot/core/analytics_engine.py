import logging
import datetime
import os
import time
import json
from datetime import timedelta
from .logging_setup import log
from .utils import get_ignored_ips

# Simple in-memory cache for analytics to reduce DB load
# Key -> (timestamp, data)
_ANALYTICS_CACHE = {}


class AnalyticsEngine:
    """
    Centralized engine for analytics queries, supporting both SQLite and Postgres.
    Used by CLI tools (analyze.py) and the HTTP Server (stats dashboard).
    Includes in-memory caching (default 30 mins) for expensive queries.
    """

    def __init__(self, db_backend):
        self.db = db_backend

    def _standardize_dates(self, data):
        """
        Ensures all timestamps in the list of dicts are UTC ISO strings.
        This prevents browser timezone confusion (negative timestamps).
        """
        if not data:
            return data

        time_fields = ["start_time", "end_time", "timestamp", "first_cmd", "last_cmd"]

        for row in data:
            for field in time_fields:
                if field in row and row[field]:
                    val = row[field]
                    if isinstance(val, str):
                        # SQLite strings are usually naive UTC.
                        # If seemingly ISO but missing Z/Offset, append Z.
                        # Matches "YYYY-MM-DD HH:MM:SS" or "YYYY-MM-DDTHH:MM:SS" etc.
                        if len(val) >= 19 and not val.endswith("Z") and "+" not in val:
                            row[field] = val + "Z"
                    elif isinstance(val, datetime.datetime):
                        if val.tzinfo is None:
                            # Treat as local system time (matching analyze.py logic)
                            # This ensures .isoformat() includes the correct local offset
                            val = val.astimezone()
                        row[field] = val.isoformat()
        return data

    def _get_cache_key(self, method, **kwargs):
        """Generates a stable cache key based on inputs."""
        # Convert kwargs to sorted tuple for stability
        stable_kwargs = sorted(
            [(k, str(v)) for k, v in kwargs.items() if v is not None]
        )
        return f"{method}::{json.dumps(stable_kwargs)}"

    def _get_cached(self, key, ttl_seconds=1800):
        """Retrieve from cache if valid."""
        if key in _ANALYTICS_CACHE:
            ts, data = _ANALYTICS_CACHE[key]
            if time.time() - ts < ttl_seconds:
                return data
            else:
                del _ANALYTICS_CACHE[key]
        return None

    def _set_cache(self, key, data):
        """Store in cache."""
        _ANALYTICS_CACHE[key] = (time.time(), data)

        # Periodic cleanup (basic) - if cache gets too big, clear half
        if len(_ANALYTICS_CACHE) > 1000:
            keys_to_del = list(_ANALYTICS_CACHE.keys())[:500]
            for k in keys_to_del:
                del _ANALYTICS_CACHE[k]

    def _get_conn_and_ph(self):
        """Helper to get connection and placeholder style."""
        conn = self.db._get_conn()

        # Determine placeholder
        ph = "?"
        if self.db.is_postgres:
            ph = "%s"

        return conn, ph

    def _to_list_of_dicts(self, cursor):
        """Converts cursor rows to list of dictionaries."""
        if not cursor.description:
            return []

        columns = [col[0] for col in cursor.description]
        rows = cursor.fetchall()

        results = []
        for row in rows:
            # Handle different row types (sqlite3.Row, tuple, RealDictRow)
            if hasattr(row, "keys"):
                # It's dict-like or sqlite3.Row
                results.append(dict(row))
            else:
                # It's a tuple
                results.append(dict(zip(columns, row)))
        return results

    def _clean_ip(self, ip, anon=False):
        """Standard IP cleaning/anonymization."""
        if not ip:
            return "-"
        if ip.startswith("::ffff:"):
            ip = ip.replace("::ffff:", "")

        if anon:
            if "." in ip:
                parts = ip.split(".")
                if len(parts) == 4:
                    parts[3] = "XXX"
                    return ".".join(parts)
            elif ":" in ip:
                # Simple IPv6 masking
                parts = ip.split(":")
                if len(parts) > 2:
                    return ":".join(parts[:3]) + ":...:XXX"
        return ip

    def get_recent_sessions(
        self,
        limit=50,
        anon=False,
        ip_filter=None,
        protocol_filter=None,
        risk_min=None,
        user_filter=None,
        asn_filter=None,
    ):
        """
        Fetches recent sessions with optional filters.
        """
        # 1. Check Cache
        cache_key = self._get_cache_key(
            "get_recent_sessions",
            limit=limit,
            anon=anon,
            ip=ip_filter,
            proto=protocol_filter,
            risk=risk_min,
            user=user_filter,
            asn=asn_filter,
        )
        cached = self._get_cached(cache_key, ttl_seconds=1800)  # 30 mins
        if cached:
            return cached

        conn, ph = self._get_conn_and_ph()
        try:
            cursor = conn.cursor()

            # Dialect specific SQL
            agg_func = "STRING_AGG" if self.db.is_postgres else "group_concat"

            # Base Query
            query = f"""
                SELECT 
                    s.session_id, 
                    s.remote_ip, 
                    s.username, 
                    s.password,
                    s.start_time, 
                    s.end_time,
                    s.client_version,
                    s.fingerprint,
                    s.protocol,
                    (SELECT COUNT(*) FROM interactions i WHERE i.session_id = s.session_id) as cmd_count,
                    (SELECT COUNT(*) FROM interactions i WHERE i.session_id = s.session_id AND i.source = 'llm') as llm_count,
                    (SELECT MIN(timestamp) FROM interactions i WHERE i.session_id = s.session_id) as first_cmd,
                    (SELECT MAX(timestamp) FROM interactions i WHERE i.session_id = s.session_id) as last_cmd,
                    (
                        SELECT AVG(ca.risk_score) 
                        FROM interactions i 
                        JOIN command_analysis ca ON i.request_md5 = ca.command_hash 
                        WHERE i.session_id = s.session_id
                    ) as avg_risk,
                    (SELECT {agg_func}(command, '|||') FROM interactions i WHERE i.session_id = s.session_id) as all_commands,
                    (SELECT command FROM interactions i WHERE i.session_id = s.session_id ORDER BY timestamp DESC LIMIT 1) as last_command,
                    s.summary,
                    s.risk_score,
                    ii.country,
                    ii.city,
                    ii.isp,
                    ii.hostname,
                    ii.org,
                    ii.asn,
                    ii.network_type,
                    ii.abuse_tags
                FROM sessions s
                LEFT JOIN ip_intelligence ii ON s.remote_ip = ii.ip
                WHERE 1=1
            """

            params = []

            # 1. Ignored IPs
            try:
                ignored = get_ignored_ips()
            except:
                ignored = []

            if ignored:
                placeholders = ",".join([ph] * len(ignored))
                query += f" AND s.remote_ip NOT IN ({placeholders})"
                params.extend(ignored)

            # 2. Filters
            if protocol_filter:
                if isinstance(protocol_filter, list):
                    placeholders = ",".join([ph] * len(protocol_filter))
                    query += f" AND s.protocol IN ({placeholders})"
                    params.extend(protocol_filter)
                else:
                    query += f" AND s.protocol = {ph}"
                    params.append(protocol_filter)

            if ip_filter:
                # Support XXX replacement and partial matching
                clean_filter = ip_filter.replace("XXX", "%")

                # If it looks like a partial IP (e.g. 192.168.) or doesn't have 4 octets, treat as prefix
                if "." in clean_filter and not clean_filter.endswith("%"):
                    parts = [p for p in clean_filter.split(".") if p]
                    if len(parts) < 4:
                        if not clean_filter.endswith("."):
                            clean_filter += ".%"
                        else:
                            clean_filter += "%"

                if "%" in clean_filter:
                    query += f" AND (s.remote_ip LIKE {ph} OR s.remote_ip LIKE {ph})"
                    params.append(clean_filter)
                    if not clean_filter.startswith("::ffff:"):
                        params.append(f"::ffff:{clean_filter}")
                    else:
                        params.append(clean_filter)
                else:
                    query += f" AND (s.remote_ip = {ph} OR s.remote_ip = {ph})"
                    params.append(ip_filter)
                    if not ip_filter.startswith("::ffff:"):
                        params.append(f"::ffff:{ip_filter}")
                    else:
                        params.append(ip_filter)

            if asn_filter and asn_filter.strip():
                query += (
                    f" AND (ii.asn LIKE {ph} OR ii.org LIKE {ph} OR ii.isp LIKE {ph})"
                )
                params.append(f"%{asn_filter}%")
                params.append(f"%{asn_filter}%")
                params.append(f"%{asn_filter}%")

            if user_filter:
                query += f" AND s.username LIKE {ph}"
                params.append(f"%{user_filter}%")

            if risk_min is not None:
                # Check session risk OR calculated avg risk
                query += f""" AND (
                    s.risk_score >= {ph} OR 
                    (SELECT AVG(ca.risk_score) 
                     FROM interactions i 
                     JOIN command_analysis ca ON i.request_md5 = ca.command_hash 
                     WHERE i.session_id = s.session_id) >= {ph}
                )"""
                params.append(risk_min)
                params.append(risk_min)

            # Filter empty sessions by default (unless env var set, but engine keeps it strict or configurable)
            # We'll stick to strict for now to reduce noise in API
            show_empty = (
                str(os.getenv("FAUXSSH_ANALYTICS_SHOW_EMPTY", "false")).lower()
                == "true"
            )
            if not show_empty:
                query += " AND (SELECT COUNT(*) FROM interactions i WHERE i.session_id = s.session_id) > 0"

            query += f" ORDER BY s.start_time DESC LIMIT {ph}"
            params.append(limit)

            cursor.execute(query, tuple(params))
            data = self._to_list_of_dicts(cursor)

            # Post-processing (Anonymization)
            for row in data:
                row["remote_ip_clean"] = self._clean_ip(row["remote_ip"], anon)
                row["remote_ip"] = row[
                    "remote_ip_clean"
                ]  # Override if we want to hide it completely in UI

            self._standardize_dates(data)
            self._set_cache(cache_key, data)
            return data

        except Exception as e:
            log.error(f"[AnalyticsEngine] Error in get_recent_sessions: {e}")
            return []
        finally:
            conn.close()

    def _parse_sort_param(self, sort_str, field_map):
        """
        Parses "Field1:Desc,Field2:Asc" into a SQL ORDER BY clause.
        """
        if not sort_str:
            return None

        clauses = []
        for part in sort_str.split(","):
            if ":" in part:
                field, direction = part.split(":", 1)
            else:
                field, direction = part, "ASC"

            field = field.strip().lower()
            direction = direction.strip().upper()

            if direction not in ("ASC", "DESC"):
                continue

            if field in field_map:
                sql_col = field_map[field]
                if field == "unique":
                    # Unique High (Rare) = Low Count. Desc (High to Low) -> Count ASC
                    # Unique Low (Common) = High Count. Asc (Low to High) -> Count DESC
                    direction = "ASC" if direction == "DESC" else "DESC"

                clauses.append(f"{sql_col} {direction}")

        return ", ".join(clauses) if clauses else None

    def get_recent_commands(
        self,
        limit=50,
        anon=False,
        ip_filter=None,
        session_filter=None,
        protocol_filter=None,
        risk_min=None,
        sort_by=None,
    ):
        """
        Fetches recent commands with optional filters.
        """
        cache_key = self._get_cache_key(
            "get_recent_commands",
            limit=limit,
            anon=anon,
            ip=ip_filter,
            session=session_filter,
            proto=protocol_filter,
            risk=risk_min,
            sort=sort_by,
        )
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        conn, ph = self._get_conn_and_ph()
        try:
            cursor = conn.cursor()

            # Get Total IPs for Unique % calculation
            try:
                cursor.execute(f"SELECT COUNT(DISTINCT remote_ip) FROM sessions")
                res = cursor.fetchone()
                if isinstance(res, (tuple, list)):
                    total_ips = res[0]
                elif hasattr(res, "values"):
                    total_ips = list(res.values())[0]
                else:
                    total_ips = res[0]
            except:
                total_ips = 1

            if not total_ips:
                total_ips = 1

            query = f"""
                SELECT 
                    i.timestamp,
                    s.remote_ip,
                    s.protocol,
                    s.username,
                    i.command,
                    i.response,
                    i.source,
                    i.request_md5,
                    i.response_size,
                    ca.activity_type,
                    ca.risk_score,
                    ca.explanation,
                    (SELECT COUNT(DISTINCT s2.remote_ip) 
                     FROM interactions i2 
                     JOIN sessions s2 ON i2.session_id = s2.session_id 
                     WHERE i2.request_md5 = i.request_md5) as cmd_ip_count
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                LEFT JOIN command_analysis ca ON i.request_md5 = ca.command_hash
                WHERE 1=1
            """

            params = []

            # Ignored IPs
            try:
                ignored = get_ignored_ips()
            except:
                ignored = []

            if ignored:
                placeholders = ",".join([ph] * len(ignored))
                query += f" AND s.remote_ip NOT IN ({placeholders})"
                params.extend(ignored)

            if ip_filter:
                clean_filter = ip_filter.replace("XXX", "%")

                if "." in clean_filter and not clean_filter.endswith("%"):
                    parts = [p for p in clean_filter.split(".") if p]
                    if len(parts) < 4:
                        if not clean_filter.endswith("."):
                            clean_filter += ".%"
                        else:
                            clean_filter += "%"

                if "%" in clean_filter:
                    query += f" AND (s.remote_ip LIKE {ph} OR s.remote_ip LIKE {ph})"
                    params.append(clean_filter)
                    if not clean_filter.startswith("::ffff:"):
                        params.append(f"::ffff:{clean_filter}")
                    else:
                        params.append(clean_filter)
                else:
                    query += f" AND (s.remote_ip = {ph} OR s.remote_ip = {ph})"
                    params.append(ip_filter)
                    if not ip_filter.startswith("::ffff:"):
                        params.append(f"::ffff:{ip_filter}")
                    else:
                        params.append(ip_filter)

            if session_filter:
                query += f" AND i.session_id LIKE {ph}"
                params.append(f"{session_filter}%")

            if protocol_filter:
                if isinstance(protocol_filter, list):
                    placeholders = ",".join([ph] * len(protocol_filter))
                    query += f" AND s.protocol IN ({placeholders})"
                    params.extend(protocol_filter)
                else:
                    query += f" AND s.protocol = {ph}"
                    params.append(protocol_filter)

            if risk_min is not None:
                query += f" AND ca.risk_score >= {ph}"
                params.append(risk_min)

            # Sorting
            sort_sql = None
            if sort_by:
                field_map = {
                    "time": "i.timestamp",
                    "ip": "s.remote_ip",
                    "user": "s.username",
                    "risk": "ca.risk_score",
                    "unique": "cmd_ip_count",  # calculated col
                    "cmds": "cmd_ip_count",  # alias
                }
                sort_sql = self._parse_sort_param(sort_by, field_map)

            if sort_sql:
                query += f" ORDER BY {sort_sql} LIMIT {ph}"
            else:
                query += f" ORDER BY i.id DESC LIMIT {ph}"

            params.append(limit)

            cursor.execute(query, tuple(params))
            data = self._to_list_of_dicts(cursor)

            # Post-process
            for row in data:
                row["remote_ip_clean"] = self._clean_ip(row["remote_ip"], anon)
                row["remote_ip"] = row["remote_ip_clean"]

                # Unique Calculation
                cmd_ip_count = row.get("cmd_ip_count", 0) or 0
                freq = cmd_ip_count / total_ips
                row["unique_pct"] = (1.0 - freq) * 100.0

            self._standardize_dates(data)
            self._set_cache(cache_key, data)
            return data

        except Exception as e:
            log.error(f"[AnalyticsEngine] Error in get_recent_commands: {e}")
            return []
        finally:
            conn.close()

    def get_top_commands(self, limit=50, duration_seconds=3600, protocol_filter=None):
        """
        Top commands frequency.
        """
        cache_key = self._get_cache_key(
            "get_top_commands",
            limit=limit,
            duration=duration_seconds,
            proto=protocol_filter,
        )
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        conn, ph = self._get_conn_and_ph()
        try:
            cursor = conn.cursor()

            if self.db.is_postgres:
                time_filter = (
                    f"i.timestamp > NOW() - INTERVAL '{duration_seconds} seconds'"
                )
                agg_proto = "STRING_AGG(DISTINCT s.protocol, ', ')"
            else:
                time_filter = (
                    f"i.timestamp > datetime('now', '-{duration_seconds} seconds')"
                )
                agg_proto = "group_concat(DISTINCT s.protocol)"

            query = f"""
                SELECT 
                    i.command,
                    COUNT(*) as total_count,
                    COUNT(DISTINCT s.remote_ip) as unique_ips,
                    MAX(ca.risk_score) as max_risk,
                    {agg_proto} as protocols,
                    MAX(i.response) as sample_response
                FROM interactions i
                JOIN sessions s ON i.session_id = s.session_id
                LEFT JOIN command_analysis ca ON i.request_md5 = ca.command_hash
                WHERE {time_filter}
            """
            params = []

            if protocol_filter:
                if isinstance(protocol_filter, list):
                    placeholders = ",".join([ph] * len(protocol_filter))
                    query += f" AND s.protocol IN ({placeholders})"
                    params.extend(protocol_filter)
                else:
                    query += f" AND s.protocol = {ph}"
                    params.append(protocol_filter)

            query += " GROUP BY i.command ORDER BY total_count DESC LIMIT " + str(
                int(limit)
            )

            cursor.execute(query, tuple(params))
            data = self._to_list_of_dicts(cursor)
            self._set_cache(cache_key, data)
            return data
        finally:
            conn.close()

    def get_top_ips(self, hours=24, limit=50, anon=False):
        """
        Gets Top IPs sorted by session count, with intelligence and protocol breakdown.
        """
        cache_key = self._get_cache_key(
            "get_top_ips", hours=hours, limit=limit, anon=anon
        )
        cached = self._get_cached(cache_key, ttl_seconds=600)
        if cached:
            return cached

        conn, ph = self._get_conn_and_ph()
        try:
            cursor = conn.cursor()
            if self.db.is_postgres:
                t_filter = f"s.start_time > NOW() - INTERVAL '{hours} hours'"
            else:
                t_filter = f"s.start_time > datetime('now', '-{hours} hours')"

            params = []
            ip_exclude = ""
            try:
                from .config import get_ignored_ips

                ignored = get_ignored_ips()
                if ignored:
                    placeholders = ",".join([ph] * len(ignored))
                    ip_exclude = f" AND s.remote_ip NOT IN ({placeholders})"
                    params.extend(ignored)
            except:
                pass

            # 1. Fetch sessions
            s_query = f"""
                SELECT s.session_id, s.remote_ip, s.protocol,
                       (SELECT COUNT(*) FROM interactions i WHERE i.session_id = s.session_id) as cmd_count
                FROM sessions s
                WHERE {t_filter} {ip_exclude}
            """
            cursor.execute(s_query, tuple(params))
            sessions = self._to_list_of_dicts(cursor)
            if not sessions:
                return []

            # 2. Extract unique IPs and fetch intelligence
            unique_ips = list(set(s["remote_ip"] for s in sessions))
            intel = {}
            chunk_size = 500
            for i in range(0, len(unique_ips), chunk_size):
                chunk = unique_ips[i : i + chunk_size]
                placeholders = ",".join([ph] * len(chunk))
                i_query = f"SELECT ip, country, asn, org FROM ip_intelligence WHERE ip IN ({placeholders})"
                cursor.execute(i_query, tuple(chunk))
                for row in self._to_list_of_dicts(cursor):
                    intel[row["ip"]] = row

            # 3. Aggregate by IP
            ip_map = {}
            for s in sessions:
                ip = s["remote_ip"]
                if ip not in ip_map:
                    ip_info = intel.get(ip, {})
                    ip_map[ip] = {
                        "ip": ip,
                        "asn": ip_info.get("asn") or "-",
                        "org": ip_info.get("org") or "-",
                        "country": ip_info.get("country") or "-",
                        "total_sessions": 0,
                        "total_commands": 0,
                        "protocols": {},
                    }

                a = ip_map[ip]
                a["total_sessions"] += 1
                a["total_commands"] += s["cmd_count"]

                proto = s["protocol"]
                if proto not in a["protocols"]:
                    a["protocols"][proto] = {"sessions": 0, "commands": 0}
                a["protocols"][proto]["sessions"] += 1
                a["protocols"][proto]["commands"] += s["cmd_count"]

            results = sorted(
                ip_map.values(), key=lambda x: x["total_sessions"], reverse=True
            )[:limit]

            # Anonymization
            if anon:
                for r in results:
                    r["ip"] = self._clean_ip(r["ip"], True)

            self._set_cache(cache_key, results)
            return results
        except Exception as e:
            log.error(f"[AnalyticsEngine] Error in get_top_ips: {e}")
            return []
        finally:
            conn.close()

    def get_dashboard_totals(self, hours=24):
        """
        Fetches global dashboard totals for the given time window.
        """
        cache_key = self._get_cache_key("get_dashboard_totals", hours=hours)
        cached = self._get_cached(cache_key, ttl_seconds=300)  # 5 mins for totals
        if cached:
            return cached

        conn, ph = self._get_conn_and_ph()
        try:
            cursor = conn.cursor()

            if self.db.is_postgres:
                t_filter = f"start_time > NOW() - INTERVAL '{hours} hours'"
                c_filter = f"interactions.timestamp > NOW() - INTERVAL '{hours} hours'"
            else:
                t_filter = f"start_time > datetime('now', '-{hours} hours')"
                c_filter = f"interactions.timestamp > datetime('now', '-{hours} hours')"

            # Ignored IPs
            try:
                ignored = get_ignored_ips()
            except:
                ignored = []

            ip_exclude = ""
            sess_ip_exclude = ""
            params = []
            if ignored:
                placeholders = ",".join([ph] * len(ignored))
                ip_exclude = f" AND remote_ip NOT IN ({placeholders})"
                sess_ip_exclude = f" AND sessions.remote_ip NOT IN ({placeholders})"
                params.extend(ignored)

            query = f"""
                SELECT 
                    (SELECT COUNT(*) FROM sessions WHERE {t_filter} {ip_exclude}) as total_sessions,
                    (SELECT COUNT(*) FROM interactions JOIN sessions ON interactions.session_id = sessions.session_id WHERE {c_filter} {sess_ip_exclude}) as total_commands,
                    (SELECT COUNT(DISTINCT remote_ip) FROM sessions WHERE {t_filter} {ip_exclude}) as unique_ips,
                    (SELECT COUNT(DISTINCT ip_intelligence.asn) FROM sessions JOIN ip_intelligence ON sessions.remote_ip = ip_intelligence.ip WHERE sessions.{t_filter} {sess_ip_exclude}) as unique_asns
            """
            # Use params * 4 because we have 4 subqueries using ip_exclude
            cursor.execute(query, tuple(params + params + params + params))
            data = self._to_list_of_dicts(cursor)[0]

            self._set_cache(cache_key, data)
            return data
        except Exception as e:
            log.error(f"[AnalyticsEngine] Error in get_dashboard_totals: {e}")
            return {
                "total_sessions": 0,
                "total_commands": 0,
                "unique_ips": 0,
                "unique_asns": 0,
            }
        finally:
            conn.close()

    def get_top_asns(self, hours=24, protocol_filter=None):
        """
        Gets Top ASNs sorted by unique IPs, with session/command breakdown per protocol.
        """
        cache_key = self._get_cache_key(
            "get_top_asns", hours=hours, proto=protocol_filter
        )
        cached = self._get_cached(cache_key, ttl_seconds=600)
        if cached:
            return cached

        conn, ph = self._get_conn_and_ph()
        try:
            cursor = conn.cursor()
            if self.db.is_postgres:
                t_filter = f"s.start_time > NOW() - INTERVAL '{hours} hours'"
                t_filter_i = f"s_inner.start_time > NOW() - INTERVAL '{hours} hours'"
            else:
                t_filter = f"s.start_time > datetime('now', '-{hours} hours')"
                t_filter_i = f"s_inner.start_time > datetime('now', '-{hours} hours')"

            params = []
            ip_exclude = ""
            try:
                from .config import get_ignored_ips

                ignored = get_ignored_ips()
                if ignored:
                    placeholders = ",".join([ph] * len(ignored))
                    ip_exclude = f" AND s.remote_ip NOT IN ({placeholders})"
                    params.extend(ignored)
            except:
                pass

            # 1. Fetch raw sessions in window (fast)
            s_query = f"""
                SELECT s.session_id, s.remote_ip, s.protocol
                FROM sessions s
                WHERE {t_filter} {ip_exclude}
            """
            if protocol_filter:
                if isinstance(protocol_filter, list):
                    s_query += (
                        f" AND s.protocol IN ({','.join([ph]*len(protocol_filter))})"
                    )
                    params.extend(protocol_filter)
                else:
                    s_query += f" AND s.protocol = {ph}"
                    params.append(protocol_filter)

            cursor.execute(s_query, tuple(params))
            sessions = self._to_list_of_dicts(cursor)

            if not sessions:
                return []

            # 2. Fetch command counts in bulk (much faster than subquery per row)
            cmd_counts = {}
            c_query = f"""
                SELECT i.session_id, COUNT(*) as cmd_count
                FROM interactions i
                JOIN sessions s_inner ON i.session_id = s_inner.session_id
                WHERE {t_filter_i}
                GROUP BY i.session_id
            """
            cursor.execute(c_query)
            for row in cursor.fetchall():
                cmd_counts[row[0]] = row[1]

            # 3. Extract unique IPs and fetch intelligence
            unique_ips = list(set(s["remote_ip"] for s in sessions))
            intel = {}
            chunk_size = 500
            for i in range(0, len(unique_ips), chunk_size):
                chunk = unique_ips[i : i + chunk_size]
                placeholders = ",".join([ph] * len(chunk))
                i_query = f"SELECT ip, asn, org FROM ip_intelligence WHERE ip IN ({placeholders})"
                cursor.execute(i_query, tuple(chunk))
                for row in self._to_list_of_dicts(cursor):
                    intel[row["ip"]] = row

            # 4. Aggregate in Python
            asn_map = {}
            for s in sessions:
                ip_info = intel.get(s["remote_ip"], {})
                asn = ip_info.get("asn") or "Unknown"
                org = ip_info.get("org") or "Unknown Organization"
                c_count = cmd_counts.get(s["session_id"], 0)

                if asn not in asn_map:
                    asn_map[asn] = {
                        "asn": asn,
                        "org": org,
                        "unique_ips_set": set(),
                        "total_sessions": 0,
                        "total_commands": 0,
                        "protocols": {},
                    }

                a = asn_map[asn]
                a["unique_ips_set"].add(s["remote_ip"])
                a["total_sessions"] += 1
                a["total_commands"] += c_count

                proto = s["protocol"]
                if proto not in a["protocols"]:
                    a["protocols"][proto] = {"sessions": 0, "commands": 0}

                a["protocols"][proto]["sessions"] += 1
                a["protocols"][proto]["commands"] += c_count

            # 5. Finalize and Sort
            results = []
            for asn, data in asn_map.items():
                data["unique_ips"] = len(data["unique_ips_set"])
                del data["unique_ips_set"]
                results.append(data)

            results.sort(key=lambda x: x["unique_ips"], reverse=True)
            top_50 = results[:50]

            self._set_cache(cache_key, top_50)
            return top_50
        except Exception as e:
            log.error(f"[AnalyticsEngine] Error in get_top_asns: {e}")
            return []
        finally:
            conn.close()

    def get_top_countries(self, hours=24):
        """
        Gets Top Countries sorted by unique IP count, with protocol breakdown.
        """
        cache_key = self._get_cache_key("get_top_countries_v2", hours=hours)
        cached = self._get_cached(cache_key, ttl_seconds=600)
        if cached:
            return cached

        conn, ph = self._get_conn_and_ph()
        try:
            cursor = conn.cursor()
            if self.db.is_postgres:
                t_filter = f"s.start_time > NOW() - INTERVAL '{hours} hours'"
            else:
                t_filter = f"s.start_time > datetime('now', '-{hours} hours')"

            params = []
            ip_exclude = ""
            try:
                from .config import get_ignored_ips

                ignored = get_ignored_ips()
                if ignored:
                    placeholders = ",".join([ph] * len(ignored))
                    ip_exclude = f" AND s.remote_ip NOT IN ({placeholders})"
                    params.extend(ignored)
            except:
                pass

            # 1. Fetch sessions with Protocol
            s_query = f"SELECT remote_ip, protocol FROM sessions s WHERE {t_filter} {ip_exclude}"
            cursor.execute(s_query, tuple(params))
            sessions = cursor.fetchall()
            if not sessions:
                return []

            # 2. Get Country Intel
            unique_ips = list(set(s[0] for s in sessions))
            country_intel = {}
            chunk_size = 500
            for i in range(0, len(unique_ips), chunk_size):
                chunk = unique_ips[i : i + chunk_size]
                placeholders = ",".join([ph] * len(chunk))
                i_query = f"SELECT ip, country FROM ip_intelligence WHERE ip IN ({placeholders})"
                cursor.execute(i_query, tuple(chunk))
                for row in self._to_list_of_dicts(cursor):
                    country_intel[row["ip"]] = row["country"] or "Unknown"

            # 3. Aggregate
            country_map = {}
            for s in sessions:
                ip = s[0]
                proto = s[1]
                country = country_intel.get(ip, "Unknown")

                if country not in country_map:
                    country_map[country] = {
                        "country": country,
                        "unique_ips_set": set(),
                        "total_sessions": 0,
                        "protocols": {},
                    }

                c_data = country_map[country]
                c_data["unique_ips_set"].add(ip)
                c_data["total_sessions"] += 1

                if proto not in c_data["protocols"]:
                    c_data["protocols"][proto] = {
                        "unique_ips_set": set(),
                        "sessions": 0,
                    }

                c_data["protocols"][proto]["unique_ips_set"].add(ip)
                c_data["protocols"][proto]["sessions"] += 1

            results = []
            for c, data in country_map.items():
                proto_stats = {}
                for p, p_data in data["protocols"].items():
                    proto_stats[p] = {
                        "unique_ips": len(p_data["unique_ips_set"]),
                        "sessions": p_data["sessions"],
                    }

                results.append(
                    {
                        "country": c,
                        "unique_ips": len(data["unique_ips_set"]),
                        "total_sessions": data["total_sessions"],
                        "protocols": proto_stats,
                    }
                )

            # Sort by Unique IPs Descending
            results.sort(key=lambda x: x["unique_ips"], reverse=True)
            results = results[:50]

            self._set_cache(cache_key, results)
            return results
        except Exception as e:
            log.error(f"[AnalyticsEngine] Error in get_top_countries: {e}")
            return []
        finally:
            conn.close()
