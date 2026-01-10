
def list_top_ips(limit=50, anon=False, db_path=None):
    conn = get_db_connection(db_path)
    c = conn.cursor()
    
    # 1. Total Unique IPs
    try:
        c.execute("SELECT COUNT(DISTINCT remote_ip) FROM sessions")
        total_unique_ips = c.fetchone()[0]
    except: total_unique_ips = 0

    query = """
        SELECT 
            s.remote_ip,
            COUNT(DISTINCT s.session_id) as total_sessions,
            MIN(s.start_time) as first_seen,
            MAX(s.start_time) as last_seen,
            
            -- Total Commands
            (SELECT COUNT(*) 
             FROM interactions i 
             JOIN sessions s2 ON i.session_id = s2.session_id 
             WHERE s2.remote_ip = s.remote_ip) as total_cmds,
             
            -- Last 1 Hour Activity (Active Attackers)
            (SELECT COUNT(*) 
             FROM interactions i 
             JOIN sessions s2 ON i.session_id = s2.session_id 
             WHERE s2.remote_ip = s.remote_ip 
             AND i.timestamp > datetime('now', '-1 hour')) as recent_cmds_1h,

            -- Estimated Current RPM (Last 1 Minute) -> Proxy for Suspension Risk
            (SELECT COUNT(*) 
             FROM interactions i 
             JOIN sessions s2 ON i.session_id = s2.session_id 
             WHERE s2.remote_ip = s.remote_ip 
             AND i.timestamp > datetime('now', '-1 minute')) as current_rpm

        FROM sessions s
        WHERE 1=1
        GROUP BY s.remote_ip
        ORDER BY current_rpm DESC, total_sessions DESC
        LIMIT ?
    """
    
    c.execute(query, (limit,))
    rows = c.fetchall()
    conn.close()

    table = Table(title=f"Top Attacking IPs (Limit {limit}) - Total IPs: {total_unique_ips}", box=box.ROUNDED)
    table.add_column("Rank", style="dim", justify="right")
    table.add_column("IP", style="magenta")
    table.add_column("Sessions", justify="right", style="green")
    table.add_column("Total Cmds", justify="right")
    table.add_column("1h Cmds", justify="right", style="yellow")
    table.add_column("Current RPM", justify="right", style="bold")
    table.add_column("Last Seen", style="dim")
    table.add_column("Status", justify="center")

    rank = 1
    for r in rows:
        ip = clean_ip(r['remote_ip'], anon=anon)
        sessions = r['total_sessions']
        cmds = r['total_cmds']
        recent_1h = r['recent_cmds_1h']
        rpm = r['current_rpm']
        last_seen = to_local_time(r['last_seen'])
        
        # Determine Status/Risk
        # RPM Limit is 1000
        rpm_style = "white"
        status = "Idle"
        status_style = "dim"
        
        if rpm > 0:
            status = "Active"
            status_style = "green"
            
        if rpm >= 1000:
            status = "SUSPENDED (Sim)" # Likely suspended by DoSProtector
            status_style = "bold red reverse"
            rpm_style = "bold red"
        elif rpm >= 800:
            status = "CRITICAL"
            status_style = "bold red"
            rpm_style = "red"
        elif rpm >= 500:
            status = "WARNING"
            status_style = "yellow"
            rpm_style = "yellow"
        elif rpm > 100:
            status = "High Traffic"
            status_style = "bold blue"
            
        table.add_row(
            str(rank),
            ip,
            str(sessions),
            str(cmds),
            str(recent_1h),
            f"[{rpm_style}]{rpm}[/{rpm_style}]",
            last_seen,
            f"[{status_style}]{status}[/{status_style}]"
        )
        rank += 1
        
    console.print(table)
    console.print("[dim]Note: 'Current RPM' is based on DB logs. Actual DoS suspension happens in-memory at 1000 RPM.[/dim]")
