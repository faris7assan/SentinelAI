##############################################################
# SentinelAI — Zeek Scripts
# Custom detection scripts for the Zeek network monitor
# Place in: /etc/zeek/site/sentinelai.zeek
# Reload: zeekctl deploy
##############################################################

@load base/frameworks/notice

module SentinelAI;

export {
    redef enum Notice::Type += {
        DNS_Tunneling,
        PortScan,
        DataExfiltration,
        C2_Beaconing,
        LateralMovement_SMB,
    };

    global dns_query_log_file = open_log_file("sentinelai_dns");
    const max_dns_subdomain_len: count = 40 &redef;
    const exfil_bytes_threshold: count = 10485760 &redef;  # 10MB
    const port_scan_threshold: count   = 20 &redef;
    const c2_beacon_interval: interval = 60 secs &redef;
}

# ─── DNS Tunneling Detection ─────────────────────────────────
event dns_request(c: connection, msg: dns_msg, qtype: count, qclass: count)
{
    if ( c$dns?$query ) {
        local q  = c$dns$query;
        local parts = split_string(q, /\./);

        # Check for abnormally long subdomains (DNS tunneling)
        for ( i in parts ) {
            if ( |parts[i]| > max_dns_subdomain_len ) {
                NOTICE([$note      = DNS_Tunneling,
                        $conn      = c,
                        $msg       = fmt("Long DNS subdomain: %s (len=%d) from %s",
                                         q, |parts[i]|, c$id$orig_h),
                        $identifier= cat(c$id$orig_h, q)]);
            }
        }

        # High-entropy subdomain detection
        if ( |q| > 60 ) {
            NOTICE([$note      = DNS_Tunneling,
                    $conn      = c,
                    $msg       = fmt("Suspicious long DNS query: %s from %s", q, c$id$orig_h),
                    $identifier= cat(c$id$orig_h)]);
        }
    }
}

# ─── Port Scan Detection ─────────────────────────────────────
global scan_table: table[addr] of set[port] &create_expire = 60 secs;

event connection_attempt(c: connection)
{
    local src = c$id$orig_h;
    local dst_port = c$id$resp_p;

    if ( src !in scan_table )
        scan_table[src] = set();

    add scan_table[src][dst_port];

    if ( |scan_table[src]| >= port_scan_threshold ) {
        NOTICE([$note      = PortScan,
                $src       = src,
                $msg       = fmt("Port scan: %s scanned %d ports",
                                  src, |scan_table[src]|),
                $identifier= cat(src)]);
        delete scan_table[src];
    }
}

# ─── Large Outbound Transfer (Data Exfiltration) ─────────────
event connection_state_remove(c: connection)
{
    if ( c$resp?$size && c$orig?$size ) {
        # Large data sent from internal host to external
        if ( c$orig$size > exfil_bytes_threshold &&
             is_local_addr(c$id$orig_h) &&
             !is_local_addr(c$id$resp_h) ) {

            NOTICE([$note      = DataExfiltration,
                    $conn      = c,
                    $msg       = fmt("Large outbound transfer: %s -> %s:%d bytes=%d",
                                      c$id$orig_h, c$id$resp_h,
                                      c$id$resp_p, c$orig$size),
                    $identifier= cat(c$id$orig_h, c$id$resp_h)]);
        }
    }
}

# ─── SMB Lateral Movement Detection ─────────────────────────
event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool)
{
    if ( is_local_addr(c$id$orig_h) && is_local_addr(c$id$resp_h) ) {
        NOTICE([$note      = LateralMovement_SMB,
                $conn      = c,
                $msg       = fmt("Internal SMB connection: %s -> %s (possible lateral movement)",
                                  c$id$orig_h, c$id$resp_h),
                $identifier= cat(c$id$orig_h, c$id$resp_h)]);
    }
}

# ─── Log all HTTP requests to external IPs ────────────────────
event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
{
    # Log suspicious user agents
    if ( c$http?$user_agent ) {
        local ua = c$http$user_agent;
        if ( /python-requests|curl|wget|nikto|sqlmap|nmap|masscan/ in ua ) {
            print fmt("[SUSPICIOUS UA] src=%s method=%s uri=%s ua=%s",
                       c$id$orig_h, method, original_URI, ua);
        }
    }
}

# ─── JSON Log Output for SentinelAI ──────────────────────────
hook Notice::policy(n: Notice::Info)
{
    # Forward all notices to SentinelAI log file
    local entry = fmt("{\"ts\":\"%s\",\"note\":\"%s\",\"msg\":\"%s\",\"src\":\"%s\"}",
                       n$ts, n$note, n$msg,
                       n?$src ? cat(n$src) : "unknown");
    print dns_query_log_file, entry;
}
