package service

// SystemdTemplates contains all systemd unit file templates
const (
	// IpsetRestoreServiceTemplate is the systemd service for restoring ipset on boot
	IpsetRestoreServiceTemplate = `[Unit]
Description=Restore TrafficGuard ipset configuration
Before=ufw.service
Before=netfilter-persistent.service
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/ipset restore -exist -f /etc/ipset.conf
ExecStart=-/usr/sbin/iptables -N SCANNERS-BLOCK
ExecStart=-/usr/sbin/ip6tables -N SCANNERS-BLOCK

[Install]
WantedBy=multi-user.target
RequiredBy=netfilter-persistent.service
`

	// MoveRulesServiceTemplate is the systemd service for moving SCANNERS-BLOCK to position 1
	MoveRulesServiceTemplate = `[Unit]
Description=Move TrafficGuard rules to position 1 in UFW chains
After=ufw.service
After=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sleep 2
ExecStart=-/usr/sbin/iptables -D ufw-before-input -j SCANNERS-BLOCK
ExecStart=/usr/sbin/iptables -I ufw-before-input 1 -j SCANNERS-BLOCK
ExecStart=-/usr/sbin/ip6tables -D ufw6-before-input -j SCANNERS-BLOCK
ExecStart=/usr/sbin/ip6tables -I ufw6-before-input 1 -j SCANNERS-BLOCK

[Install]
WantedBy=multi-user.target
`

	// AggregateLogsServiceTemplate is the systemd service for log aggregation
	AggregateLogsServiceTemplate = `[Unit]
Description=TrafficGuard Log Aggregator
After=rsyslog.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/antiscan-aggregate-logs.sh
StandardOutput=journal
StandardError=journal
`

	// AggregateLogsTimerTemplate is the systemd timer for log aggregation
	AggregateLogsTimerTemplate = `[Unit]
Description=TrafficGuard Log Aggregator Timer
Requires=antiscan-aggregate.service

[Timer]
OnBootSec=1min
OnUnitActiveSec=30sec
AccuracySec=5sec

[Install]
WantedBy=timers.target
`

	// AggregateLogsScriptTemplate is the bash script for log aggregation
	AggregateLogsScriptTemplate = `#!/bin/bash
# TrafficGuard Log Aggregation Script
# Full dump of all requests with ASN/netname lookup
#
# Output CSV format: DATETIME|IP_ADDRESS|ASN|NETNAME|PORT|
# Example: 2026-01-26T12:34:56|1.2.3.4|AS12345|EXAMPLE-NET|22|
#
# Features:
# - Whois lookup with caching (RIPE database with auto-referrals)
# - Atomic log rotation (grab -> clear -> process)
# - Appends each request as individual record

set -uo pipefail

# Configuration
IPV4_LOG="/var/log/iptables-scanners-ipv4.log"
IPV6_LOG="/var/log/iptables-scanners-ipv6.log"
OUTPUT_CSV="/var/log/iptables-scanners-aggregate.csv"
WHOIS_CACHE="/tmp/antiscan-whois-cache.txt"
TEMP_IPV4="/tmp/antiscan-ipv4-$$.tmp"
TEMP_IPV6="/tmp/antiscan-ipv6-$$.tmp"

# Create whois cache if doesn't exist, clean if older than 1 day
if [ -f "$WHOIS_CACHE" ]; then
    find "$WHOIS_CACHE" -mtime +1 -delete 2>/dev/null || true
fi
touch "$WHOIS_CACHE"

# Grab content and immediately clear (atomic as possible)
if [ -f "$IPV4_LOG" ]; then
    cat "$IPV4_LOG" > "$TEMP_IPV4"
    > "$IPV4_LOG"
    chown syslog:adm "$IPV4_LOG" 2>/dev/null || true
    chmod 640 "$IPV4_LOG" 2>/dev/null || true
fi

if [ -f "$IPV6_LOG" ]; then
    cat "$IPV6_LOG" > "$TEMP_IPV6"
    > "$IPV6_LOG"
    chown syslog:adm "$IPV6_LOG" 2>/dev/null || true
    chmod 640 "$IPV6_LOG" 2>/dev/null || true
fi

# Function to get ASN and netname from IP with caching
get_ip_info() {
    local ip="$1"

    # Check cache first
    local cached=$(grep "^${ip}|" "$WHOIS_CACHE" 2>/dev/null | head -1)
    if [ -n "$cached" ]; then
        echo "$cached" | cut -d'|' -f2-
        return
    fi

    local asn=""
    local netname=""

    # Always use RIPE (most comprehensive database with auto-referrals)
    local whois_server="whois.ripe.net"

    # Try whois lookup with timeout
    local whois_output=$(timeout 3 whois -h "$whois_server" "$ip" 2>/dev/null || echo "")

    if [ -n "$whois_output" ]; then
        asn=$(echo "$whois_output" | grep -iE "^origin:" | head -1 | awk '{print $2}' | sed 's/AS//gi' | tr -d '\r\n ')
        netname=$(echo "$whois_output" | grep -iE "^netname:" | head -1 | awk '{print $2}' | tr -d '\r\n')
    fi

    # Validate ASN is numeric
    if [ -n "$asn" ] && ! echo "$asn" | grep -qE '^[0-9]+$'; then
        asn=""
    fi

    [ -z "$asn" ] && asn="UNKNOWN"
    [ -z "$netname" ] && netname="UNKNOWN"

    if [ "$asn" != "UNKNOWN" ] && ! echo "$asn" | grep -q "^AS"; then
        asn="AS${asn}"
    fi

    echo "${ip}|${asn}|${netname}" >> "$WHOIS_CACHE"
    echo "${asn}|${netname}"
}

# Create CSV header if file doesn't exist
if [ ! -f "$OUTPUT_CSV" ]; then
    echo "DATETIME|IP_ADDRESS|ASN|NETNAME|PORT|" > "$OUTPUT_CSV"
fi

# Process each log line individually and append to CSV
process_log() {
    local tmpfile="$1"
    local pattern="$2"

    grep "$pattern" "$tmpfile" 2>/dev/null | while IFS= read -r line; do
        # Extract timestamp: ISO format (first field) or traditional syslog (first three fields)
        tm=$(echo "$line" | awk '{
            if ($1 ~ /^[0-9][0-9][0-9][0-9]-/) { print $1 }
            else { print $1, $2, $3 }
        }')

        # Extract source IP
        ip=$(echo "$line" | grep -oE 'SRC=[0-9a-fA-F:.]+' | head -1 | cut -d'=' -f2)
        [ -z "$ip" ] && continue

        # Extract destination port
        port=$(echo "$line" | grep -oE 'DPT=[0-9]+' | head -1 | cut -d'=' -f2)
        [ -z "$port" ] && port="UNKNOWN"

        info=$(get_ip_info "$ip")
        echo "${tm}|${ip}|${info}|${port}|" >> "$OUTPUT_CSV"
    done
}

if [ -f "$TEMP_IPV4" ] && [ -s "$TEMP_IPV4" ]; then
    process_log "$TEMP_IPV4" "ANTISCAN-v4:"
fi

if [ -f "$TEMP_IPV6" ] && [ -s "$TEMP_IPV6" ]; then
    process_log "$TEMP_IPV6" "ANTISCAN-v6:"
fi

# Cleanup
rm -f "$TEMP_IPV4" "$TEMP_IPV6"

exit 0
`

	// RsyslogConfigTemplate is the rsyslog configuration for iptables logging
	RsyslogConfigTemplate = `:msg, contains, "ANTISCAN-v4: " /var/log/iptables-scanners-ipv4.log
:msg, contains, "ANTISCAN-v6: " /var/log/iptables-scanners-ipv6.log
& stop
`

	// LogrotateConfigTemplate is the logrotate configuration
	LogrotateConfigTemplate = `/var/log/iptables-scanners-*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}

/var/log/iptables-scanners-aggregate.csv {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root adm
}
`
)

// SystemdServicePaths contains paths to systemd service files
const (
	IpsetRestoreServicePath  = "/etc/systemd/system/antiscan-ipset-restore.service"
	MoveRulesServicePath     = "/etc/systemd/system/antiscan-move-rules.service"
	AggregateLogsServicePath = "/etc/systemd/system/antiscan-aggregate.service"
	AggregateLogsTimerPath   = "/etc/systemd/system/antiscan-aggregate.timer"
	AggregateLogsScriptPath  = "/usr/local/bin/antiscan-aggregate-logs.sh"
	RsyslogConfigPath        = "/etc/rsyslog.d/10-iptables-scanners.conf"
	LogrotateConfigPath      = "/etc/logrotate.d/iptables-scanners"
)

// UFWBeforeRulesTemplates contains templates for UFW before.rules
const (
	// UFWBeforeRulesHeader is the header for SCANNERS-BLOCK in UFW before.rules
	UFWBeforeRulesHeader = `
# SCANNERS-BLOCK chain - managed by antiscan
:SCANNERS-BLOCK - [0:0]
-A ufw-before-input -j SCANNERS-BLOCK
`

	// UFWBeforeRulesFooter is the footer for SCANNERS-BLOCK in UFW before.rules
	UFWBeforeRulesFooter = `# END SCANNERS-BLOCK
`

	// UFW6BeforeRulesHeader is the header for SCANNERS-BLOCK in UFW before6.rules
	UFW6BeforeRulesHeader = `
# SCANNERS-BLOCK chain - managed by antiscan
:SCANNERS-BLOCK - [0:0]
-A ufw6-before-input -j SCANNERS-BLOCK
`

	// UFW6BeforeRulesFooter is the footer for SCANNERS-BLOCK in UFW before6.rules
	UFW6BeforeRulesFooter = `# END SCANNERS-BLOCK
`
)

// IpsetConfigPaths contains paths for ipset configuration
const (
	IpsetConfigPath     = "/etc/ipset.conf"
	IpsetConfigPathAlt  = "/etc/iptables/ipsets"
	IptablesRulesV4Path = "/etc/iptables/rules.v4"
	IptablesRulesV6Path = "/etc/iptables/rules.v6"
	UFWBeforeRulesPath  = "/etc/ufw/before.rules"
	UFW6BeforeRulesPath = "/etc/ufw/before6.rules"
)

// LogPaths contains paths for log files
const (
	IPv4LogPath      = "/var/log/iptables-scanners-ipv4.log"
	IPv6LogPath      = "/var/log/iptables-scanners-ipv6.log"
	AggregateLogPath = "/var/log/iptables-scanners-aggregate.csv"
)
