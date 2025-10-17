#!/usr/bin/with-contenv bashio

# Enable debugging for unexpected exits
trap 'logger "DEBUG: Script exiting at line $LINENO with exit code $?" 1' EXIT

# SIGTERM-handler this function will be executed when the container receives the SIGTERM signal (when stopping)
term_handler(){
	logger "Stopping Home Assistant Access Point" 0
	# Clean up iptables rules if they were added
	if $(bashio::config.true "client_internet_access"); then
		iptables-nft -t nat -D POSTROUTING -o $DEFAULT_ROUTE_INTERFACE -j MASQUERADE 2>/dev/null || true
		iptables-nft -P FORWARD DROP 2>/dev/null || true
	fi
	# Clean up WiFi access rules
	iptables-nft -D INPUT -i $INTERFACE -j ACCEPT 2>/dev/null || true
	# Clean up network interface
	ifdown $INTERFACE 2>/dev/null || true
	ip link set $INTERFACE down 2>/dev/null || true
	ip addr flush dev $INTERFACE 2>/dev/null || true
	# Re-enable NetworkManager management
	nmcli dev set $INTERFACE managed yes 2>/dev/null || true
	exit 0
}

# Logging function to set verbosity of output to addon log
logger(){
    msg=$1
    level=$2
    if [ $DEBUG -ge $level ]; then
        echo $msg
    fi
}

CONFIG_PATH=/data/options.json

# Convert integer configs to boolean, to avoid a breaking old configs
declare -r bool_configs=( hide_ssid client_internet_access dhcp )
for i in $bool_configs ; do
    if bashio::config.true $i || bashio::config.false $i ; then
        continue
    elif [ $config_value -eq 0 ] ; then
        bashio::addon.option $config_value false
    else
        bashio::addon.option $config_value true
    fi
done

SSID=$(bashio::config "ssid")
WPA_PASSPHRASE=$(bashio::config "wpa_passphrase")
CHANNEL=$(bashio::config "channel")
ADDRESS=$(bashio::config "address")
NETMASK=$(bashio::config "netmask")
BROADCAST=$(bashio::config "broadcast")
INTERFACE=$(bashio::config "interface")
HIDE_SSID=$(bashio::config.false "hide_ssid"; echo $?)
DHCP=$(bashio::config.false "dhcp"; echo $?)
DHCP_START_ADDR=$(bashio::config "dhcp_start_addr" )
DHCP_END_ADDR=$(bashio::config "dhcp_end_addr" )
DNSMASQ_CONFIG_OVERRIDE=$(bashio::config 'dnsmasq_config_override' )
ALLOW_MAC_ADDRESSES=$(bashio::config 'allow_mac_addresses' )
DENY_MAC_ADDRESSES=$(bashio::config 'deny_mac_addresses' )
DEBUG=$(bashio::config 'debug' )
HOSTAPD_CONFIG_OVERRIDE=$(bashio::config 'hostapd_config_override' )
CLIENT_INTERNET_ACCESS=$(bashio::config.false 'client_internet_access'; echo $?)
CLIENT_DNS_OVERRIDE=$(bashio::config 'client_dns_override' )
DNSMASQ_CONFIG_OVERRIDE=$(bashio::config 'dnsmasq_config_override' )

# Get the Default Route interface
DEFAULT_ROUTE_INTERFACE=$(ip route show default | awk '/^default/ { print $5 }')

echo "Starting Home Assistant Access Point Addon"

# Pre-flight checks function
preflight_checks() {
    logger "=== Pre-flight System Checks ===" 1
    
    # Check if we're running with the right privileges
    if [ "$(id -u)" -ne 0 ]; then
        logger "Error: Must run as root for network configuration" 0
        return 1
    fi
    logger "✓ Running as root" 1
    
    # Check required commands
    local required_commands="hostapd iw ip"
    for cmd in $required_commands; do
        if ! command -v $cmd >/dev/null 2>&1; then
            logger "Error: Required command '$cmd' not found" 0
            return 1
        fi
    done
    logger "✓ Required commands available" 1
    
    # Check for RF kill blocks
    if command -v rfkill >/dev/null 2>&1; then
        # Try to access rfkill, handle permission errors gracefully
        blocked_devices=$(rfkill list 2>/dev/null | grep -E "(Wireless LAN|WiFi)" | grep "blocked: yes" || true)
        rfkill_status=$?
        
        if [ $rfkill_status -ne 0 ]; then
            logger "Warning: Cannot access rfkill (insufficient permissions) - continuing anyway" 1
        elif [ -n "$blocked_devices" ]; then
            logger "Warning: Some wireless devices are blocked by rfkill:" 1
            echo "$blocked_devices" | while read line; do logger "  $line" 1; done
            logger "Attempting to unblock..." 1
            rfkill unblock wifi 2>/dev/null || logger "Failed to unblock WiFi devices (insufficient permissions)" 1
        else
            logger "✓ No wireless devices blocked by rfkill" 1
        fi
    else
        logger "Warning: rfkill command not available - skipping RF kill check" 1
    fi
    
    logger "✓ Pre-flight checks completed" 1
    logger "================================" 1
    return 0
}

# Run pre-flight checks
if ! preflight_checks; then
    logger "Pre-flight checks failed, cannot continue" 0
    exit 1
fi

# Diagnostic information
logger "=== System Diagnostics ===" 1
logger "Home Assistant Access Point v0.6.12" 1
logger "Debug level: $DEBUG" 1
logger "Interface: $INTERFACE" 1
logger "SSID: '$SSID'" 1
logger "SSID length: ${#SSID}" 1
logger "WPA_PASSPHRASE length: ${#WPA_PASSPHRASE}" 1
logger "Channel: $CHANNEL" 1
logger "Address: $ADDRESS" 1

# Critical configuration check
if [ -z "$SSID" ]; then
    logger "CRITICAL ERROR: SSID is empty! Please configure the addon with your WiFi network name." 0
    logger "Go to the addon configuration and set 'ssid' to your desired WiFi network name." 0
    exit 1
fi

if [ -z "$WPA_PASSPHRASE" ]; then
    logger "CRITICAL ERROR: WPA_PASSPHRASE is empty! Please configure the addon with your WiFi password." 0
    logger "Go to the addon configuration and set 'wpa_passphrase' to your desired WiFi password (8+ chars)." 0
    exit 1
fi

logger "✓ Basic configuration appears valid" 1

# Check NetworkManager version
if command -v nmcli >/dev/null 2>&1; then
    NM_VERSION=$(nmcli --version 2>&1 || echo "unknown")
    logger "NetworkManager info: $NM_VERSION" 1
else
    logger "NetworkManager: not available" 1
fi

# Check available wireless interfaces
logger "Available wireless interfaces:" 1
if command -v iw >/dev/null 2>&1; then
    iw dev 2>/dev/null | grep Interface | awk '{print "  - " $2}' | while read line; do logger "$line" 1; done || logger "  No wireless interfaces found" 1
else
    logger "  iw command not available" 1
fi

# Check if hostapd is available
if command -v hostapd >/dev/null 2>&1; then
    HOSTAPD_VERSION=$(hostapd -v 2>&1 | head -n1 || echo "unknown")
    logger "hostapd: $HOSTAPD_VERSION" 1
else
    logger "Error: hostapd not found!" 0
    exit 1
fi
logger "=== End Diagnostics ===" 1

# Setup interface
logger "# Setup interface:" 1
logger "Add to /etc/network/interfaces: iface $INTERFACE inet static" 1
# Create and add our interface to interfaces file
echo "iface $INTERFACE inet static"$'\n' >> /etc/network/interfaces

logger "Run command: nmcli dev set $INTERFACE managed no" 1
# Check if NetworkManager is available and interface exists
if command -v nmcli >/dev/null 2>&1; then
    # Check for NetworkManager version mismatch and try to handle it
    nm_version_check=$(nmcli --version 2>&1 || true)
    if echo "$nm_version_check" | grep -q "Warning.*versions don't match"; then
        logger "Warning: NetworkManager version mismatch detected, attempting restart..." 1
        # Try to restart NetworkManager if possible
        systemctl restart NetworkManager 2>/dev/null || service NetworkManager restart 2>/dev/null || true
        sleep 2
    fi
    
    if nmcli dev status 2>/dev/null | grep -q "^$INTERFACE"; then
        logger "Interface $INTERFACE found in NetworkManager, setting unmanaged" 1
        nmcli dev set $INTERFACE managed no 2>/dev/null || logger "Warning: Failed to set interface unmanaged" 1
    else
        logger "Warning: Interface $INTERFACE not found in NetworkManager, continuing..." 1
        # List available interfaces for debugging
        logger "Available interfaces:" 1
        nmcli dev status 2>/dev/null | while read line; do logger "$line" 1; done || true
    fi
else
    logger "Warning: nmcli not available, skipping NetworkManager configuration" 1
fi

logger "Run command: ip link set $INTERFACE down" 1
ip link set $INTERFACE down

# Verify interface exists and get its status
if ! ip link show $INTERFACE >/dev/null 2>&1; then
    logger "Error: Network interface $INTERFACE does not exist!" 0
    logger "Available interfaces:" 0
    ip link show | grep "^[0-9]" | awk '{print $2}' | sed 's/:$//' | while read iface; do
        logger "  - $iface" 0
    done
    exit 1
fi

# Check if interface supports wireless and can do AP mode
logger "=== Wireless Interface Validation ===" 1
if ! iw dev $INTERFACE info >/dev/null 2>&1; then
    logger "Error: Interface $INTERFACE does not appear to be a wireless interface!" 0
    logger "Available wireless interfaces:" 0
    if command -v iw >/dev/null 2>&1; then
        available_interfaces=$(iw dev 2>/dev/null | grep Interface | awk '{print $2}')
        if [ -n "$available_interfaces" ]; then
            echo "$available_interfaces" | while read wiface; do
                logger "  - $wiface" 0
                # Check capabilities of each interface
                iw phy$(iw dev $wiface info | grep wiphy | awk '{print $2}') info 2>/dev/null | grep -A 10 "Supported interface modes:" | grep -q "AP" && logger "    (supports AP mode)" 0 || logger "    (does not support AP mode)" 0
            done
        else
            logger "  No wireless interfaces found!" 0
        fi
    else
        logger "  iw command not available" 0
    fi
    logger "Please check your configuration and set 'interface' to a valid wireless interface" 0
    exit 1
fi

# Check if interface supports AP mode
logger "Checking if $INTERFACE supports AP mode..." 1
phy_device=$(iw dev $INTERFACE info | grep wiphy | awk '{print $2}')
if iw phy phy$phy_device info 2>/dev/null | grep -A 10 "Supported interface modes:" | grep -q "AP"; then
    logger "✓ Interface $INTERFACE supports AP mode" 1
else
    logger "Error: Interface $INTERFACE does not support AP mode!" 0
    logger "This interface cannot create a WiFi access point" 0
    exit 1
fi

# Check if interface is already in use
current_mode=$(iw dev $INTERFACE info 2>/dev/null | grep type | awk '{print $2}')
if [ "$current_mode" != "managed" ] && [ "$current_mode" != "monitor" ]; then
    logger "Warning: Interface $INTERFACE is in '$current_mode' mode" 1
fi

logger "✓ Wireless interface validation passed" 1
logger "=====================================" 1

logger "Interface $INTERFACE validated successfully" 1

# Show current interface status before configuration
logger "Current interface status before configuration:" 1
ip addr show $INTERFACE | while read line; do logger "  $line" 1; done

logger "Add to /etc/network/interfaces: address $ADDRESS" 1
echo "address $ADDRESS"$'\n' >> /etc/network/interfaces
logger "Add to /etc/network/interfaces: netmask $NETMASK" 1
echo "netmask $NETMASK"$'\n' >> /etc/network/interfaces
logger "Add to /etc/network/interfaces: broadcast $BROADCAST" 1
echo "broadcast $BROADCAST"$'\n' >> /etc/network/interfaces

logger "Run command: ip link set $INTERFACE up" 1
ip link set $INTERFACE up

# Setup signal handlers
trap 'term_handler' SIGTERM

# Enforces required env variables and validate them
logger "=== Configuration Validation ===" 1
required_vars=(ssid wpa_passphrase channel address netmask broadcast)
for required_var in "${required_vars[@]}"; do
    bashio::config.require $required_var "An AP cannot be created without this information"
    eval "var_value=\$$(echo $required_var | tr '[:lower:]' '[:upper:]')"
    logger "$required_var: $var_value" 1
done

if [ -z "$SSID" ] || [ -z "$WPA_PASSPHRASE" ]; then
    logger "Error: SSID and WPA_PASSPHRASE are required but empty!" 0
    logger "Please configure your add-on with:" 0
    logger "  - ssid: Your WiFi Network Name" 0
    logger "  - wpa_passphrase: Your WiFi Password (8+ characters)" 0
    bashio::exit.nok "Missing required WiFi configuration!"
fi

if [ ${#WPA_PASSPHRASE} -lt 8 ] ; then
    logger "Error: WPA password is only ${#WPA_PASSPHRASE} characters long!" 0
    bashio::exit.nok "The WPA password must be at least 8 characters long!"
fi

logger "✓ Configuration validation passed" 1
logger "=================================" 1

# Setup hostapd.conf
logger "# Setup hostapd:" 1
logger "Add to hostapd.conf: ssid=$SSID" 1
echo "ssid=$SSID"$'\n' >> /hostapd.conf
logger "Add to hostapd.conf: wpa_passphrase=********" 1
echo "wpa_passphrase=$WPA_PASSPHRASE"$'\n' >> /hostapd.conf
logger "Add to hostapd.conf: channel=$CHANNEL" 1
echo "channel=$CHANNEL"'\n' >> /hostapd.conf
logger "Add to hostapd.conf: ignore_broadcast_ssid=$HIDE_SSID" 1
echo "ignore_broadcast_ssid=$HIDE_SSID"$'\n' >> /hostapd.conf

### MAC address filtering
## Allow is more restrictive, so we prioritise that and set
## macaddr_acl to 1, and add allowed MAC addresses to hostapd.allow
if [ ${#ALLOW_MAC_ADDRESSES} -ge 1 ]; then
    logger "Add to hostapd.conf: macaddr_acl=1" 1
    echo "macaddr_acl=1"$'\n' >> /hostapd.conf
    ALLOWED=($ALLOW_MAC_ADDRESSES)
    logger "# Setup hostapd.allow:" 1
    logger "Allowed MAC addresses:" 0
    for mac in "${ALLOWED[@]}"; do
        echo "$mac"$'\n' >> /hostapd.allow
        logger "$mac" 0
    done
    logger "Add to hostapd.conf: accept_mac_file=/hostapd.allow" 1
    echo "accept_mac_file=/hostapd.allow"$'\n' >> /hostapd.conf
## else set macaddr_acl to 0, and add denied MAC addresses to hostapd.deny
elif [ ${#DENY_MAC_ADDRESSES} -ge 1 ]; then
        logger "Add to hostapd.conf: macaddr_acl=0" 1
        echo "macaddr_acl=0"$'\n' >> /hostapd.conf
        DENIED=($DENY_MAC_ADDRESSES)
        logger "Denied MAC addresses:" 0
        for mac in "${DENIED[@]}"; do
            echo "$mac"$'\n' >> /hostapd.deny
            logger "$mac" 0
        done
        logger "Add to hostapd.conf: accept_mac_file=/hostapd.deny" 1
        echo "deny_mac_file=/hostapd.deny"$'\n' >> /hostapd.conf
## else set macaddr_acl to 0, with blank allow and deny files
else
    logger "Add to hostapd.conf: macaddr_acl=0" 1
    echo "macaddr_acl=0"$'\n' >> /hostapd.conf
fi


# Function to convert netmask to CIDR notation for modern ip command
netmask_to_cidr() {
    local netmask=$1
    local cidr=0
    local octet
    
    IFS='.' read -ra octets <<< "$netmask"
    for octet in "${octets[@]}"; do
        case $octet in
            255) cidr=$((cidr + 8)) ;;
            254) cidr=$((cidr + 7)) ;;
            252) cidr=$((cidr + 6)) ;;
            248) cidr=$((cidr + 5)) ;;
            240) cidr=$((cidr + 4)) ;;
            224) cidr=$((cidr + 3)) ;;
            192) cidr=$((cidr + 2)) ;;
            128) cidr=$((cidr + 1)) ;;
            0) ;;
            *) cidr=24; break ;;
        esac
    done
    echo $cidr
}

# Function to configure interface IP address
configure_interface_ip() {
    logger "Configuring IP address for interface $INTERFACE" 1
    
    # First flush any existing IP addresses
    ip addr flush dev $INTERFACE 2>/dev/null || true
    
    CIDR=$(netmask_to_cidr "$NETMASK")
    logger "Using CIDR: /$CIDR for netmask $NETMASK" 1
    
    # Try to set IP using ip command (modern approach)
    if ip addr add $ADDRESS/$CIDR dev $INTERFACE broadcast $BROADCAST 2>/dev/null; then
        logger "Successfully set IP address using ip command" 1
    else
        logger "ip command failed, trying ifconfig..." 1
        if ifconfig $INTERFACE $ADDRESS netmask $NETMASK broadcast $BROADCAST 2>/dev/null; then
            logger "Successfully set IP address using ifconfig" 1
        else
            logger "Error: Failed to set IP address with both ip and ifconfig!" 0
            return 1
        fi
    fi
    
    # Ensure interface is up
    ip link set $INTERFACE up
    
    # Verify IP was set correctly
    sleep 1
    current_ip=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
    if [ "$current_ip" = "$ADDRESS" ]; then
        logger "✓ IP address $ADDRESS successfully configured on $INTERFACE" 1
        return 0
    else
        logger "Error: IP verification failed. Expected: $ADDRESS, Got: $current_ip" 0
        return 1
    fi
}

# Configure IP - this will be called later after hostapd setup

# Add interface to hostapd.conf
logger "Add to hostapd.conf: interface=$INTERFACE" 1
echo "interface=$INTERFACE"$'\n' >> /hostapd.conf

# Append override options to hostapd.conf
if [ ${#HOSTAPD_CONFIG_OVERRIDE} -ge 1 ]; then
    logger "# Custom hostapd config options:" 0
    HOSTAPD_OVERRIDES=($HOSTAPD_CONFIG_OVERRIDE)
    for override in "${HOSTAPD_OVERRIDES[@]}"; do
        echo "$override"$'\n' >> /hostapd.conf
        logger "Add to hostapd.conf: $override" 0
    done
fi

# Setup dnsmasq.conf if DHCP is enabled in config
if $(bashio::config.true "dhcp"); then
    logger "# DHCP enabled. Setup dnsmasq:" 1
    logger "Add to dnsmasq.conf: dhcp-range=$DHCP_START_ADDR,$DHCP_END_ADDR,12h" 1
        echo "dhcp-range=$DHCP_START_ADDR,$DHCP_END_ADDR,12h"$'\n' >> /dnsmasq.conf
        logger "Add to dnsmasq.conf: interface=$INTERFACE" 1
        echo "interface=$INTERFACE"$'\n' >> /dnsmasq.conf

    ## DNS
    dns_array=()
        if [ ${#CLIENT_DNS_OVERRIDE} -ge 1 ]; then
            dns_string="dhcp-option=6"
            DNS_OVERRIDES=($CLIENT_DNS_OVERRIDE)
            for override in "${DNS_OVERRIDES[@]}"; do
                dns_string+=",$override"
            done
            echo "$dns_string"$'\n' >> /dnsmasq.conf
            logger "Add custom DNS: $dns_string" 0
        else
            # Get DNS servers from NetworkManager - improved for newer versions
            IFS=$'\n' read -r -d '' -a dns_array < <( (nmcli device show | grep IP4.DNS | awk '{print $2}' || nmcli con show --active | grep IP4.DNS | awk '{print $2}') && printf '\0' )

            if [ ${#dns_array[@]} -eq 0 ]; then
                # Fallback to resolv.conf if NetworkManager doesn't provide DNS
                IFS=$'\n' read -r -d '' -a dns_array < <( grep "^nameserver" /etc/resolv.conf | awk '{print $2}' && printf '\0' )
                logger "Using DNS servers from /etc/resolv.conf as fallback" 1
            fi

            if [ ${#dns_array[@]} -eq 0 ]; then
                logger "Couldn't get DNS servers from host. Consider setting with 'client_dns_override' config option." 0
                # Use Google DNS as last resort but don't add it if we might have DNS conflicts
                logger "Skipping DNS configuration to avoid conflicts with port=0 setting" 1
            else
                # Only add DNS servers if we have them and they're valid
                dns_string="dhcp-option=6"
                valid_dns_count=0
                for dns_entry in "${dns_array[@]}"; do
                    # Validate IP address format
                    if [[ $dns_entry =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                        dns_string+=",$dns_entry"
                        valid_dns_count=$((valid_dns_count + 1))
                    fi
                done
                
                if [ $valid_dns_count -gt 0 ]; then
                    echo "$dns_string"$'\n' >> /dnsmasq.conf
                    logger "Add DNS: $dns_string" 0
                else
                    logger "No valid DNS servers found, skipping DNS configuration" 1
                fi
            fi

        fi

    # Append override options to dnsmasq.conf
    if [ ${#DNSMASQ_CONFIG_OVERRIDE} -ge 1 ]; then
        logger "# Custom dnsmasq config options:" 0
        DNSMASQ_OVERRIDES=($DNSMASQ_CONFIG_OVERRIDE)
        for override in "${DNSMASQ_OVERRIDES[@]}"; do
            echo "$override"$'\n' >> /dnsmasq.conf
            logger "Add to dnsmasq.conf: $override" 0
        done
    fi
else
	logger "# DHCP not enabled. Skipping dnsmasq" 1
fi

# Setup Client Internet Access
if $(bashio::config.true "client_internet_access"); then
    logger "# Setting up client internet access" 1
    
    # Ensure we have a default route interface
    if [ -z "$DEFAULT_ROUTE_INTERFACE" ]; then
        DEFAULT_ROUTE_INTERFACE=$(ip route show default | awk '/^default/ { print $5 }' | head -n1)
        logger "Default route interface: $DEFAULT_ROUTE_INTERFACE" 1
    fi
    
    if [ -n "$DEFAULT_ROUTE_INTERFACE" ]; then
        ## Route traffic - using newer iptables-nft commands
        logger "Setting up NAT masquerading on $DEFAULT_ROUTE_INTERFACE" 1
        iptables-nft -t nat -A POSTROUTING -o $DEFAULT_ROUTE_INTERFACE -j MASQUERADE
        iptables-nft -A FORWARD -i $INTERFACE -o $DEFAULT_ROUTE_INTERFACE -j ACCEPT
        iptables-nft -A FORWARD -i $DEFAULT_ROUTE_INTERFACE -o $INTERFACE -m state --state RELATED,ESTABLISHED -j ACCEPT
    else
        logger "Warning: No default route interface found, client internet access may not work" 0
    fi
fi

# Enable IP forwarding for proper routing
logger "Enabling IP forwarding" 1
if ! echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null; then
    logger "Warning: Cannot write to /proc/sys/net/ipv4/ip_forward (read-only filesystem)" 1
    logger "IP forwarding may already be enabled by the host system" 1
    current_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "unknown")
    logger "Current ip_forward value: $current_forward" 1
fi

# Add basic routing rule to allow WiFi clients to reach the host
logger "Setting up basic routing for WiFi clients" 1
# Allow traffic from WiFi interface to reach local services
iptables-nft -A INPUT -i $INTERFACE -j ACCEPT 2>/dev/null || true

# Start dnsmasq if DHCP is enabled in config
if $(bashio::config.true "dhcp"); then
    logger "## Starting dnsmasq daemon" 1
    
    # Show dnsmasq configuration if debug enabled
    if [ $DEBUG -gt 0 ]; then
        logger "dnsmasq configuration:" 1
        cat /dnsmasq.conf | while read line; do logger "  $line" 1; done
    fi
    
    # Test dnsmasq configuration
    logger "Testing dnsmasq configuration..." 1
    dnsmasq_test_output=$(dnsmasq --test -C /dnsmasq.conf 2>&1)
    dnsmasq_test_result=$?
    logger "dnsmasq test output: $dnsmasq_test_output" 1
    if [ $dnsmasq_test_result -eq 0 ]; then
        logger "✓ dnsmasq configuration test passed" 1
    else
        logger "⚠ Warning: dnsmasq configuration test failed (exit code: $dnsmasq_test_result)" 1
        logger "dnsmasq may still work, continuing..." 1
    fi
    
    # Debug: Show where we are in the script
    logger "=== DEBUG: About to check interface IP ===" 1
    
    # Verify interface has IP before starting dnsmasq
    logger "Checking interface $INTERFACE for IP address..." 1
    interface_ip=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
    logger "Interface IP check result: '$interface_ip'" 1
    
    if [ -z "$interface_ip" ]; then
        logger "Warning: Interface $INTERFACE has no IP address for DHCP!" 0
        logger "Attempting to configure IP address again..." 1
        # Try to configure the interface IP again
        configure_interface_ip "$ADDRESS" "$NETMASK" "$BROADCAST" "$INTERFACE"
        # Check again after configuration attempt
        interface_ip=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}' | cut -d'/' -f1)
        if [ -z "$interface_ip" ]; then
            logger "Error: Still no IP address on $INTERFACE after retry. DHCP may not work properly." 0
            logger "Continuing anyway - AP might still work without DHCP..." 1
        else
            logger "✓ IP address configured after retry: $interface_ip" 1
        fi
    else
        logger "Interface $INTERFACE has IP $interface_ip, starting dnsmasq..." 1
    fi
    
    # Check what might be using DHCP/DNS ports before starting dnsmasq
    logger "=== Pre-dnsmasq Port Diagnostics ===" 1
    dhcp_conflicts=$(netstat -ul 2>/dev/null | grep ":67 " || true)
    dns_conflicts=$(netstat -ul 2>/dev/null | grep ":53 " || true)
    
    if [ -n "$dhcp_conflicts" ]; then
        logger "Warning: Port 67 (DHCP) appears to be in use:" 1
        logger "$dhcp_conflicts" 1
    fi
    
    if [ -n "$dns_conflicts" ]; then
        logger "Warning: Port 53 (DNS) appears to be in use:" 1
        logger "$dns_conflicts" 1
    fi
    
    # Try to start dnsmasq with verbose logging to capture any errors
    logger "Starting dnsmasq with enhanced error logging..." 1
    dnsmasq_log=$(dnsmasq -C /dnsmasq.conf --log-facility=- 2>&1 &)
    DNSMASQ_PID=$!
    logger "dnsmasq started with PID: $DNSMASQ_PID" 1
    
    # Give dnsmasq a moment to start and verify it's running
    sleep 3
    if ! kill -0 $DNSMASQ_PID 2>/dev/null; then
        logger "Error: dnsmasq failed to start or crashed!" 0
        logger "DHCP will not work. Check dnsmasq configuration above." 0
        logger "dnsmasq error output: $dnsmasq_log" 0
        logger "=== Trying dnsmasq without DNS (DHCP only) ===" 1
        # Try starting dnsmasq with DNS disabled (port=0)
        echo "port=0" >> /dnsmasq.conf
        dnsmasq -C /dnsmasq.conf &
        DNSMASQ_PID=$!
        sleep 2
        if ! kill -0 $DNSMASQ_PID 2>/dev/null; then
            logger "Error: Even DHCP-only dnsmasq failed to start" 0
            # Don't exit here, AP might still work without DHCP
        else
            logger "✓ dnsmasq started in DHCP-only mode" 1
        fi
    else
        logger "✓ dnsmasq appears to be running and DHCP should be available" 1
        # Try to verify dnsmasq is listening
        if netstat -ul | grep -q ":67 "; then
            logger "✓ dnsmasq is listening on DHCP port 67" 1
        else
            logger "⚠ Warning: dnsmasq may not be listening on DHCP port" 1
        fi
    fi
else
    logger "## DHCP disabled, skipping dnsmasq" 1
fi

logger "## Starting hostapd daemon" 1

# Show final hostapd configuration for debugging
logger "=== hostapd Configuration ===" 1
logger "Final hostapd configuration:" 1
cat /hostapd.conf | while read line; do logger "  $line" 1; done
logger "=============================" 1

# Verify hostapd configuration before starting
logger "Validating hostapd configuration..." 1
hostapd_validation=$(hostapd -t /hostapd.conf 2>&1)
if [ $? -ne 0 ]; then
    logger "Error: hostapd configuration validation failed!" 0
    logger "Validation output:" 0
    echo "$hostapd_validation" | while read line; do logger "  $line" 0; done
    logger "Configuration file contents:" 0
    cat /hostapd.conf | while read line; do logger "  $line" 0; done
    
    # Common troubleshooting tips
    logger "=== Troubleshooting Tips ===" 0
    logger "1. Check if the wireless interface name is correct" 0
    logger "2. Verify the channel is supported by your WiFi adapter" 0
    logger "3. Make sure no other process is using the interface" 0
    logger "4. Try a different channel (1, 6, or 11 are common)" 0
    logger "============================" 0
    exit 1
fi
logger "✓ hostapd configuration validation passed" 1

# Ensure interface is ready for hostapd
logger "Preparing interface $INTERFACE for hostapd..." 1
ip link set $INTERFACE up
sleep 1

# Check if another process is using the interface
if pgrep -f "hostapd.*$INTERFACE" >/dev/null; then
    logger "Warning: Another hostapd process may be running on $INTERFACE" 0
    pkill -f "hostapd.*$INTERFACE" 2>/dev/null || true
    sleep 2
fi

# Final pre-hostapd diagnostics
logger "=== Pre-hostapd Interface Status ===" 1
logger "Interface: $INTERFACE" 1
logger "Interface status: $(ip link show $INTERFACE 2>/dev/null | head -1 || echo 'NOT FOUND')" 1
logger "IP configuration: $(ip addr show $INTERFACE 2>/dev/null | grep inet || echo 'NO IP')" 1
logger "Wireless capabilities: $(iw $INTERFACE info 2>/dev/null | grep -E 'wiphy|type|channel' || echo 'NO WIRELESS INFO')" 1
logger "hostapd config check: $(hostapd -t /hostapd.conf 2>&1 || echo 'CONFIG INVALID')" 1
logger "===================================" 1

# If debug level is greater than 1, start hostapd in debug mode
if [ $DEBUG -gt 1 ]; then
    logger "Starting hostapd in debug mode" 1
    hostapd -d /hostapd.conf & 
    HOSTAPD_PID=$!
    logger "hostapd started with PID: $HOSTAPD_PID" 1
    wait ${HOSTAPD_PID}
else
    logger "=== STARTING HOSTAPD DAEMON ===" 1
    logger "About to start hostapd with config: /hostapd.conf" 1
    
    # Show the actual hostapd config if debug enabled
    if [ $DEBUG -gt 0 ]; then
        logger "hostapd.conf contents:" 1
        cat /hostapd.conf | while read line; do logger "  $line" 1; done
    fi
    
    # Start hostapd and capture any immediate errors
    logger "Executing: hostapd /hostapd.conf &" 1
    hostapd /hostapd.conf &
    HOSTAPD_PID=$!
    logger "hostapd started with PID: $HOSTAPD_PID" 1
    logger "Waiting for hostapd to initialize..." 1
    
    # Give hostapd progressive time to start and monitor it
    check_count=0
    max_checks=10
    while [ $check_count -lt $max_checks ]; do
        sleep 1
        check_count=$((check_count + 1))
        
        if ! kill -0 $HOSTAPD_PID 2>/dev/null; then
            logger "Error: hostapd process (PID: $HOSTAPD_PID) has died!" 0
            logger "This usually means:" 0
            logger "  1. Wrong interface name or interface not available" 0
            logger "  2. Interface is busy/in use by another process" 0
            logger "  3. Channel not supported by the wireless adapter" 0
            logger "  4. Invalid hostapd configuration" 0
            logger "Check logs above for specific error messages" 0
            exit 1
        fi
        
        # Check if hostapd has successfully enabled the AP
        if iw dev $INTERFACE info 2>/dev/null | grep -q "type AP"; then
            logger "✓ hostapd successfully enabled AP mode on $INTERFACE" 1
            break
        fi
        
        if [ $check_count -eq 5 ]; then
            logger "hostapd is running but AP mode not yet active, waiting..." 1
        fi
    done
    
    if [ $check_count -eq $max_checks ]; then
        logger "Warning: hostapd is running but AP mode verification timed out" 1
    else
        logger "✓ hostapd appears to be running successfully" 1
    fi
    
    # Wait a bit for hostapd to fully initialize, then configure IP
    sleep 3
    logger "Configuring interface IP address now that hostapd is running..." 1
    if ! configure_interface_ip; then
        logger "Error: Failed to configure IP address, stopping..." 0
        kill $HOSTAPD_PID 2>/dev/null || true
        exit 1
    fi
    
    # Wait a bit more then check if AP is actually broadcasting
    sleep 2
    logger "Checking if access point is broadcasting..." 1
    if command -v iw >/dev/null 2>&1; then
        if iw dev $INTERFACE info | grep -q "type AP"; then
            logger "✓ Interface $INTERFACE is in AP mode" 1
        else
            logger "⚠ Warning: Interface $INTERFACE may not be in AP mode" 1
        fi
        
        # Show interface status for debugging
        logger "Interface status:" 1
        iw dev $INTERFACE info | while read line; do logger "  $line" 1; done
        
        # Show IP configuration
        logger "IP configuration:" 1
        ip addr show $INTERFACE | grep "inet " | while read line; do logger "  $line" 1; done
    fi
    
    # Final status check before entering wait loop
    logger "=== Final Status Check ===" 1
    logger "hostapd PID: $HOSTAPD_PID" 1
    if [ -n "$DNSMASQ_PID" ]; then
        logger "dnsmasq PID: $DNSMASQ_PID" 1
    fi
    logger "Interface IP: $(ip addr show $INTERFACE | grep 'inet ' | awk '{print $2}')" 1
    logger "Access Point should be available at: $ADDRESS" 1
    logger "SSID: $SSID" 1
    logger "=========================" 1
    logger "=== SCRIPT REACHED WAIT PHASE ===" 1
    logger "About to wait for hostapd PID: $HOSTAPD_PID" 1
    logger "If script stops here, hostapd is running in background" 1
    
    wait ${HOSTAPD_PID}
fi

# If we reach this point, hostapd has exited - clean up
logger "hostapd has exited, cleaning up..." 0
term_handler
