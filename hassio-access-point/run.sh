#!/usr/bin/with-contenv bashio

# SIGTERM-handler this function will be executed when the container receives the SIGTERM signal (when stopping)
term_handler(){
	logger "Stopping Home Assistant Access Point" 0
	# Clean up iptables rules if they were added
	if $(bashio::config.true "client_internet_access"); then
		iptables-nft -t nat -D POSTROUTING -o $DEFAULT_ROUTE_INTERFACE -j MASQUERADE 2>/dev/null || true
		iptables-nft -P FORWARD DROP 2>/dev/null || true
	fi
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

# Setup interface
logger "# Setup interface:" 1
logger "Add to /etc/network/interfaces: iface $INTERFACE inet static" 1
# Create and add our interface to interfaces file
echo "iface $INTERFACE inet static"$'\n' >> /etc/network/interfaces

logger "Run command: nmcli dev set $INTERFACE managed no" 1
# Check if NetworkManager is available and interface exists
if nmcli dev status | grep -q "^$INTERFACE"; then
    nmcli dev set $INTERFACE managed no
else
    logger "Warning: Interface $INTERFACE not found in NetworkManager, continuing..." 1
fi

logger "Run command: ip link set $INTERFACE down" 1
ip link set $INTERFACE down

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

# Enforces required env variables
required_vars=(ssid wpa_passphrase channel address netmask broadcast)
for required_var in "${required_vars[@]}"; do
    bashio::config.require $required_var "An AP cannot be created without this information"
done

if [ ${#WPA_PASSPHRASE} -lt 8 ] ; then
    bashio::exit.nok "The WPA password must be at least 8 characters long!"
fi

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


# Set address for the selected interface. Not sure why this is now not being set via /etc/network/interfaces, but maybe interfaces file is no longer required...
logger "Setting IP address for interface $INTERFACE" 1

# Convert netmask to CIDR notation for modern ip command
# Function to convert netmask to CIDR
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

CIDR=$(netmask_to_cidr "$NETMASK")

if ! ifconfig $INTERFACE $ADDRESS netmask $NETMASK broadcast $BROADCAST 2>/dev/null; then
    logger "Warning: Failed to set IP address via ifconfig, trying ip command" 1
    ip addr add $ADDRESS/$CIDR dev $INTERFACE broadcast $BROADCAST
    ip link set $INTERFACE up
fi

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
                # Use Google DNS as last resort
                dns_array=("8.8.8.8" "8.8.4.4")
                logger "Using Google DNS servers as last resort" 1
            else
                dns_string="dhcp-option=6"
                for dns_entry in "${dns_array[@]}"; do
                    # Validate IP address format
                    if [[ $dns_entry =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                        dns_string+=",$dns_entry"
                    fi
                done
                echo "$dns_string"$'\n' >> /dnsmasq.conf
                logger "Add DNS: $dns_string" 0
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

# Start dnsmasq if DHCP is enabled in config
if $(bashio::config.true "dhcp"); then
    logger "## Starting dnsmasq daemon" 1
    dnsmasq -C /dnsmasq.conf
fi

logger "## Starting hostapd daemon" 1
# Verify hostapd configuration before starting
if ! hostapd -t /hostapd.conf; then
    logger "Error: hostapd configuration validation failed" 0
    exit 1
fi

# If debug level is greater than 1, start hostapd in debug mode
if [ $DEBUG -gt 1 ]; then
    logger "Starting hostapd in debug mode" 1
    hostapd -d /hostapd.conf & wait ${!}
else
    logger "Starting hostapd daemon" 1
    hostapd /hostapd.conf & wait ${!}
fi

# If we reach this point, hostapd has exited - clean up
logger "hostapd has exited, cleaning up..." 0
term_handler
