# Home Assistant Access Point
Use your Home Assistant host as a WiFi access point - perfect for off-grid and security focused installations.

**✨ Updated for Home Assistant OS 16.x and newer hypervisor versions ✨**

## Main features
- Create a WiFi access point with built-in (Raspberry Pi) or external WiFi (USB) cards (using hostapd)
- Hidden or visible SSIDs
- DHCP server (Optional. Uses dnsmasq)
- MAC address filtering (allow/deny)
- Internet routing for clients (Optional)
- Enhanced compatibility with newer Home Assistant OS versions
- Improved error handling and network management

## Installation

Please add
`https://github.com/adriy-be/Hassio-Access-Point` to your Home Assistant addon repositories list. If you're not sure how, see [instructions](https://www.home-assistant.io/hassio/installing_third_party_addons/) on the Home Assistant website.

## Config

### Options
- **ssid** (**required**): The name of your access point
- **wpa_passphrase** (**required**): The passkey for your access point
- **channel** (**required**): The WiFi channel to use
- **address** (**required**): The address of your hass.io WiFi card/network
- **netmask** (**required**): Subnet mask of the network
- **broadcast** (**required**): Broadcast address of the network
- **interface** (_optional_): Which wlan card to use. Default: wlan0
- **hide_ssid** (_optional_): Whether SSID is visible or hidden. 0 = visible, 1 = hidden. Defaults to visible
- **dhcp** (_optional_): Enable or disable DHCP server. 0 = disable, 1 = enable. Defaults to disabled
- **dhcp_start_addr** (_optional_): Start address for DHCP range. Required if DHCP enabled
- **dhcp_end_addr** (_optional_): End address for DHCP range. Required if DHCP enabled
- **allow_mac_addresses** (_optional_): List of MAC addresses to allow. Note: if using allow, blocks everything not in list
- **deny_mac_addresses** (_optional_): List of MAC addresses to block. Note: if using deny, allows everything not in list
- **debug** (_optional_): Set logging level. 0 = basic output, 1 = show addon detail, 2 = same as 1 plus run hostapd in debug mode
- **hostapd_config_override** (_optional_): List of hostapd config options to add to hostapd.conf (can be used to override existing options)
- **client_internet_access** (_optional_): Provide internet access for clients. 1 = enable
- **client_dns_override** (_optional_): Specify list of DNS servers for clients. Requires DHCP to be enabled. Note: Add-on will try to use DNS servers of the parent host by default.
- **dnsmasq_config_override** (_optional_): List of dnsmasq config options to add to dnsmasq.conf (can be used to override existing options, as well as reserving IPs, e.g. `dhcp-host=12:34:56:78:90:AB,192.168.99.123`)

Note: use either allow or deny lists for MAC filtering. If using allow, deny will be ignored.

### Example configuration

```
    "ssid": "AP-NAME",
    "wpa_passphrase": "AP-PASSWORD",
    "channel": "6",
    "address": "192.168.10.1",
    "netmask": "255.255.255.0",
    "broadcast": "192.168.10.255",
    "interface": "wlan0",
    "hide_ssid": "1",
    "dhcp": "1",
    "dhcp_start_addr": "192.168.10.10",
    "dhcp_end_addr": "192.168.10.20",
    "allow_mac_addresses": [],
    "deny_mac_addresses": ['ab:cd:ef:fe:dc:ba'],
    "debug": "0",
    "hostapd_config_override": [],
    "client_internet_access": '1',
    "client_dns_override": ['1.1.1.1', '8.8.8.8']
```

### Device & OS compatibility

**New in v0.6.0**: Enhanced compatibility with Home Assistant OS 16.x series and newer hypervisor versions.

This add-on is actively tested on the latest Home Assistant OS using Raspberry Pi 3B+, Pi 4, and Pi 5. It's optimized for:
- Home Assistant OS 16.0+ (recommended)
- Home Assistant OS 10.0+ (legacy support)
- Home Assistant Core 2024.1.0+

The add-on works with 32 & 64 bit HAOS, and has also been tested on Debian-based systems with Home Assistant Supervised.

**Note**: If you encounter issues with newer Home Assistant OS versions, please check the [issues page](https://github.com/mattlongman/hassio-access-point/issues) or create a new issue with your system details.
