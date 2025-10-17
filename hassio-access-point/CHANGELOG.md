# Changelog

## [0.6.13] - 2025-10-17
### Fixed
- **Critical**: Added immediate SSID and password validation to catch configuration issues
- Enhanced hostapd startup logging to show exactly when and how WiFi access point starts
- Added comprehensive hostapd.conf content logging for troubleshooting
- Added checkpoint markers to track script execution flow to wait phase

### Added
- Early configuration validation with clear error messages for missing SSID/password
- Detailed hostapd startup process logging
- Script execution phase markers to identify where failures occur
- Enhanced configuration display showing SSID and password lengths

## [0.6.12] - 2025-10-17
### Fixed
- **Critical**: Added comprehensive debugging to identify exact failure point
- Fixed dnsmasq configuration test output capture to prevent script confusion
- Added exit trap to show exactly where script terminates unexpectedly
- Enhanced logging around interface IP checking and configuration

### Added
- Debug logging to track script execution flow
- Better error capture for dnsmasq configuration testing
- Exit trap to identify unexpected script termination points

## [0.6.11] - 2025-10-17
### Fixed
- **Critical**: Fixed script crash when interface IP configuration fails
- Fixed IP forwarding error on read-only filesystem (Docker containers)
- Replaced fatal exit with warning and retry logic when interface has no IP
- Added retry mechanism for interface IP configuration
- Script now continues even if IP configuration partially fails

### Changed
- IP forwarding failure now shows warning instead of causing script failure
- Interface IP check is now non-fatal with retry logic
- Better error handling for Docker container filesystem limitations

## [0.6.10] - 2025-10-17
### Fixed
- **Critical**: Fixed dnsmasq startup failure that prevented DHCP from working
- Added comprehensive dnsmasq diagnostics to identify port conflicts and startup issues
- Added `bind-interfaces` directive to prevent dnsmasq from conflicting with system services
- Enhanced error handling with fallback to DHCP-only mode if DNS conflicts occur
- Improved DNS server validation to prevent invalid configurations

### Added
- Pre-startup port diagnostics to identify DHCP/DNS port conflicts
- Enhanced dnsmasq error logging and troubleshooting information
- Fallback mechanism to start dnsmasq in DHCP-only mode if full mode fails

## [0.6.9] - 2025-10-17
### Fixed
- **Critical**: Enabled DHCP by default so WiFi clients automatically receive IP addresses
- **Critical**: Simplified iptables rules to prevent interference with normal WiFi access
- Fixed issue where stopping addon would break TP-Link WiFi access to Home Assistant
- Enabled IP forwarding for proper routing between WiFi clients and Home Assistant
- Replaced complex NAT rules with simple INPUT rule to allow WiFi client access

### Changed
- Default DHCP setting changed from `false` to `true` for better user experience
- Simplified networking approach to be less intrusive to system firewall rules

## [0.6.7] - 2025-10-17
### Fixed
- **Critical**: Added iptables rules to allow WiFi clients to access Home Assistant on port 8123
- Fixed connectivity issue preventing access to Home Assistant web interface from WiFi clients
- Added support for HTTP (port 80) and HTTPS (port 443) access to Home Assistant
- Added DNS access rules for proper name resolution from WiFi clients

### Added
- Comprehensive iptables rules for Home Assistant access from WiFi access point
- Proper cleanup of iptables rules when addon stops

## [0.6.6] - 2025-10-17
### Fixed
- Fixed bash syntax error where `local` variables were declared outside function scope
- Improved rfkill error handling to gracefully handle permission denied errors
- Enhanced NetworkManager version mismatch detection to capture stderr warnings
- Added comprehensive pre-hostapd diagnostics for better troubleshooting
- Script now runs without syntax errors while maintaining WiFi AP functionality

### Added
- Enhanced diagnostics before hostapd startup showing interface status, IP config, and wireless capabilities
- Better error handling for rfkill access when insufficient Docker privileges exist
- Improved NetworkManager version compatibility checking

## [0.6.5] - 2025-10-17

### Added
- **Comprehensive Troubleshooting**: Added extensive pre-flight checks and diagnostics for "no WiFi appearing" issues
- **Configuration Validation**: Added detailed validation of SSID, password, and all required settings
- **Wireless Interface Detection**: Enhanced detection and validation of wireless interfaces with AP mode support
- **RF Kill Management**: Added automatic detection and unblocking of RF-killed wireless devices
- **Progressive hostapd Monitoring**: Added step-by-step monitoring of hostapd startup with detailed error messages
- **Common Issue Detection**: Added detection and guidance for common configuration problems

### Fixed
- **Missing Configuration Detection**: Better error messages when SSID or password are not configured
- **Interface Compatibility**: Added checks to verify wireless interface supports AP mode before attempting setup
- **Process Monitoring**: Improved detection of hostapd startup failures with specific troubleshooting guidance
- **Configuration Display**: Enhanced logging of all configuration parameters for easier debugging

### Changed
- **Error Messages**: Much more detailed and actionable error messages for common failure scenarios
- **Startup Sequence**: Added systematic pre-flight checks before attempting network configuration
- **Logging Structure**: Organized diagnostic output into clear sections for easier troubleshooting

## [0.6.3] - 2025-10-17

### Fixed
- **Critical Networking Issue**: Fixed IP address configuration timing that prevented devices from accessing the web interface
- **DHCP Server Binding**: Improved dnsmasq startup to ensure it binds to the interface after IP configuration
- **Interface IP Validation**: Added comprehensive IP address validation and verification
- **Service Dependencies**: Fixed startup sequence to configure IP after hostapd initialization

### Added
- **IP Configuration Function**: Centralized interface IP configuration with multiple fallback methods
- **Network Status Verification**: Added checks to verify services are actually listening on correct ports
- **Enhanced IP Diagnostics**: Better logging of interface IP status throughout startup
- **Service Status Monitoring**: Added PID tracking and validation for all network services

### Changed
- **Startup Sequence**: Improved timing of IP configuration, hostapd, and dnsmasq startup
- **Error Handling**: Better error messages when network configuration fails
- **Service Validation**: Added verification that dnsmasq successfully binds to DHCP port

## [0.6.2] - 2025-10-17

### Added
- **Enhanced Diagnostics**: Added comprehensive system diagnostics during startup
- **NetworkManager Version Handling**: Automatic detection and handling of NetworkManager version mismatches
- **Interface Validation**: Better validation of wireless interfaces before attempting to configure
- **Process Status Monitoring**: Added PID tracking and status checking for hostapd and dnsmasq
- **Access Point Broadcasting Verification**: Added checks to verify AP is actually broadcasting after startup
- **Configuration Display**: Enhanced debug output showing final configurations for troubleshooting

### Fixed
- **NetworkManager Compatibility**: Added automatic restart attempt when version mismatches are detected
- **Interface Detection**: Better error messages when wireless interfaces are not found or available
- **Service Startup Validation**: Added validation that hostapd and dnsmasq actually start successfully
- **Error Handling**: Improved error messages and exit codes for failed configurations

### Changed
- **Startup Process**: More robust startup sequence with better status reporting
- **Debug Output**: Enhanced debug information to help troubleshoot configuration issues
- **Error Messages**: More descriptive error messages for common configuration problems

## [0.6.1] - 2025-10-17

### Fixed
- **Docker Build Fixes**: Resolved Docker build failures for Alpine Linux compatibility
- Fixed missing Alpine packages: replaced non-existent `awk` and `grep` packages with `gawk`
- Updated Dockerfile format to modern standards (LABEL instead of MAINTAINER, proper ENV syntax)
- Implemented custom netmask-to-CIDR conversion function, removing dependency on `ipcalc`
- Added BUILD_FROM default value to prevent base image warnings
- Updated repository URL to reflect new maintainer (adriy-be)

### Changed
- Modernized Dockerfile with current best practices and warning fixes
- Improved IP address configuration with better fallback mechanisms
- Enhanced error handling for network interface configuration

## [0.6.0] - 2025-01-17

### Changed
- **MAJOR UPDATE**: Updated for compatibility with newest Home Assistant OS hypervisor
- Updated to use Home Assistant naming conventions (changed from "Hass.io" to "Home Assistant")
- Improved error handling and network interface management for newer NetworkManager versions
- Enhanced iptables rules for better internet access routing with proper stateful connections
- Added fallback DNS resolution methods for improved reliability
- Better cleanup on container shutdown with proper iptables rule removal
- Added configuration validation for hostapd before starting
- Improved logging throughout the addon
- Updated Dockerfile with additional required packages for newer HAOS versions
- Added minimum Home Assistant version requirement (2024.1.0)
- Enhanced compatibility with Home Assistant OS 16.x series

### Fixed
- Fixed compatibility issues with newer Home Assistant OS networking stack
- Improved DNS resolution fallback mechanisms
- Better handling of missing network interfaces
- Fixed potential IP address configuration issues on newer systems

## [0.5.2.1] - 2024-04-02

### Fixed
- Hotfix for a typo in the previous version
- Closes [#73](https://github.com/mattlongman/Hassio-Access-Point/issues/73) (Thanks for the issue, @muellermartin!)

## [0.5.2] - 2024-04-02

### Fixed
- Fixed repo to use LF again (my bad!)

## [0.5.1] - 2024-03-11

### Added
-  [PR-69](https://github.com/mattlongman/Hassio-Access-Point/pull/) (nice!!!) from [Hactys](https://github.com/Hactys): Added French translation for configs

## [0.5.0] - 2024-02-27

All changes for this version are in [PR-63](https://github.com/mattlongman/Hassio-Access-Point/pull/63) from [ROBOT0-VT](https://github.com/ROBOT0-VT) (New maintainer! =D).

### Added
- Validation for addon configuration menu
- English translations strings for more clear explanation of config options
    - Translations for other languages are welcome via pull request

### Changed
- Allow some addon config options to be optional
- Main script now uses `bashio` instead of `jq` to read config options
- Main script now uses `bashio` for checking of config options where feasible
- Config file has been converted to YAML format, for consistency with official HASSOS addons
- General cleanup

## [0.4.8] - 2023-10-19

### Fixed
- [PR-56](https://github.com/mattlongman/Hassio-Access-Point/pull/56) from [rrooggiieerr](https://github.com/rrooggiieerr): "Breaking Change: On Arm based boards network names are enumerated based on device tree. This means that the first Ethernet devices will no longer be named eth0 but end0. This pull request proposes a solution by using the default route interface to forward client internet access to."

## [0.4.7] - 2023-06-23

### Fixed
- IPtables dependency change as noted in [issue 42](https://github.com/mattlongman/Hassio-Access-Point/issues/42#issuecomment-1579294919). Thanks to [@tomduijf](https://github.com/tomduijf) for submitting [PR 48](https://github.com/mattlongman/Hassio-Access-Point/pull/48).

## [0.4.6] - 2023-04-23

### Bump to revert 0.4.5

## [0.4.4] - 2022-12-20

### Fixed
- [Issue](https://github.com/mattlongman/Hassio-Access-Point/issues/11) - Implemented changes detailed by @dingausmwald [here](https://github.com/mattlongman/Hassio-Access-Point/issues/11#issuecomment-1360142164)

## [0.4.3] - 2022-06-21

### Fixed
- [Issue](https://github.com/mattlongman/Hassio-Access-Point/issues/31) from @adosikas: `nmcli: command not found`. Added `apk add networkmanager-cli` to Dockerfile. Found this via [this PR](https://github.com/hassio-addons/addon-ssh/pull/415).

## [0.4.2] - 2022-06-14

### Added
- [PR](https://github.com/mattlongman/Hassio-Access-Point/pull/23) from @esotericnonsense (thanks!): Added a new config addon option: dnsmasq_config_override to allow additions/overrides to the dnsmasq config file, for example in order to add static DHCP leases with the dhcp-host= option. This option operates similarly to hostapd_config_override.

## [0.4.1] - 2021-07-21

### Added
- Allow DNS override for clients even if internet routing isn't enabled (allowing resolution of local hosts if the add-ons parent host doesn't have the correct DNS servers set).

## [0.4.0] - 2021-07-10

### Added
- Feature request: [Route traffic from wlan0 to eth0](https://github.com/mattlongman/Hassio-Access-Point/issues/5). Internet access for clients can be enabled with `client_internet_access: '1'`. If DHCP is also enabled, Hassio-Access-Point will try to get the parent host's DNS servers (not just container DNS servers), and server to clients as part of the DHCP config. This can be overridden with e.g. `client_dns_override: ['1.1.1.1', '8.8.8.8']`. If DHCP is not enabled, `client_internet_access: '1'` will still work, but DNS server will need to be set manually as with the rest of the IP config.

## [0.3.1] - 2020-10-21

### Fixed
- Conflict on port 53, as per [this issue](https://github.com/mattlongman/Hassio-Access-Point/issues/3). Added `port=0` to dnsmasq.conf as a fix (to disable DNS), but will explore expanding the DNS options as part of a future update.

## [0.3.0] - 2020-10-15

### Added
- Added a new config addon option: hostapd_config_override to allow additions/overrides to the hostapd config file (run.sh appends to the config file once everything else has been run, so for overriding an existing entry in the file, the later entry will take precedence). hostapd_config_override is a dictionary, so even if you're not overriding anything, `hostapd_config_override: []` must be in the addon options to allow you to save the addon config (if anyone knows how to make dictionaries optional, I'd love to know how..). Fix for [this](https://github.com/mattlongman/Hassio-Access-Point/issues/2).

## [0.2.1] - 2020-10-13

### Fixed
- [Issue](https://github.com/mattlongman/Hassio-Access-Point/issues/1) where AP started and clients could connect, but IP addresses were not being assigned. dnsmasq error: "dnsmasq: warning: interface wlan0 does not currently exist". This seems to be caused by the interface not having an IP address set. Not sure why this isn't being set via interfaces file, but added an ifconfig command to set address/subnet mask/broadcast address.

## [0.2.0] - 2020-09-25

### Added
- Add an debug option to addon config. debug=0 for mininal output. debug=1 to show addon detail. debug=2 for same as 1 + run hostapd in debug mode.

## [0.1.1] - 2020-09-23

### Removed
- Remove unnecessary docker privileges (SYS_ADMIN, SYS_RAWIO, SYS_TIME, SYS_NICE) from config.json
- Remove full access ("full_access": true) from config.json

## [0.1.0] - 2020-09-23

First release.

**Note**: This project was forked from [https://github.com/davidramosweb/hassio-addons](https://github.com/davidramosweb/hassio-addons/tree/f932481fa0503bf0f0b3f8a705b40780d3fe469a). I've submitted a lot of the functionality of this project back as a PR, but some of the extra stuff is outside the scope of a hostapd addon, so I'll leave it here for now as a more expandable hass.io access point addon.

### Added
- Allow hidden SSIDs (as per https://github.com/davidramosweb/hassio-addons/pull/6)
- Allow specification of interface name (defaults to wlan0) (as per https://github.com/davidramosweb/hassio-addons/issues/11)
- Added MAC address filtering
- Add DHCP server (dnsmasq)
- Enable AppArmor
- Add a basic icon/logo. Can do better...

### Changed
- Enabled wmm ("QoS support, also required for full speed on 802.11n/ac/ax") - have tested on mutiple RPIs, but needs further compatibility testing, and potentially moving option to addon config
- Remove interfaces file. Now generate it with specified interface name
- Remove /dev/mem mapping in config.json. Don't need memory access
- Remove RW access to config, ssl, addons, share, backup. Not required

### Fixed
- Remove networkmanager, net-tools, sudo versions (as per https://github.com/davidramosweb/hassio-addons/pull/15, https://github.com/davidramosweb/hassio-addons/pull/8, https://github.com/davidramosweb/hassio-addons/issues/14, https://github.com/davidramosweb/hassio-addons/issues/13)
- Corrected broadcast address (as per https://github.com/davidramosweb/hassio-addons/pull/1)
