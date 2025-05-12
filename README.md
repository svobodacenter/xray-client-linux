# svoboda.center xray client

Privacy focused Linux [xray](https://github.com/XTLS/Xray-core) client by https://svoboda.center

## Features

- DNS resolving via [DNSCrypt](https://dnscrypt.info), protecting user from DNS-based surveillance
- Automatically updated **DNS blacklist** for blocking ads/tracking/malware
- Robust **killswitch** prevents IP leaks
- **VPN > Tor chain** for enhanced privacy without the need to install Tor on client's machine
- Automatically updated **geosite.dat and geoip.dat** for xray routing

## Usage

Requirements: 
- systemd
- root privileges

```bash
# Clone the repository
git clone https://github.com/svobodacenter/xray-client-linux

# Navigate to the client's directory
cd xray-client-linux

# Run (root priveleges are required)
sudo ./run.sh --config path/to/config.json
# OR just put config.json into this directory and run sudo ./run.sh
```

### Examples

- Route traffic through VPN and then Tor
    ```bash
    sudo ./run.sh --torify
    ```
- Detach
    ```bash
    sudo ./run.sh --detach
    ## stop detached process
    sudo ./run.sh --stop
    ```
- No killswitch
    ```bash
    sudo ./run.sh --nokillswitch
    ```
- Show help
    ```bash
    sudo ./run.sh --help
    ```

If, for some reason, the client is killed and killswitch is still enabled, to disable it run: `sudo ./run.sh --killswitch-off`

## Questions

If you have any questions, feel free to reach out:

- **Website:** https://svoboda.center
- **Telegram:** https://t.me/svoboda_center
- **Twitter:** https://x.com/svobodacenter
- **Tox:** FC31427EC043880C59BB875209462462558941F570BEF564F15CB6473F4A6146272986AD2CF8
- **Email:** svobodacenter@mailum.com
- **PGP:** https://svoboda.center/pgp.asc

## License

This project is licensed under the Mozilla Public License Version 2.0. See the [LICENSE](LICENSE) file for more details.

## Credits

- [XTLS](https://github.com/XTLS)
- [DNSCrypt](https://github.com/DNSCrypt)
- [xjasonlyu](https://github.com/xjasonlyu)
- [wintun](https://www.wintun.net)