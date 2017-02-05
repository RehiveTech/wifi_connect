# WiFi Connect

RehiveTech WiFi Connect (www.rehivetech.com) is a tool intended for linux embedded devices in order to configure WiFi network client without having a straight access to the system console. The application creates its own configuration WiFi access point (AP) running on the same USB WiFi dongle which is afterwards used for network connection. Configuration AP is possible connect via notebook / smartphone / tablet and access the control panel by typing appropriate IP address to the web browser address bar (by default http://192.168.50.1:8080). Once the WiFi client configuration is done the dongle is switched back to the client mode connecting the preconfigured network with SSID and password.


### Prerequisities

 Python - tested on 2.7 version only.

 - hostapd
 - iw
 - wpasupplicant
 - dnsmasq

 Wlan adapter driver must support AP mode

```
$ iw list
Wiphy phy1
...
	Supported interface modes:
		 * IBSS
		 * managed
		 * AP
		 * AP/VLAN
		 * WDS
		 * monitor
		 * mesh point
```

### Configuration

There is no special configuration file. Look at the beginning of the `wifi_connect.py` script for several options. Appropriate description is attached. Also check if the all the 3rd party application paths are correct.

### Running

For test just start `./wifi_connect.py` from the command line.

Integration with the systemd can be done by following service definition in `/lib/systemd/system/wifi_connect.service`. Only change the `WorkingDirectory` and `ExecStart` directives. Then enable and start the systemd service:

```
systemctl enable wifi_connect
systemctl daemon-reload
systemctl start wifi_connect
```

```
[Unit]
Description=Rehivetech WiFi Connect
After=syslog.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/root/wifi
ExecStart=/root/wifi/wifi_connect.py
StandardOutput=syslog
StandardError=syslog
RestartSec=30
Restart=always

[Install]
WantedBy=multi-user.target
```

### Author

Josef Hajek -  <hajek@rehivetech.com>
