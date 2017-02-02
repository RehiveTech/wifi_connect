#!/usr/bin/env python2

# #############################################################################
# wifi_connect.py: RehiveTech WiFi Connect                                    #
# Authors: Josef Hajek <hajek@rehivetech.com>                                 #
#                                                                             #
# Copyright RehiveTech s.r.o., 2017                                           #
# #############################################################################

import os
import os.path
import sys
import signal
import subprocess
import SimpleHTTPServer
import SocketServer
import socket
import json
import cgi
import tempfile
import binascii
import fcntl
import struct
import time
from multiprocessing import Process, Value

# SSID identification of the Access point network.
AP_SSID = 'RT_WiFi_Connect'

# Channel the access point is listening on.
AP_CHANNEL = 3

# IP address of the AP wlan interface where the web is available.
# Must end with '1', supposed netmask is /24.
AP_IP = '192.168.50.1'

# Port the webserver is running on.
HTTP_PORT = 8080

# Number of seconds in configuration mode waiting
# for user interaction afer reboot.
INITIAL_WEB_WAIT = 60

# Time extension of configuration activated mode by click on 'Refresh' button
REFRESH_WEB_WAIT = 120

# Config file path for the wpa_supplicant client configuration.
WPA_CONF = os.path.dirname(os.path.realpath(__file__)) + '/wpa_supplicant.conf'

# Paths to binaries used by the application
HOSTAPD = '/usr/sbin/hostapd'
HOSTAPD_CLI = '/usr/sbin/hostapd_cli'
DNSMASQ = '/usr/sbin/dnsmasq'
WPACLI = '/sbin/wpa_cli'
WPA_SUPPLICANT = '/sbin/wpa_supplicant'
DHCLIENT = '/sbin/dhclient'
IW = '/sbin/iw'
IP = '/bin/ip'

DEVNULL = open(os.devnull, 'w')


def exit_app(signum, frame):
    """Graceful exit the appliacation, clear all the resources.
    """
    global httpd
    global ap
    global c

    print 'Exiting WiFi connect application'
    signal.signal(signal.SIGINT, original_sigint)

    if c is not None:
        c.destroy()
    if ap is not None:
        ap.destroy()
    if httpd is not None:
        httpd.server_close()  # shutdown server
    sys.exit(0)


def get_wlan_name():
    """Return string of the first wlan interface name.
    """
    for i in os.listdir('/sys/class/net/'):
        if i.startswith('wlan'):
            return i
    return 'N/A'


def get_ip_address(ifname):
    """Get IP address of an interface with the given name.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15])
        )[20:24])
    except Exception:
        return None


class Client():
    """WiFi client class. Implements base methods for USB dongle acting as a
    client for a WiFi network.
    """

    CTRL_INTERFACE = None
    DHCLIENT_PF = None
    DHCLIENT_LF = None
    dhclient_proc = None
    inteface = None

    def __init__(self, interface, temp_dir='/tmp'):
        self.iface = interface
        subprocess.call([IP, 'link', 'set', 'dev', interface, 'up'])

        self.CTRL_INTERFACE = temp_dir + '/wpa_ctrl_interface'
        self.DHCLIENT_PF = temp_dir + '/dhclient.' + self.iface + '.pid'
        self.DHCLIENT_LF = temp_dir + '/dhclient.' + self.iface + '.lf'

        # generated config file of does not exist
        if not os.path.isfile(WPA_CONF):
            self.gen_wpaconf()

    def config(self, ssid, key=''):
        self.ssid = ssid
        self.gen_wpaconf(ssid=ssid, wep_key=key, wpa_psk=key)

    def scan(self):
        """Perform site survey for the surronding networks.
        """
        scanned = {}
        try:
            res = subprocess.call([WPACLI, '-g',
                                   self.CTRL_INTERFACE + '/' +
                                   self.iface,
                                   'scan'])
        except Exception, e:
            print 'Cannot scan: ' + str(e)
            return scanned

        try:
            res = subprocess.check_output([WPACLI, '-g',
                                           self.CTRL_INTERFACE + '/' +
                                           self.iface,
                                           'scan_result'])
        except Exception, e:
            print 'Cannot scan: ' + str(e)
            return scanned

        for line in res.splitlines():
            if line[2] != ':':  # consider MAC addresses AA:BB:CC:...
                continue
            ln = line.split()
            scanned[ln[4]] = {'channel': ln[1], 'signal': ln[2], 'enc': ln[3]}

        return scanned

    def scan_iw(self):
        """The same as a self.scan() but using using 'iw' tool.
        """
        scanned = {}
        try:
            res = subprocess.check_output([IW, self.iface, 'scan'])
        except Exception, e:
            print 'Cannot scan: ' + str(e)
            return scanned

        index = None
        for line in res.splitlines():
            ln = line.strip()
            if ln.startswith('BSS'):
                index = ln
                scanned[index] = {'channel': '', 'signal': '', 'enc': '[ESS]'}
            if ln.startswith('SSID'):
                scanned[index]['SSID'] = ln.split(':')[1].strip()
            if ln.startswith('signal'):
                scanned[index]['signal'] = ln.split(':')[1].strip()
            if ln.startswith('freq'):
                scanned[index]['channel'] = ln.split(':')[1].strip()
            if ln.startswith('WPA'):
                scanned[index]['enc'] = 'WPA'

        for k, v in scanned.items():  # change scanned to proper format
            scanned[v['SSID']] = v
            del scanned[k]

        return scanned

    def get_iface(self):
        return self.iface

    def status(self):
        """Get status of the current connection.
        """
        status = {}
        try:
            res = subprocess.check_output([WPACLI, '-g',
                                           self.CTRL_INTERFACE + '/' +
                                           self.iface, 'status'],
                                          stdout=DEVNULL,
                                          stderr=DEVNULL)
        except Exception:
            # print 'Cannot get status: ' + str(e)
            return status

        for line in res.splitlines():
            ln = line.split('=')
            if len(ln) < 2:
                continue
            status[ln[0]] = ln[1]

        if 'ssid' not in status:
            status['ssid'] = self.get_ssid()
        return status

    def connect(self):
        """Connect WiFi network defined in the configuration file.
        """
        self.destroy()
        ret = subprocess.call([WPA_SUPPLICANT, '-i', self.iface,
                               '-c', WPA_CONF, '-D', 'wext', '-B'])
        if ret != 0:
            return False

        self.dhclient_proc = subprocess.Popen([DHCLIENT,
                                               '-pf', self.DHCLIENT_PF,
                                               '-lf', self.DHCLIENT_LF,
                                               '-d', self.iface])

    def destroy(self):
        if self.dhclient_proc is not None:
            self.dhclient_proc.terminate()
        subprocess.call([WPACLI, '-g', self.CTRL_INTERFACE + '/' + self.iface,
                         'terminate'])
        subprocess.call([IP, 'addr', 'flush', 'dev', self.iface])

    def get_ssid(self):
        """Get SSID string from the configuration file.
        """
        f = open(WPA_CONF, 'r')
        s = f.read()
        f.close()
        for i in s.split('\n'):
            if i.strip().startswith('ssid'):
                return i.strip().split('=')[1][1:-1]
        return 'N/A'

    def gen_wpaconf(self, ssid="NOT_CONNECTED", wep_key="NOT_CONNECTED",
                    wpa_psk="NOT_CONNECTED"):
        """Generate config file for wpa_supplicant.
        Config file is stored in given location.
        Manual page:
        https://www.freebsd.org/cgi/man.cgi?query=wpa_supplicant.conf&sektion=5
        http://manpages.ubuntu.com/manpages/hardy/man5/wpa_supplicant.conf.5.html
        """
        if len(wpa_psk) < 8:
            wpa_psk = 'dummy123'  # dummy password if incorrect length

        conf = """
            ctrl_interface=%s
            # WPA/WPA2
            network={
                ssid="%s"
                key_mgmt=WPA-PSK
                psk="%s"
            }

            # WEP
            network={
                ssid="%s"
                key_mgmt=NONE
                wep_key0="%s"
                wep_tx_keyidx=0
            }

            #OPEN
            network={
                ssid="%s"
                key_mgmt=NONE
            }
            """ % (self.CTRL_INTERFACE, ssid, wpa_psk, ssid, wep_key, ssid)

        f = open(WPA_CONF, 'w')
        f.write(conf)
        f.close()


class AccessPoint():
    """WiFi AccessPoint class. Implements base methods for USB dongle acting as a
    WiFi Access Point.
    """

    CTRL_INTERFACE = None
    running = False

    def __init__(self, ssid, wlan_iface, channel, temp_dir='/tmp'):
        self.ssid = ssid
        self.channel = channel
        self.wlan_iface = wlan_iface
        self.ap_iface = wlan_iface
        self.dnsmasq_proc = None
        self.CTRL_INTERFACE = temp_dir + '/hostapd_ctrl_interface'

    def create_interface(self):
        """Creates access point virtual interface.
        """
        rnd_hex = binascii.b2a_hex(os.urandom(1))

        ifcs = os.listdir('/sys/class/net/')
        ret = subprocess.call([IW, 'dev', self.wlan_iface, 'interface', 'add',
                               self.ap_iface + '_ap', 'type', '__ap'])
        time.sleep(2)
        ifcs1 = os.listdir('/sys/class/net/')
        ifcs = list(set(ifcs1) - set(ifcs))
        if ret != 0 or len(ifcs) != 1:
            return False

        self.ap_iface = ifcs[0]
        print self.ap_iface

        ret = subprocess.call([IP, 'link', 'set', self.ap_iface, 'address',
                               "02:be:ee:00:00:" + rnd_hex])
        if ret != 0:
            return False
        return True

    def run(self):
        """Launch access point. Set-up IP of the interface, dhcp server and hostapd.
        """
        dh_beg = AP_IP[:-1] + '2'
        dh_end = AP_IP[:-1] + '9'
        subprocess.call([IP, 'addr', 'flush', 'dev', self.ap_iface])
        subprocess.call([IP, 'addr', 'add', AP_IP + '/24', 'dev',
                         self.ap_iface])

        self.dnsmasq_proc = subprocess.Popen([DNSMASQ, '-b',
                                              '-i', self.ap_iface, '-k',
                                              '--port=0',
                                              '--dhcp-leasefile=/tmp/dnsmq.ls',
                                              '--dhcp-range=%s,%s,5m' %
                                              (dh_beg, dh_end),
                                              ])

        tf = tempfile.NamedTemporaryFile(prefix='hostapd-', suffix='.conf',
                                         delete=False)
        tf.write('interface=%s\n' % self.ap_iface)
        tf.write('ssid=%s\n' % self.ssid)
        tf.write('channel=%s\n' % self.channel)
        tf.write('hw_mode=g\n')
        tf.write('ctrl_interface=%s\n' % self.CTRL_INTERFACE)
        tf.write('ctrl_interface_group=0\n')
        tf.flush()

        self.proc = subprocess.Popen([HOSTAPD, tf.name])
        self.running = True

        return True

    def destroy(self):
        if self.running:
            try:
                self.proc.terminate()
                self.dnsmasq_proc.terminate()
            except Exception, e:
                print 'Cannot stop process: ' + str(e)

            if self.wlan_iface != self.ap_iface:  # destroy virtual interface
                subprocess.call([IW, 'dev', self.ap_iface, 'del'])
            self.running = False

    def get_stations(self):
        """Get list of connected stations.
        """
        sta = []
        try:
            res = subprocess.check_output([HOSTAPD_CLI, '-p',
                                           self.CTRL_INTERFACE,
                                           'all_sta'])
        except Exception, e:
            print 'Cannot get stations: ' + str(e)
            return sta

        for i in res.splitlines():
            if i[2] == ':':
                sta.append(i.strip())
        return sta


class TCPServer(SocketServer.TCPServer):
    """Avoid 'Address already in use' error. However already established
    connections still hang in TIME_WAIT state.
    """
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)


class ServerHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    """Processing HTTP requests
    """

    def do_GET(self):
        if self.path.startswith('/scan'):
            # scan and get list of WiFi networks
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            resp = c.scan()
            self.wfile.write(json.dumps(resp))
            return

        if self.path.startswith('/refresh'):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            web_wait_cnt.value = REFRESH_WEB_WAIT
            return

        if self.path.startswith('/get_status'):
            # get status periodical ajax request
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            cl = c.status()
            cl_iface = get_ip_address(c.get_iface())
            resp = {}
            resp['Wlan interface'] = get_wlan_name()
            resp['SSID'] = c.get_ssid()
            if 'ssid' in cl:
                resp['SSID'] = cl['ssid']
            if 'key_mgmt' in cl:
                resp['Encryption'] = cl['key_mgmt']
            if 'freq' in cl:
                resp['Frequency'] = cl['freq']
            if 'address' in cl:
                resp['Address'] = cl['address']
            if 'wpa_state' in cl:
                resp['State'] = cl['wpa_state']
            resp['IP address'] = 'N/A'
            if cl_iface is not None:
                resp['IP address'] = cl_iface
            resp['web_wait_cnt'] = str(web_wait_cnt.value)
            if scanned is not None:
                resp['scanned'] = scanned
            self.wfile.write(json.dumps(resp))
            return

        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        ctype, pdict = cgi.parse_header(self.headers['content-type'])
        if ctype == 'multipart/form-data':
            postvars = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers['content-length'])
            postvars = cgi.parse_qs(self.rfile.read(length),
                                    keep_blank_values=1)
        else:
            postvars = {}

        if 'submit' in postvars:
            ssid = postvars['ssid'][0].strip()
            password = postvars['password'][0].strip()
            if ssid == '':
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write('Connecting to <b>%s</b>'
                                 % (c.get_ssid()))
                web_wait_cnt.value = 0  # break waiting loop
                return
            elif ssid == 'NOT_CONNECTED':
                c.config('NOT_CONNECTED', 'NOT_CONNECTED')
                c.connect()
            else:
                c.config(ssid, password)
                self.send_response(200)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write('Connecting to <b>%s</b>'
                                 % (ssid))
                web_wait_cnt.value = 0  # break waiting loop in main
                return

        SimpleHTTPServer.SimpleHTTPRequestHandler.do_GET(self)
        return

    def list_directory(self, path):
        self.send_error(403, "ACCESS DENIED")  # denial listening directory
        return None


def start_http_server(httpd):
    httpd.serve_forever()


if __name__ == "__main__":
    c = None
    ap = None
    https = None
    scanned = None
    # make temporary directory for related application files
    temp_dir = tempfile.mkdtemp(prefix='wifi_connect-')
    web_wait_cnt = Value('i', INITIAL_WEB_WAIT)
    wlan_iface = get_wlan_name()

    # program termination handler
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exit_app)

    c = Client(wlan_iface, temp_dir=temp_dir)
    scanned = c.scan_iw()
    ap = AccessPoint(AP_SSID, wlan_iface, AP_CHANNEL, temp_dir=temp_dir)
    # ap.create_interface()  # create virtual interface for AP

    Handler = ServerHandler
    Handler.extensions_map.update({
        '.webapp': 'application/x-web-app-manifest+json',
    })
    try:
        httpd = TCPServer(('', HTTP_PORT), Handler)
    except Exception, e:
        print 'Cannot set_up http server: ' + str(e)
        sys.exit(1)

    p = Process(target=start_http_server, args=(httpd,))
    p.start()

    ap.run()
    print 'Waiting %d seconds for the web user at port %d' \
        % (INITIAL_WEB_WAIT, HTTP_PORT)

    while web_wait_cnt.value > 0:
        web_wait_cnt.value -= 1
        time.sleep(1)

    print 'Starting WiFi client'
    ap.destroy()
    p.terminate()
    c.connect()

    while True:  # idle forever
        time.sleep(1000)
