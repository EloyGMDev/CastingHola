# EloyGM - 06/10/2025 - 6 October 2025

from __future__ import annotations

import argparse
import http.server
import socketserver
import threading
import os
import sys
import time
from typing import List, Tuple, Dict, Optional

# Dependencias externas
try:
    import pychromecast
except Exception as e:
    pychromecast = None

import socket
import requests
import xml.etree.ElementTree as ET

# Config
HTTP_PORT = 8000
IMAGE_FILENAME = "Hola.png"
SSDP_ADDR = ("239.255.255.250", 1900)
SSDP_MX = 2
SSDP_ST = "urn:schemas-upnp-org:device:MediaRenderer:1"


############################
# HTTP server to serve Hola.png
############################

def serve_static(directory: str, port: int = HTTP_PORT) -> Tuple[threading.Thread, dict]:
    """Start a simple HTTP server serving `directory` on port. Returns thread and control dict."""
    cwd = os.getcwd()
    os.chdir(directory)

    handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", port), handler)

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    print(f"[HTTP] Serving {directory} on port {port} — URL: http://{get_local_ip()}:{port}/{IMAGE_FILENAME}")

    control = {
        "server": httpd,
        "thread": thread,
    }

    os.chdir(cwd)
    return thread, control


############################
# Utility
############################

def get_local_ip() -> str:
    """Try to get the local IP address used to reach the internet (best-effort)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't need to be reachable
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


############################
# Chromecast discovery + casting
############################

def discover_chromecasts(timeout: int = 5) -> List[pychromecast.Chromecast] | List:
    if pychromecast is None:
        print("[Chromecast] pychromecast is not installed; skipping discovery.")
        return []

    print(f"[Chromecast] Discovering devices (timeout={timeout}s)…")
    chromecasts, browser = pychromecast.get_chromecasts(timeout=timeout)
    try:
        browser.stop()
    except Exception:
        pass
    return chromecasts


def cast_image_chromecast(cast: pychromecast.Chromecast, image_url: str):
    try:
        print(f"[Chromecast] Connecting to {cast.device.friendly_name} ({cast.host})")
        c = pychromecast.Chromecast(cast.host)
        c.wait(5)
        mc = c.media_controller
        # common mime type for PNG
        mc.play_media(image_url, 'image/png')
        mc.block_until_active(timeout=5)
        mc.play()
        print(f"[Chromecast] Sent image to {cast.device.friendly_name}")
    except Exception as e:
        print(f"[Chromecast] Error sending to {getattr(cast.device, 'friendly_name', cast)}: {e}")


def stop_chromecast(cast: pychromecast.Chromecast):
    try:
        c = pychromecast.Chromecast(cast.host)
        c.wait(5)
        mc = c.media_controller
        mc.stop()
        print(f"[Chromecast] Stopped media on {cast.device.friendly_name}")
    except Exception as e:
        print(f"[Chromecast] Error stopping {getattr(cast.device, 'friendly_name', cast)}: {e}")


############################
# SSDP / DLNA discovery
############################

def ssdp_search(st: str = SSDP_ST, mx: int = SSDP_MX, timeout: int = 3) -> List[Dict[str, str]]:
    """Discover UPnP devices using SSDP. Returns list of headers maps."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(timeout)
    # Allow multiple sockets to use the same PORT number
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except Exception:
        pass

    msg = '\r\n'.join([
        'M-SEARCH * HTTP/1.1',
        f'HOST: {SSDP_ADDR[0]}:{SSDP_ADDR[1]}',
        'MAN: "ssdp:discover"',
        f'MX: {mx}',
        f'ST: {st}',
        '',
        ''
    ]).encode('utf-8')

    sock.sendto(msg, SSDP_ADDR)
    responses = []
    start = time.time()
    while True:
        try:
            data, addr = sock.recvfrom(65507)
            text = data.decode('utf-8', errors='ignore')
            headers = parse_ssdp_response(text)
            headers['_addr'] = addr[0]
            responses.append(headers)
        except socket.timeout:
            break
        except Exception:
            break
        if time.time() - start > timeout + 1:
            break
    sock.close()
    return responses


def parse_ssdp_response(text: str) -> Dict[str, str]:
    lines = text.split('\r\n')
    headers = {}
    for line in lines[1:]:
        if ':' in line:
            k, v = line.split(':', 1)
            headers[k.strip().upper()] = v.strip()
    return headers


def fetch_device_description(location: str) -> Optional[ET.Element]:
    try:
        r = requests.get(location, timeout=4)
        r.raise_for_status()
        xml = ET.fromstring(r.content)
        return xml
    except Exception:
        return None


def parse_friendly_name_from_desc(xml: ET.Element) -> Optional[str]:
    if xml is None:
        return None
    ns = {'d': 'urn:schemas-upnp-org:device-1-0'}
    # try find friendlyName
    fn = xml.find('.//{urn:schemas-upnp-org:device-1-0}friendlyName')
    if fn is not None and fn.text:
        return fn.text
    # fallback
    elm = xml.find('.//friendlyName')
    if elm is not None and elm.text:
        return elm.text
    return None


def discover_dlna_renderers(timeout: int = 3) -> List[Dict[str, str]]:
    print(f"[DLNA] Searching for DLNA/UPnP renderers (timeout={timeout}s)…")
    responses = ssdp_search(timeout=timeout)
    devices = []
    seen = set()
    for r in responses:
        location = r.get('LOCATION')
        if not location:
            continue
        if location in seen:
            continue
        seen.add(location)
        xml = fetch_device_description(location)
        fn = parse_friendly_name_from_desc(xml)
        devices.append({
            'friendly_name': fn or r.get('_addr') or 'Unknown',
            'location': location,
            'address': r.get('_addr'),
            'server': r.get('SERVER'),
            'st': r.get('ST'),
            'usn': r.get('USN')
        })
    if not devices:
        print("[DLNA] No DLNA/UPnP renderers found.")
    else:
        print(f"[DLNA] Found {len(devices)} renderers.")
    return devices


############################
# DLNA: SetAVTransportURI + Play
############################

def find_avtransport_control_url(desc_xml: ET.Element, base_url: str) -> Optional[str]:
    """Parse device description XML and find AVTransport control URL if present."""
    if desc_xml is None:
        return None
    # look for service with serviceType urn:schemas-upnp-org:service:AVTransport:1
    for service in desc_xml.findall('.//{urn:schemas-upnp-org:device-1-0}service'):
        st = service.find('{urn:schemas-upnp-org:device-1-0}serviceType')
        ctl = service.find('{urn:schemas-upnp-org:device-1-0}controlURL')
        if st is not None and 'AVTransport' in (st.text or '') and ctl is not None:
            control = ctl.text
            if control.startswith('http'):
                return control
            # join base
            return requests.compat.urljoin(base_url, control)
    # fallback: try to search without namespace
    for service in desc_xml.findall('.//service'):
        st = service.find('serviceType')
        ctl = service.find('controlURL')
        if st is not None and ctl is not None and 'AVTransport' in (st.text or ''):
            control = ctl.text
            if control.startswith('http'):
                return control
            return requests.compat.urljoin(base_url, control)
    return None


def send_dlna_set_av_transport(control_url: str, media_url: str, instance_id: int = 0) -> bool:
    """Send SetAVTransportURI and Play SOAP actions to the control URL. Returns True on success (best-effort)."""
    headers = {
        'Content-Type': 'text/xml; charset="utf-8"',
        'SOAPACTION': '"urn:schemas-upnp-org:service:AVTransport:1#SetAVTransportURI"'
    }
    body_set = f"""
    <?xml version="1.0" encoding="utf-8"?>
    <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
      <s:Body>
        <u:SetAVTransportURI xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
          <InstanceID>{instance_id}</InstanceID>
          <CurrentURI>{media_url}</CurrentURI>
          <CurrentURIMetaData></CurrentURIMetaData>
        </u:SetAVTransportURI>
      </s:Body>
    </s:Envelope>
    """
    try:
        r = requests.post(control_url, data=body_set.encode('utf-8'), headers=headers, timeout=5)
        # ignore exact status, some devices return 200 but still work
    except Exception as e:
        print(f"[DLNA] Error SetAVTransportURI: {e}")
        return False

    # Now send Play
    headers['SOAPACTION'] = '"urn:schemas-upnp-org:service:AVTransport:1#Play"'
    body_play = f"""
    <?xml version="1.0" encoding="utf-8"?>
    <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
      <s:Body>
        <u:Play xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
          <InstanceID>{instance_id}</InstanceID>
          <Speed>1</Speed>
        </u:Play>
      </s:Body>
    </s:Envelope>
    """
    try:
        r2 = requests.post(control_url, data=body_play.encode('utf-8'), headers=headers, timeout=5)
        return r2.status_code in (200, 204) or r2.ok
    except Exception as e:
        print(f"[DLNA] Error Play: {e}")
        return False


def stop_dlna(control_url: str, instance_id: int = 0) -> bool:
    headers = {
        'Content-Type': 'text/xml; charset="utf-8"',
        'SOAPACTION': '"urn:schemas-upnp-org:service:AVTransport:1#Stop"'
    }
    body_stop = f"""
    <?xml version="1.0" encoding="utf-8"?>
    <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
      <s:Body>
        <u:Stop xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">
          <InstanceID>{instance_id}</InstanceID>
        </u:Stop>
      </s:Body>
    </s:Envelope>
    """
    try:
        r = requests.post(control_url, data=body_stop.encode('utf-8'), headers=headers, timeout=5)
        return r.status_code in (200, 204) or r.ok
    except Exception as e:
        print(f"[DLNA] Error Stop: {e}")
        return False


def cast_image_dlna(device: Dict[str, str], image_url: str) -> bool:
    # device.location -> URL to device description XML
    desc = fetch_device_description(device['location'])
    if desc is None:
        print(f"[DLNA] Could not get description for {device.get('friendly_name')}")
        return False
    control_url = find_avtransport_control_url(desc, device['location'])
    if not control_url:
        print(f"[DLNA] AVTransport control not found for {device.get('friendly_name')}")
        return False
    print(f"[DLNA] Sending image to {device.get('friendly_name')} via control {control_url}")
    success = send_dlna_set_av_transport(control_url, image_url)
    print(f"[DLNA] Result: {success}")
    return success


def stop_dlna_device(device: Dict[str, str]) -> bool:
    desc = fetch_device_description(device['location'])
    if desc is None:
        return False
    control_url = find_avtransport_control_url(desc, device['location'])
    if not control_url:
        return False
    return stop_dlna(control_url)


############################
# CLI and flow
############################

def main():
    parser = argparse.ArgumentParser(description='CastHola — discover and send Hola.png to displays (Chromecast + DLNA)')
    parser.add_argument('--discover', action='store_true', help='Discover devices')
    parser.add_argument('--cast', action='store_true', help='Cast Hola.png to discovered devices')
    parser.add_argument('--serve', action='store_true', help='Serve Hola.png on HTTP server (required by many targets)')
    parser.add_argument('--stop', action='store_true', help='Stop playback on discovered devices')
    parser.add_argument('--port', type=int, default=HTTP_PORT, help='HTTP port for serving Hola.png')
    parser.add_argument('--timeout', type=int, default=4, help='Discovery timeout seconds')
    args = parser.parse_args()

    # legal reminder
    print('\nNOTICE: Run this ONLY in controlled environments with express permission. Unauthorized use may be illegal.\n')

    if not os.path.exists(IMAGE_FILENAME):
        print(f"Error: {IMAGE_FILENAME} does not exist in the current directory ({os.getcwd()}). Create or place the image and try again.")
        if not args.discover and not args.stop:
            sys.exit(1)

    http_control = None
    if args.serve:
        # start server
        thread, control = serve_static(os.getcwd(), args.port)
        http_control = control
        # server is started in background

    devices = []

    # Chromecast discovery
    chromecasts = []
    if pychromecast is not None:
        try:
            chromecasts = discover_chromecasts(timeout=args.timeout)
            for cc in chromecasts:
                devices.append({
                    'protocol': 'chromecast',
                    'name': cc.device.friendly_name,
                    'host': cc.host,
                    'object': cc
                })
        except Exception as e:
            print(f"[Chromecast] Error discovery: {e}")

    # DLNA discovery
    dlna_devices = discover_dlna_renderers(timeout=args.timeout)
    for d in dlna_devices:
        devices.append({
            'protocol': 'dlna',
            'name': d.get('friendly_name'),
            'location': d.get('location'),
            'object': d
        })

    if args.discover or not any([args.cast, args.stop]):
        print('\n== Detected Devices ==')
        if not devices:
            print('  (none)')
        else:
            for i, dev in enumerate(devices, 1):
                print(f"  {i}. {dev['name']}  [{dev['protocol']}]")

    # Build image URL if serving
    if args.serve:
        image_url = f"http://{get_local_ip()}:{args.port}/{IMAGE_FILENAME}"
    else:
        # if not serving, we cannot provide a URL; chromecast and DLNA need a URL
        image_url = None

    # Cast
    if args.cast:
        if image_url is None:
            print("[Error] To cast remotely many protocols require the image to be available via HTTP. Use --serve.")
        else:
            print(f"\n[Action] Casting {IMAGE_FILENAME} -> {image_url}\n")
            for dev in devices:
                if dev['protocol'] == 'chromecast':
                    try:
                        cast_image_chromecast(dev['object'], image_url)
                    except Exception as e:
                        print(f"[Chromecast] Error: {e}")
                elif dev['protocol'] == 'dlna':
                    try:
                        cast_image_dlna(dev['object'], image_url)
                    except Exception as e:
                        print(f"[DLNA] Error: {e}")

    # Stop
    if args.stop:
        print('\n[Action] Stopping playback on discovered devices...')
        for dev in devices:
            if dev['protocol'] == 'chromecast':
                try:
                    stop_chromecast(dev['object'])
                except Exception as e:
                    print(f"[Chromecast] Error stopping: {e}")
            elif dev['protocol'] == 'dlna':
                try:
                    ok = stop_dlna_device(dev['object'])
                    print(f"[DLNA] Stop {dev['name']}: {ok}")
                except Exception as e:
                    print(f"[DLNA] Error stopping: {e}")

    # shutdown server if we started it
    if http_control is not None:
        try:
            print('\n[HTTP] Shutting down server...')
            http_control['server'].shutdown()
            http_control['server'].server_close()
        except Exception:
            pass

    print('\n[Done]')


if __name__ == '__main__':
    main()