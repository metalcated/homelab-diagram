"""Bounded, scope-pinned read transports. No redirects or credential-bearing logs."""
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import ssl
import struct
import time
from urllib.parse import urlsplit
from scan_events import quiet

MAX_RESPONSE = 4*1024*1024


class CollectorError(ValueError):
    def __init__(self, message, code=0):
        super().__init__(message)
        self.code=code if isinstance(code,int) else 0


def endpoint(value):
    parsed=urlsplit(str(value))
    try:
        port=parsed.port or 443
    except ValueError:
        raise CollectorError("Invalid management port.") from None
    if parsed.scheme not in ("https","wss") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise CollectorError("Enter an HTTPS/WSS management URL without embedded credentials, query, or fragment.")
    if parsed.path not in ("","/","/api/current","/api2/json","/rest","/redfish/v1"):
        raise CollectorError("Use the device's base URL, optionally /api/current, /api2/json, /rest or /redfish/v1.")
    if not 1<=port<=65535:
        raise CollectorError("Invalid management port.")
    return parsed.hostname,port


def resolve_scoped(host,port,nets,resolver=socket.getaddrinfo):
    try:
        address=ipaddress.ip_address(host)
        values=[str(address)]
    except ValueError:
        try:
            values=sorted({r[4][0] for r in resolver(host,port,type=socket.SOCK_STREAM)})
        except OSError:
            raise CollectorError("Management hostname could not be resolved.") from None
    allowed=[v for v in values if any(ipaddress.ip_address(v).version==n.version and ipaddress.ip_address(v) in n for n in nets)]
    if not allowed:
        raise CollectorError("Management endpoint resolves outside the site's saved scope.")
    return allowed


def fingerprint(value):
    result=str(value or '').replace(':','').replace(' ','').lower()
    if result and (len(result)!=64 or any(c not in '0123456789abcdef' for c in result)):
        raise CollectorError("Certificate pin must be a SHA-256 fingerprint (64 hexadecimal characters).")
    return result


class PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self,host,port,address,pin="",timeout=8):
        self.address=address
        self.pin=fingerprint(pin)
        context=ssl.create_default_context()
        if self.pin:
            context.check_hostname=False
            context.verify_mode=ssl.CERT_NONE
        super().__init__(host,port,timeout=timeout,context=context)

    def connect(self):
        raw=socket.create_connection((self.address,self.port),self.timeout)
        try:
            self.sock=self._context.wrap_socket(raw,server_hostname=self.host)
            if self.pin and not hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()==self.pin:
                self.sock.close()
                raise CollectorError("Certificate fingerprint mismatch. No credentials were sent.")
        except BaseException:
            raw.close()
            raise


class HTTPS:
    def __init__(self,config,address,headers=None,stop=None,emit=None):
        self.host,self.port=endpoint(config['endpoint'])
        self.address=address
        self.pin=config.get('fingerprint','')
        self.headers=dict(headers or {})
        self.stop=stop or (lambda:False)
        self.calls=0
        self.emit=emit or quiet

    def get(self,path):
        self.calls+=1
        if self.calls>1500 or self.stop():
            raise CollectorError("Collection stopped or exceeded its request limit.")
        parts=urlsplit(path)
        if parts.scheme or parts.netloc or not path.startswith('/') or '..' in parts.path.split('/') or '\\' in path or '\r' in path or '\n' in path:
            raise CollectorError("Device returned an unsafe resource link.")
        conn=PinnedHTTPS(self.host,self.port,self.address,self.pin)
        resource=parts.path
        started=time.monotonic()
        self.emit('request','GET '+resource)
        try:
            # Verify trust/pin before constructing a request with credentials.
            conn.connect()
            conn.request('GET',path,headers={**self.headers,'Accept':'application/json'})
            response=conn.getresponse()
            body=response.read(MAX_RESPONSE+1)
            if response.status==401:
                raise CollectorError(f'Authentication rejected (HTTP 401) at {resource}. Check the required account/token format and credential.',401)
            if response.status==403:
                raise CollectorError(f'Read access denied (HTTP 403) at {resource}. Check the account and token permissions for this request.',403)
            if response.status!=200:
                raise CollectorError(f"Management GET returned HTTP {response.status}; redirects are not followed.",response.status)
            if len(body)>MAX_RESPONSE:
                raise CollectorError("Management response exceeded 4 MiB.")
            try:
                data=json.loads(body)
            except (UnicodeError,ValueError):
                raise CollectorError("Management endpoint did not return valid JSON.") from None
            self.emit('response',f'HTTP {response.status} / GET {resource}',{'bytes':len(body),'duration_ms':round((time.monotonic()-started)*1000),'data':data})
            return data
        except CollectorError as error:
            self.emit('error',f'GET {resource}: {error}',{'code':error.code})
            raise
        except (ssl.SSLError,ssl.CertificateError):
            self.emit('error','TLS verification failed; no response preview is available.')
            raise CollectorError("TLS verification failed. Configure a trusted certificate or an explicitly verified SHA-256 pin.") from None
        except (OSError,http.client.HTTPException):
            self.emit('error','Management endpoint could not be reached or timed out.')
            raise CollectorError("Management endpoint could not be reached or timed out.") from None
        finally:
            conn.close()


class TrueNASWebSocket:
    """Small RFC 6455 text client for bounded JSON-RPC reads on /api/current."""
    READ_METHODS={'system.info','interface.query','pool.query','disk.query','sharing.smb.query','sharing.nfs.query'}

    def __init__(self,config,address,stop=None,emit=None):
        host,port=endpoint(config['endpoint'])
        self.connection=PinnedHTTPS(host,port,address,config.get('fingerprint',''))
        self.socket=None
        self.counter=0
        self.stop=stop or (lambda:False)
        self.emit=emit or quiet
        self.emit('request','Open TrueNAS WebSocket /api/current')
        try:
            self.connection.connect()
            self.socket=self.connection.sock
            key=base64.b64encode(os.urandom(16)).decode()
            authority=f'[{host}]' if ':' in host else host
            if port!=443:authority+=f':{port}'
            request=(f'GET /api/current HTTP/1.1\r\nHost: {authority}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
                     f'Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n')
            self.socket.sendall(request.encode('ascii'))
            response=bytearray()
            while not response.endswith(b'\r\n\r\n'):
                byte=self.socket.recv(1)
                if not byte or len(response)>16384:raise CollectorError('Invalid WebSocket upgrade response.')
                response.extend(byte)
            lines=response.decode('latin1').split('\r\n')
            headers={k.lower():v.strip() for k,v in (line.split(':',1) for line in lines[1:] if ':' in line)}
            expected=base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            if (lines[0].split()[1]!='101' or headers.get('sec-websocket-accept')!=expected or
                headers.get('upgrade','').lower()!='websocket' or 'upgrade' not in headers.get('connection','').lower() or headers.get('sec-websocket-extensions')):
                raise CollectorError('TrueNAS did not accept a supported WebSocket connection.')
            self.emit('response','WebSocket upgrade accepted (HTTP 101).')
        except BaseException:
            self.emit('error','TrueNAS WebSocket connection or TLS verification failed.')
            self.close()
            raise

    def close(self):
        self.connection.close()

    def send_frame(self,opcode,payload):
        if len(payload)>MAX_RESPONSE:raise CollectorError('WebSocket message is too large.')
        size=len(payload)
        head=bytes([0x80|opcode,0x80|(size if size<126 else 126 if size<65536 else 127)])
        if size>=126:head+=struct.pack('!H' if size<65536 else '!Q',size)
        mask=os.urandom(4)
        self.socket.sendall(head+mask+bytes(v^mask[i%4] for i,v in enumerate(payload)))

    def receive(self):
        def read(size):
            data=bytearray()
            while len(data)<size:
                chunk=self.socket.recv(size-len(data))
                if not chunk:raise CollectorError('TrueNAS closed the WebSocket connection.')
                data.extend(chunk)
            return bytes(data)
        message=bytearray()
        started=False
        deadline=time.monotonic()+30
        while time.monotonic()<deadline and not self.stop():
            a,b=read(2)
            final,opcode=bool(a&128),a&15
            if a&112 or b&128:raise CollectorError('Unsupported WebSocket frame flags.')
            size=b&127
            if size==126:size=struct.unpack('!H',read(2))[0]
            elif size==127:size=struct.unpack('!Q',read(8))[0]
            if size>MAX_RESPONSE or len(message)+size>MAX_RESPONSE:raise CollectorError('WebSocket response exceeded 4 MiB.')
            if opcode>=8 and (not final or size>125):raise CollectorError('Invalid WebSocket control frame.')
            payload=read(size)
            if opcode==8:raise CollectorError('TrueNAS closed the WebSocket session.')
            if opcode==9:self.send_frame(10,payload);continue
            if opcode==10:continue
            if opcode==1 and not started:started=True
            elif opcode!=0 or not started:raise CollectorError('Expected a WebSocket text response.')
            message.extend(payload)
            if final:
                try:return json.loads(message)
                except (ValueError,UnicodeError):raise CollectorError('Invalid TrueNAS JSON response.') from None
        raise CollectorError('TrueNAS response timed out or collection was stopped.')

    def call(self,method,params=None):
        if method not in self.READ_METHODS|{'auth.login_ex','auth.login_with_api_key'}:
            raise CollectorError('Only read-only inventory methods and API-key login are allowed.')
        self.counter+=1
        request={'jsonrpc':'2.0','id':self.counter,'method':method,'params':params or []}
        self.emit('request','JSON-RPC '+method)
        try:
            self.send_frame(1,json.dumps(request).encode())
            for _ in range(100):
                response=self.receive()
                if not isinstance(response,dict) or response.get('id')!=self.counter:continue
                if response.get('error'):
                    code=response['error'].get('code',0)
                    raise CollectorError('TrueNAS method or read permission is unavailable.',code)
                result=response.get('result')
                if method.startswith('auth.'):
                    self.emit('response','Authentication response received; contents hidden.')
                else:self.emit('response','JSON-RPC result / '+method,{'result':result})
                return result
            raise CollectorError('Too many unsolicited TrueNAS notifications.')
        except CollectorError as error:
            self.emit('error','JSON-RPC '+method+': '+str(error),{'code':error.code})
            raise
        except (OSError,ValueError):
            self.emit('error','TrueNAS request failed or timed out.')
            raise CollectorError('TrueNAS request failed or timed out.') from None
