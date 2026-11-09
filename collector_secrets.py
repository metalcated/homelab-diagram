"""Session credentials or opt-in macOS Keychain storage; never SQLite or argv."""
import ctypes
import json
import sys
import threading


class Keychain:
    def __init__(self):
        if sys.platform!='darwin':raise ValueError('macOS Keychain is unavailable on this platform.')
        self.cf=ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')
        self.sec=ctypes.CDLL('/System/Library/Frameworks/Security.framework/Security')
        p=ctypes.c_void_p
        self.cf.CFStringCreateWithCString.argtypes=[p,ctypes.c_char_p,ctypes.c_uint32];self.cf.CFStringCreateWithCString.restype=p
        self.cf.CFDataCreate.argtypes=[p,p,ctypes.c_long];self.cf.CFDataCreate.restype=p
        self.cf.CFDataGetLength.argtypes=[p];self.cf.CFDataGetLength.restype=ctypes.c_long
        self.cf.CFDataGetBytePtr.argtypes=[p];self.cf.CFDataGetBytePtr.restype=p
        self.cf.CFDictionaryCreateMutable.argtypes=[p,ctypes.c_long,p,p];self.cf.CFDictionaryCreateMutable.restype=p
        self.cf.CFDictionarySetValue.argtypes=[p,p,p]
        self.cf.CFRelease.argtypes=[p]
        self.sec.SecItemAdd.argtypes=[p,p];self.sec.SecItemAdd.restype=ctypes.c_int32
        self.sec.SecItemUpdate.argtypes=[p,p];self.sec.SecItemUpdate.restype=ctypes.c_int32
        self.sec.SecItemCopyMatching.argtypes=[p,ctypes.POINTER(p)];self.sec.SecItemCopyMatching.restype=ctypes.c_int32

    def constant(self,name):
        return ctypes.c_void_p.in_dll(self.sec,name).value

    def operation(self,account,secret=None):
        owned=[]
        def string(value):
            p=self.cf.CFStringCreateWithCString(None,value.encode(),0x08000100);owned.append(p);return p
        def dictionary(values):
            p=self.cf.CFDictionaryCreateMutable(None,0,None,None);owned.append(p)
            for k,v in values:self.cf.CFDictionarySetValue(p,self.constant(k),v)
            return p
        try:
            base=[('kSecClass',self.constant('kSecClassGenericPassword')),
                  ('kSecAttrService',string('net.metalcated.homelab-diagram.collector')),
                  ('kSecAttrAccount',string(account))]
            if secret is None:
                true=ctypes.c_void_p.in_dll(self.cf,'kCFBooleanTrue').value
                query=dictionary(base+[('kSecReturnData',true),('kSecMatchLimit',self.constant('kSecMatchLimitOne')),
                                       ('kSecUseAuthenticationUI',self.constant('kSecUseAuthenticationUIFail'))])
                result=ctypes.c_void_p()
                status=self.sec.SecItemCopyMatching(query,ctypes.byref(result))
                if status==-25300:return None
                if status:raise ValueError('Keychain is locked or requires approval. Re-enter the credential for this session or unlock Keychain.')
                try:
                    return json.loads(ctypes.string_at(self.cf.CFDataGetBytePtr(result),self.cf.CFDataGetLength(result)))
                finally:self.cf.CFRelease(result)
            raw=json.dumps(secret).encode()
            buffer=ctypes.create_string_buffer(raw)
            data=self.cf.CFDataCreate(None,ctypes.cast(buffer,ctypes.c_void_p),len(raw));owned.append(data)
            status=self.sec.SecItemAdd(dictionary(base+[('kSecValueData',data)]),None)
            if status==-25299:status=self.sec.SecItemUpdate(dictionary(base),dictionary([('kSecValueData',data)]))
            if status:raise ValueError('Could not save credentials to macOS Keychain. Use session-only storage or unlock Keychain.')
        finally:
            for value in reversed(owned):
                if value:self.cf.CFRelease(value)


class Vault:
    def __init__(self):
        self.memory={}
        self.lock=threading.Lock()
        try:self.keychain=Keychain()
        except (ValueError,OSError,AttributeError):self.keychain=None

    def put(self,key,values,persistent=False):
        if not isinstance(values,dict) or any(not isinstance(v,str) or len(v)>4096 or any(ord(c)<32 for c in v) for v in values.values()):
            raise ValueError('Invalid collector credential fields.')
        values={k:v for k,v in values.items() if k in ('password','community','auth_password','privacy_password') and v}
        if not values:return None
        with self.lock:
            if persistent:
                if self.keychain is None:raise ValueError('macOS Keychain is unavailable. Choose session-only storage.')
                self.keychain.operation(key,values)
                if self.keychain.operation(key)!=values:
                    raise ValueError('Keychain read-back did not match the credential submitted. Save was not confirmed; re-enter it or choose session-only storage.')
            self.memory[key]=dict(values)
        return 'keychain' if persistent else 'session'

    def get(self,key,mode):
        with self.lock:
            if key in self.memory:return dict(self.memory[key])
        if mode=='keychain' and self.keychain is not None:
            result=self.keychain.operation(key)
            if result:return result
        raise ValueError('This connection needs credentials. Edit it and enter them before collecting.')
