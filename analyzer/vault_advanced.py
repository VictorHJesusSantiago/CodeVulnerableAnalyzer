"""Cofre AEAD versionado com RBAC, TTL, rotação, Shamir e auditoria encadeada."""
from __future__ import annotations
import hashlib, hmac, json, secrets, struct, time
from dataclasses import dataclass, asdict
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Tuple

class VaultSecurityError(Exception): pass

def scrypt_kdf(password: str, salt: bytes, length: int = 32, n: int = 2**14, r: int = 8, p: int = 1) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=length)

def _rotl(v: int, n: int) -> int: return ((v << n) & 0xffffffff) | (v >> (32-n))
def _quarter(s: List[int], a: int,b: int,c: int,d: int) -> None:
    s[a]=(s[a]+s[b])&0xffffffff;s[d]=_rotl(s[d]^s[a],16)
    s[c]=(s[c]+s[d])&0xffffffff;s[b]=_rotl(s[b]^s[c],12)
    s[a]=(s[a]+s[b])&0xffffffff;s[d]=_rotl(s[d]^s[a],8)
    s[c]=(s[c]+s[d])&0xffffffff;s[b]=_rotl(s[b]^s[c],7)
def _chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state=list(struct.unpack("<4I",b"expand 32-byte k"))+list(struct.unpack("<8I",key))+[counter]+list(struct.unpack("<3I",nonce))
    work=state[:]
    for _ in range(10):
        for x in ((0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)): _quarter(work,*x)
    return struct.pack("<16I",*((work[i]+state[i])&0xffffffff for i in range(16)))
def _stream(key: bytes, nonce: bytes, data: bytes, counter: int=1) -> bytes:
    out=bytearray()
    for off in range(0,len(data),64):
        block=_chacha_block(key,counter+off//64,nonce)
        out.extend(a^b for a,b in zip(data[off:off+64],block))
    return bytes(out)
def _poly1305(msg: bytes, key: bytes) -> bytes:
    r=int.from_bytes(key[:16],"little") & 0x0ffffffc0ffffffc0ffffffc0fffffff
    s=int.from_bytes(key[16:],"little"); acc=0; p=(1<<130)-5
    for i in range(0,len(msg),16):
        chunk=msg[i:i+16]; acc=(acc+int.from_bytes(chunk+b"\x01","little"))*r%p
    return ((acc+s)%(1<<128)).to_bytes(16,"little")
def _pad16(data: bytes) -> bytes: return b"" if len(data)%16==0 else b"\0"*(16-len(data)%16)

def chacha20poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes=b"") -> Tuple[bytes,bytes]:
    if len(key)!=32 or len(nonce)!=12: raise ValueError("ChaCha20 requer chave de 32 bytes e nonce de 12 bytes")
    cipher=_stream(key,nonce,plaintext)
    mac_data=aad+_pad16(aad)+cipher+_pad16(cipher)+struct.pack("<QQ",len(aad),len(cipher))
    return cipher,_poly1305(mac_data,_chacha_block(key,0,nonce)[:32])

def chacha20poly1305_decrypt(key: bytes, nonce: bytes, cipher: bytes, tag: bytes, aad: bytes=b"") -> bytes:
    mac_data=aad+_pad16(aad)+cipher+_pad16(cipher)+struct.pack("<QQ",len(aad),len(cipher))
    expected=_poly1305(mac_data,_chacha_block(key,0,nonce)[:32])
    if not hmac.compare_digest(expected,tag): raise VaultSecurityError("Tag AEAD inválida")
    return _stream(key,nonce,cipher)

def shamir_split(secret: bytes, shares: int, threshold: int) -> List[str]:
    """Secret sharing sobre GF(257); cada elemento ocupa dois bytes."""
    if not 2<=threshold<=shares<=255: raise ValueError("Use 2 <= threshold <= shares <= 255")
    coeffs=[[b]+[secrets.randbelow(257) for _ in range(threshold-1)] for b in secret]
    result=[]
    for x in range(1,shares+1):
        values=[sum(c*pow(x,i,257) for i,c in enumerate(poly))%257 for poly in coeffs]
        result.append(f"{x}-"+b"".join(v.to_bytes(2,"big") for v in values).hex())
    return result

def shamir_combine(parts: Iterable[str]) -> bytes:
    parsed=[]
    for part in parts:
        sx,raw=part.split("-",1); data=bytes.fromhex(raw)
        parsed.append((int(sx),[int.from_bytes(data[i:i+2],"big") for i in range(0,len(data),2)]))
    if len(parsed)<2: raise ValueError("São necessárias ao menos duas partes")
    out=[]
    for pos in range(len(parsed[0][1])):
        total=0
        for j,(xj,vals) in enumerate(parsed):
            num=den=1
            for m,(xm,_) in enumerate(parsed):
                if m!=j: num=num*(-xm)%257; den=den*(xj-xm)%257
            total=(total+vals[pos]*num*pow(den,-1,257))%257
        if total>255: raise VaultSecurityError("Partes inválidas")
        out.append(total)
    return bytes(out)

class KeyProvider(Protocol):
    def wrap(self, key: bytes, context: Dict[str,str]) -> bytes: ...
    def unwrap(self, wrapped: bytes, context: Dict[str,str]) -> bytes: ...

class CallbackKeyProvider:
    """Adaptador seguro para TPM, YubiKey/FIDO2 ou AWS/Azure/GCP KMS."""
    def __init__(self, wrap: Callable[[bytes,Dict[str,str]],bytes], unwrap: Callable[[bytes,Dict[str,str]],bytes]):
        self._wrap,self._unwrap=wrap,unwrap
    def wrap(self,key:bytes,context:Dict[str,str])->bytes:return self._wrap(key,context)
    def unwrap(self,key:bytes,context:Dict[str,str])->bytes:return self._unwrap(key,context)

@dataclass
class SecretVersion:
    version:int; nonce:str; cipher:str; tag:str; created_at:float; expires_at:Optional[float]; metadata:Dict[str,Any]

class AdvancedVault:
    ROLES={"reader":{"read"},"writer":{"read","write"},"rotator":{"read","write","rotate"},"admin":{"read","write","rotate","delete","audit"}}
    def __init__(self,password:str):
        self.salt=secrets.token_bytes(16); self.key=scrypt_kdf(password,self.salt)
        self.entries:Dict[str,List[SecretVersion]]={}; self.bindings:Dict[str,set[str]]={}; self.audit:List[Dict[str,Any]]=[]
    def grant(self,actor:str,role:str)->None:
        if role not in self.ROLES: raise ValueError("Papel desconhecido")
        self.bindings.setdefault(actor,set()).add(role); self._audit(actor,"grant",role)
    def _allow(self,actor:str,action:str)->None:
        if not any(action in self.ROLES[r] for r in self.bindings.get(actor,set())): raise PermissionError(f"{actor} não pode {action}")
    def _audit(self,actor:str,action:str,target:str)->None:
        prev=self.audit[-1]["signature"] if self.audit else ""
        event={"at":time.time(),"actor":actor,"action":action,"target":target,"previous":prev}
        event["signature"]=hmac.new(self.key,json.dumps(event,sort_keys=True).encode(),hashlib.sha256).hexdigest()
        self.audit.append(event)
    def verify_audit(self)->bool:
        prev=""
        for item in self.audit:
            event={k:v for k,v in item.items() if k!="signature"}
            if event["previous"]!=prev or not hmac.compare_digest(item["signature"],hmac.new(self.key,json.dumps(event,sort_keys=True).encode(),hashlib.sha256).hexdigest()): return False
            prev=item["signature"]
        return True
    def put(self,name:str,value:str,actor:str,ttl:Optional[int]=None,metadata:Optional[Dict[str,Any]]=None)->int:
        self._allow(actor,"write"); versions=self.entries.setdefault(name,[]); number=len(versions)+1
        nonce=secrets.token_bytes(12); aad=f"{name}:{number}".encode()
        cipher,tag=chacha20poly1305_encrypt(self.key,nonce,value.encode(),aad)
        versions.append(SecretVersion(number,nonce.hex(),cipher.hex(),tag.hex(),time.time(),time.time()+ttl if ttl else None,metadata or {}))
        self._audit(actor,"write",f"{name}@{number}"); return number
    def get(self,name:str,actor:str,version:Optional[int]=None)->str:
        self._allow(actor,"read"); versions=self.entries.get(name,[])
        if not versions: raise KeyError(name)
        item=versions[-1] if version is None else next(v for v in versions if v.version==version)
        if item.expires_at and item.expires_at<=time.time(): raise VaultSecurityError("Segredo expirado")
        plain=chacha20poly1305_decrypt(self.key,bytes.fromhex(item.nonce),bytes.fromhex(item.cipher),bytes.fromhex(item.tag),f"{name}:{item.version}".encode())
        self._audit(actor,"read",f"{name}@{item.version}"); return plain.decode()
    def rotate(self,name:str,generator:Callable[[],str],actor:str,ttl:Optional[int]=None)->int:
        self._allow(actor,"rotate"); version=self.put(name,generator(),actor,ttl); self._audit(actor,"rotate",name); return version
    def leaked(self,candidates:Iterable[str],actor:str)->List[str]:
        self._allow(actor,"read"); values={hashlib.sha256(self.get(n,actor).encode()).digest():n for n in self.entries}
        return sorted({values[h] for value in candidates if (h:=hashlib.sha256(value.encode()).digest()) in values})
    def export_encrypted(self)->bytes:
        body=json.dumps({"salt":self.salt.hex(),"entries":{k:[asdict(v) for v in vals] for k,vals in self.entries.items()},"bindings":{k:sorted(v) for k,v in self.bindings.items()},"audit":self.audit},sort_keys=True).encode()
        nonce=secrets.token_bytes(12); cipher,tag=chacha20poly1305_encrypt(self.key,nonce,body,b"vulnscan-sync-v1")
        return b"CVAS1"+nonce+tag+cipher
    @classmethod
    def restore(cls,blob:bytes,password:str)->"AdvancedVault":
        # O salt está dentro do payload; backups devem ser acompanhados pelo salt externo.
        raise VaultSecurityError("Use restore_with_salt para impedir tentativa de derivação ambígua")
    @classmethod
    def restore_with_salt(cls,blob:bytes,password:str,salt:bytes)->"AdvancedVault":
        obj=cls.__new__(cls);obj.salt=salt;obj.key=scrypt_kdf(password,salt)
        raw=chacha20poly1305_decrypt(obj.key,blob[5:17],blob[33:],blob[17:33],b"vulnscan-sync-v1"); doc=json.loads(raw)
        obj.entries={k:[SecretVersion(**v) for v in vals] for k,vals in doc["entries"].items()}
        obj.bindings={k:set(v) for k,v in doc["bindings"].items()};obj.audit=doc["audit"];return obj

class MemorySecretAgent:
    def __init__(self,vault:AdvancedVault,idle_ttl:int=300):
        self.vault=vault;self.idle_ttl=idle_ttl;self.cache:Dict[Tuple[str,str],Tuple[float,str]]={}
    def get(self,name:str,actor:str)->str:
        key=(name,actor); now=time.monotonic()
        if key in self.cache and self.cache[key][0]>now:return self.cache[key][1]
        value=self.vault.get(name,actor);self.cache[key]=(now+self.idle_ttl,value);return value
    def lock(self)->None:self.cache.clear()
