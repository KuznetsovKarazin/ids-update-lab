"""Explicit PUBLIC DEVELOPMENT KEY and binary runtime contract for stage 030.

This is reproducible laboratory signing, not production key management. Image
patching changes the ESP image checksum/SHA and app version; embedded ELF SHA
identifies the original compiled template, NOT the patched image. The entire
patched image is separately SHA256 bound and RSA authenticated by FW_BEGIN.
"""
from pathlib import Path
import hashlib
import struct
import math
import numpy as np
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

HERE=Path(__file__).resolve().parent
ABI={'lr':2,'dt':3,'mlp_float':4,'mlp_int8':5}
MAGIC=b'IDS030FACTORYREG'
SCHEMA=bytes.fromhex('8f3aba7e6bce09ffd8fc1fad9c054081629076299f24a209e25a443c2d5b7225')
KEY_PATH=HERE/'PUBLIC_DEVELOPMENT_ONLY_private.pem'
def sha(b):return hashlib.sha256(b).hexdigest()
def key():return serialization.load_pem_private_key(KEY_PATH.read_bytes(),password=None)
def public_pem():return key().public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
def f32s(a):
    x=np.asarray(a,dtype='<f4')
    if not np.isfinite(x).all():raise ValueError('nonfinite parameter')
    return x.tobytes()

def payload(model,version,release):
    kind=model['kind'];abi=ABI[kind]
    if not 1<=int(version)<=0xffffffff:raise ValueError('version')
    r=release.encode('ascii')
    if not 1<=len(r)<=16 or any(c<33 or c>126 for c in r):raise ValueError('release')
    threshold=float(np.float32(model['threshold']))
    if not 0<=threshold<=1.0:raise ValueError('threshold')
    p=(b'SIDST01\0' if abi==3 else b'SIDSM01\0' if abi>=4 else b'SIDSB01\0')
    p+=struct.pack('<IIII',1,abi,int(version),8)+SCHEMA+r.ljust(16,b'\0')+struct.pack('<f',threshold)
    if abi==2:
        if len(model['weights'])!=8:raise ValueError('weights')
        p+=f32s([model['bias']])+f32s(model['mean'])+f32s(model['scale'])+f32s(model['weights'])
    elif abi==3:
        nodes=model['nodes']
        if not 1<=len(nodes)<=127:raise ValueError('tree node count')
        p+=struct.pack('<I',len(nodes))
        for n in nodes:
            leaf=n['feature']<0
            p+=struct.pack('<hhhHff',-1 if leaf else n['left'],-1 if leaf else n['right'],-1 if leaf else n['feature'],0,0 if leaf else n['threshold'],n['probability'])
    else:
        if len(model['layers'])!=3:raise ValueError('topology')
        p+=struct.pack('<I',3)+f32s(model['mean'])+f32s(model['scale'])+struct.pack('<4I',8,16,8,1)
        if abi==5:
            if not math.isfinite(model['input_scale']) or model['input_scale']<=0 or not -127<=model['q_threshold']<=128:raise ValueError('quantized input/threshold')
            p+=struct.pack('<fi',model['input_scale'],model['q_threshold'])
        dims=[8,16,8,1]
        for j,l in enumerate(model['layers']):
            w=np.asarray(l['weights']);b=np.asarray(l['bias'])
            if w.shape!=(dims[j],dims[j+1]) or b.shape!=(dims[j+1],):raise ValueError('layer shape')
            if abi==4:p+=f32s(w)+f32s(b)
            else:
                if (w!=np.rint(w)).any() or (w<-127).any() or (w>127).any():raise ValueError('int8 weights')
                if (b!=np.rint(b)).any() or (np.abs(b.astype(np.int64))+dims[j]*127*127>2147483647).any():raise ValueError('bias/accumulator bound')
                if not 1<=l['multiplier']<=2147483647 or not 1<=l['shift']<=62 or not math.isfinite(l['output_scale']) or l['output_scale']<=0:raise ValueError('requantization')
                p+=struct.pack('<IIf',l['multiplier'],l['shift'],l['output_scale'])+w.astype('i1').tobytes()+b.astype('<i4').tobytes()
    if abi!=3 and (len(model['mean'])!=8 or len(model['scale'])!=8 or any(x<=0 for x in model['scale'])):raise ValueError('preprocess')
    if len(p)+272>4096:raise ValueError('envelope exceeds runtime')
    return p

def sign_envelope(model,version,release):
    p=payload(model,version,release)
    sig=key().sign(p,padding.PKCS1v15(),hashes.SHA256())
    return b'SIDSPK1\0'+struct.pack('<II',len(p),len(sig))+p+sig

def bad_contract_envelope(model,version,release):
    """Authenticated deliberately incompatible schema, negative control only."""
    p=bytearray(payload(model,version,release));p[24]^=1;p=bytes(p)
    sig=key().sign(p,padding.PKCS1v15(),hashes.SHA256())
    return b'SIDSPK1\0'+struct.pack('<II',len(p),len(sig))+p+sig

def envelope_metadata(envelope):
    if len(envelope)<352 or envelope[:8]!=b'SIDSPK1\0':raise ValueError('envelope format')
    plen,slen=struct.unpack_from('<II',envelope,8)
    if slen!=256 or len(envelope)!=plen+272:raise ValueError('envelope size')
    p=envelope[16:16+plen]
    key().public_key().verify(envelope[16+plen:],p,padding.PKCS1v15(),hashes.SHA256())
    abi,version,count=struct.unpack_from('<III',p,12)
    if count!=8 or p[24:56]!=SCHEMA or abi not in ABI.values():raise ValueError('runtime schema')
    return {'runtime_abi':abi,'version':version,'feature_count':count,'schema':SCHEMA.hex(),'release':p[56:72].split(b'\0')[0].decode(),
            'bundle_sha256':sha(p),'envelope_sha256':sha(envelope),'envelope_bytes':len(envelope),'payload_bytes':plen,
            'pretransform':'identity' if abi==3 else 'log1p','decision_rule':'q>=q_threshold' if abi==5 else 'probability>threshold'}

def image_metadata(image):
    if image[0]!=0xe9 or struct.unpack_from('<I',image,32)[0]!=0xabcd5432:raise ValueError('ESP32-S3 image required')
    version=int(image[48:80].split(b'\0')[0]);sdk=image[144:176].split(b'\0')[0].decode();elf=image[176:208].hex()
    return {'version':version,'idf_version':sdk,'elf_sha256':elf,'elf_identity_scope':'compiled_template_before_model_patch',
            'image_sha256':sha(image),'image_size':len(image),'expected_build':f'esp-idf-{sdk};app={version};elf={elf[:9]}'}

def esp_segments(image):
    if len(image)<288 or image[0]!=0xe9 or image[23]!=1:raise ValueError('Expected SHA256-appended ESP image')
    pos=24;segments=[]
    for _ in range(image[1]):
        if pos+8>len(image):raise ValueError('Truncated segment')
        address,n=struct.unpack_from('<II',image,pos);start=pos+8;end=start+n
        if end>len(image):raise ValueError('Truncated segment body')
        segments.append((start,end));pos=end
    checksum_pos=(pos//16)*16+15
    if checksum_pos+33!=len(image):raise ValueError('Unexpected checksum/SHA offset or trailing signature')
    return segments,checksum_pos

def verify_image(image):
    segments,checksum_pos=esp_segments(image);cs=0xef
    for start,end in segments:
        for b in image[start:end]:cs^=b
    if image[checksum_pos]!=cs or hashlib.sha256(image[:checksum_pos+1]).digest()!=image[checksum_pos+1:]:raise ValueError('ESP image checksum/SHA mismatch')
    return image_metadata(image)

def patch_image(template,envelope):
    verify_image(template);info=envelope_metadata(envelope)
    if template.count(MAGIC)!=1:raise ValueError('Factory patch marker is not unique')
    pos=template.index(MAGIC);segments,checksum_pos=esp_segments(template)
    end=pos+16+4+4096
    if not any(start<=pos and end<=stop for start,stop in segments):raise ValueError('Patch region crosses an image segment')
    oldn=struct.unpack_from('<I',template,pos+16)[0]
    old=envelope_metadata(template[pos+20:pos+20+oldn])
    if info['runtime_abi']!=old['runtime_abi']:raise ValueError('Model/template ABI mismatch')
    image=bytearray(template);image[pos+16:pos+20]=struct.pack('<I',len(envelope));image[pos+20:end]=envelope.ljust(4096,b'\0')
    image[48:80]=str(info['version']).encode().ljust(32,b'\0')
    checksum=0xef
    for start,stop in segments:
        for b in image[start:stop]:checksum^=b
    image[checksum_pos]=checksum;image[checksum_pos+1:]=hashlib.sha256(image[:checksum_pos+1]).digest()
    result=bytes(image);verify_image(result)
    return result

def whole_manifest(image,envelope):
    i=verify_image(image);e=envelope_metadata(envelope)
    if i['version']!=e['version'] or image.count(envelope)!=1:raise ValueError('Image/model binding')
    metadata=b'SIDSFW1\0'+struct.pack('<II',e['version'],len(image))+hashlib.sha256(image).digest()+struct.pack('<I',e['runtime_abi'])+SCHEMA
    signature=key().sign(metadata,padding.PKCS1v15(),hashes.SHA256())
    return {'metadata_hex':metadata.hex(),'signature_hex':signature.hex(),**i,**e,'test_key':True}

def bootstrap(kind):
    m={'kind':kind,'threshold':.5,'mean':[0.]*8,'scale':[1.]*8}
    if kind=='lr':m.update(weights=[0.]*8,bias=0.)
    elif kind=='dt':m['nodes']=[{'feature':-1,'left':-1,'right':-1,'threshold':0.,'probability':0.}]
    else:
        dims=[8,16,8,1];m['layers']=[]
        for ni,no in zip(dims[:-1],dims[1:]):
            l={'weights':[[0]*no for _ in range(ni)],'bias':[0]*no}
            if kind=='mlp_int8':l.update(multiplier=1<<30,shift=30,output_scale=1.)
            m['layers'].append(l)
        if kind=='mlp_int8':m.update(input_scale=1.,q_threshold=1)
    return m

def header(kind):
    e=sign_envelope(bootstrap(kind),1,'bootstrap030');pem=public_pem().decode()
    def cbytes(b):return ','.join(str(i) for i in b)
    return '''// PUBLIC TEST KEY ONLY. Factory bytes are patched and re-signed by the host.
#pragma once
#include <cstdint>
#include <cstddef>
namespace ids_generated {
inline constexpr unsigned kFeatureCount=8;
inline constexpr unsigned kRuntimeAbi=%d;
inline constexpr unsigned kFactoryVersion = 1;
inline constexpr unsigned char kFeatureContractHash[32]={%s};
inline constexpr unsigned char kPublicKeyPem[]=R"PEM(%s)PEM";
inline constexpr const char* kDataOrigin="TON_IoT_temporal_030";
struct FactoryRegion { unsigned char magic[16]; uint32_t length; unsigned char bytes[4096]; };
__attribute__((used)) inline const FactoryRegion kFactoryRegion={{%s},%d,{%s}};
inline const unsigned char* factory_envelope(){return kFactoryRegion.bytes;}
inline size_t factory_length(){return reinterpret_cast<const volatile FactoryRegion*>(&kFactoryRegion)->length;}
inline uint32_t factory_version(){const volatile unsigned char* p=kFactoryRegion.bytes+32;return uint32_t(p[0])|uint32_t(p[1])<<8|uint32_t(p[2])<<16|uint32_t(p[3])<<24;}
}
'''%(ABI[kind],cbytes(SCHEMA),pem,cbytes(MAGIC),len(e),cbytes(e))
