#!/usr/bin/env python3
"""Author: Oleksandr Kuznetsov. Actual OTA dispatcher + real RSA/SHA + fake flash.

Native checks do not exercise ESP-IDF flash, boot validation or physical hardware.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import zlib

REPO=Path(__file__).resolve().parents[2]
def module(name,path):
    s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
codec=module('ota039_codec',REPO/'research030/hardware_codec/codec030.py')
stubs=module('ota039_original_stubs',REPO/'tests/test_ota_timing.py').HEADERS
SOURCE=r'''
#include "firmware_ota.h"
#include "esp_ota_ops.h"
#include "mbedtls/sha256.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <vector>
static std::vector<unsigned char> flash;
static esp_partition_t partition{0x1d0000};
static esp_app_desc_t current{"1"};
static int64_t clock_us=0;
static unsigned selections=0,aborts=0;
class Crypto final : public ids::Crypto {
  EVP_PKEY* key;
public:
  explicit Crypto(const char* filename) { FILE* f=std::fopen(filename,"r");key=PEM_read_PUBKEY(f,nullptr,nullptr,nullptr);std::fclose(f); }
  ~Crypto(){EVP_PKEY_free(key);}
  bool verify(const uint8_t* p,size_t n,const uint8_t* signature) override {
    EVP_MD_CTX* ctx=EVP_MD_CTX_new();EVP_PKEY_CTX* pctx=nullptr;
    bool ok=EVP_DigestVerifyInit(ctx,&pctx,EVP_sha256(),nullptr,key)==1 &&
      EVP_PKEY_CTX_set_rsa_padding(pctx,RSA_PKCS1_PADDING)==1 &&
      EVP_DigestVerify(ctx,signature,256,p,n)==1;
    EVP_MD_CTX_free(ctx);return ok;
  }
  bool sha256(const uint8_t* p,size_t n,uint8_t* out) override {
    unsigned len=0;return EVP_Digest(p,n,out,&len,EVP_sha256(),nullptr)==1 && len==32;
  }
};
int64_t esp_timer_get_time(){return ++clock_us;}
const esp_partition_t* esp_ota_get_next_update_partition(const esp_partition_t*){return &partition;}
esp_err_t esp_ota_begin(const esp_partition_t*,size_t,esp_ota_handle_t* handle){flash.clear();*handle=1;return ESP_OK;}
esp_err_t esp_ota_write(esp_ota_handle_t,const void* p,size_t n){const auto* b=static_cast<const unsigned char*>(p);flash.insert(flash.end(),b,b+n);return ESP_OK;}
esp_err_t esp_ota_abort(esp_ota_handle_t){++aborts;return ESP_OK;}
esp_err_t esp_ota_end(esp_ota_handle_t){return ESP_OK;}
esp_err_t esp_ota_get_partition_description(const esp_partition_t*,esp_app_desc_t* out){if(flash.size()<80)return -1;std::memcpy(out->version,flash.data()+48,32);return ESP_OK;}
esp_err_t esp_ota_set_boot_partition(const esp_partition_t*){++selections;return ESP_OK;}
const esp_app_desc_t* esp_app_get_description(){return &current;}
void mbedtls_sha256_init(mbedtls_sha256_context* c){c->ctx=EVP_MD_CTX_new();}
void mbedtls_sha256_free(mbedtls_sha256_context* c){EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(c->ctx));c->ctx=nullptr;}
int mbedtls_sha256_starts(mbedtls_sha256_context* c,int){return EVP_DigestInit_ex(static_cast<EVP_MD_CTX*>(c->ctx),EVP_sha256(),nullptr)==1?0:-1;}
int mbedtls_sha256_update(mbedtls_sha256_context* c,const unsigned char* p,size_t n){return EVP_DigestUpdate(static_cast<EVP_MD_CTX*>(c->ctx),p,n)==1?0:-1;}
int mbedtls_sha256_finish(mbedtls_sha256_context* c,unsigned char* out){unsigned n=0;return EVP_DigestFinal_ex(static_cast<EVP_MD_CTX*>(c->ctx),out,&n)==1&&n==32?0:-1;}
int main(int argc,char** argv){
  if(argc!=2)return 2;Crypto crypto(argv[1]);
  const unsigned char schema[32]={0x8f,0x3a,0xba,0x7e,0x6b,0xce,0x09,0xff,0xd8,0xfc,0x1f,0xad,0x9c,0x05,0x40,0x81,0x62,0x90,0x76,0x29,0x9f,0x24,0xa2,0x09,0xe2,0x5a,0x44,0x3c,0x2d,0x5b,0x72,0x25};
  firmware_ota_init(crypto,1,schema,2);std::string line;
  while(std::getline(std::cin,line))if(!firmware_ota_process(line.c_str()))return 3;
  unsigned char digest[32];crypto.sha256(flash.data(),flash.size(),digest);
  std::printf("{\"event\":\"native_summary\",\"selections\":%u,\"aborts\":%u,\"bytes\":%zu,\"sha256\":\"",selections,aborts,flash.size());
  for(unsigned char c:digest)std::printf("%02x",c);std::printf("\"}\n");
}
'''

class OtaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        headers=dict(stubs);headers['mbedtls/sha256.h']=headers['mbedtls/sha256.h'].replace('unsigned char value;','void* ctx;')
        for name,value in headers.items():
            p=cls.root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value)
        (cls.root/'runner.cpp').write_text(SOURCE);(cls.root/'public.pem').write_bytes(codec.public_pem())
        firmware=REPO/'revision039/firmware';vendor=firmware/'components/miniz_tinfl'
        subprocess.run(['cc','-fPIC','-O2','-I'+str(vendor),'-c',str(vendor/'miniz_tinfl.c'),'-o',str(cls.root/'miniz.o')],check=True)
        subprocess.run(['c++','-std=c++17','-O2','-I'+str(cls.root),'-I'+str(firmware/'main'),
            '-I'+str(firmware/'components/ids_core/include'),'-I'+str(vendor),str(cls.root/'runner.cpp'),
            str(firmware/'main/firmware_ota.cpp'),str(cls.root/'miniz.o'),'-lcrypto','-o',str(cls.root/'runner')],check=True)
        model=json.loads((REPO/'paper037/evidence_inputs/training/models/B_lr.json').read_text())
        cls.envelope=codec.sign_envelope(model,2,'native039')
        cls.image=codec.patch_image((REPO/'research030/prebuilt/lr_whole/ids_update_lab.bin').read_bytes(),cls.envelope)
        cls.manifest=codec.whole_manifest(cls.image,cls.envelope)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def commands(self,compressed=True,data=None,manifest=None):
        manifest=manifest or self.manifest;data=self.image if data is None else data
        prefix='FWZ' if compressed else 'FW';encoded=zlib.compress(data,6) if compressed else data
        commands=[f'{prefix}_BEGIN {manifest["metadata_hex"]} {manifest["signature_hex"]}'+(f' {len(encoded)}' if compressed else '')]
        commands += [f'{prefix}_CHUNK {i} {encoded[i:i+1024].hex()}' for i in range(0,len(encoded),1024)]
        commands.append(prefix+'_END');return commands
    def execute(self,commands):
        p=subprocess.run([str(self.root/'runner'),str(self.root/'public.pem')],input='\n'.join(commands)+'\n',capture_output=True,text=True,check=True)
        return [json.loads(s) for s in p.stdout.splitlines()]
    def test_both_transports_reconstruct_exact_signed_image(self):
        for compressed in (False,True):
            rows=self.execute(self.commands(compressed))
            self.assertEqual(rows[-2]['event'],'fw_ready');self.assertEqual(rows[-1]['selections'],1)
            self.assertEqual(rows[-1]['sha256'],hashlib.sha256(self.image).hexdigest())
            ready=rows[-2]
            self.assertEqual(ready['device_active_us'],ready['begin_us']+ready['chunk_sum_us']+ready['finalize_us'])
    def test_signed_image_hash_failure_then_valid_retry_resets_state(self):
        altered=self.image[:-1]+bytes([self.image[-1]^1])
        rows=self.execute(self.commands(data=altered)+self.commands())
        errors=[x.get('error') for x in rows if x['event']=='fw_error']
        self.assertEqual(errors,['image_sha256']);self.assertEqual(rows[-1]['selections'],1)
        self.assertEqual(rows[-1]['aborts'],1)
    def test_invalid_signature_does_not_write_flash(self):
        m=dict(self.manifest);m['signature_hex']='00'+m['signature_hex'][2:]
        rows=self.execute(self.commands(manifest=m)[:1])
        self.assertEqual(rows[0]['error'],'signature');self.assertEqual(rows[-1]['bytes'],0)
        self.assertEqual(rows[-1]['selections'],0)
    def test_validly_signed_replay_and_wrong_contract_rejected_before_flash(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        for change,error in (('version','non_monotonic_version'),('schema','feature_schema')):
            metadata=bytearray.fromhex(self.manifest['metadata_hex'])
            if change=='version':metadata[8:12]=(1).to_bytes(4,'little')
            else:metadata[52]^=1
            signature=codec.key().sign(bytes(metadata),padding.PKCS1v15(),hashes.SHA256())
            m=dict(metadata_hex=metadata.hex(),signature_hex=signature.hex())
            rows=self.execute(self.commands(manifest=m)[:1])
            self.assertEqual(rows[0]['error'],error)
            self.assertEqual(rows[-1]['bytes'],0);self.assertEqual(rows[-1]['selections'],0)
    def test_truncated_stream_and_wrong_offsets_do_not_select(self):
        c=self.commands();truncated=c[:-2]+['FWZ_END']
        rows=self.execute(truncated);self.assertEqual(rows[-2]['error'],'incomplete_image')
        self.assertEqual(rows[-1]['selections'],0)
        c[1]=c[1].replace('FWZ_CHUNK 0 ','FWZ_CHUNK 1 ')
        rows=self.execute(c[:2]);self.assertEqual(rows[1]['error'],'chunk_order_or_size')
        self.assertEqual(rows[-1]['selections'],0)
    def test_encoding_cannot_change_mid_transfer(self):
        c=self.commands();c[1]=c[1].replace('FWZ_CHUNK','FW_CHUNK')
        rows=self.execute(c[:2]);self.assertEqual(rows[1]['error'],'encoding_mismatch')
        self.assertEqual(rows[-1]['selections'],0)
    def test_boot_descriptor_must_match_manifest_version(self):
        changed=bytearray(self.image);changed[48]=ord('3')
        metadata=bytearray.fromhex(self.manifest['metadata_hex']);metadata[16:48]=hashlib.sha256(changed).digest()
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        signed=codec.key().sign(bytes(metadata),padding.PKCS1v15(),hashes.SHA256())
        m=dict(metadata_hex=metadata.hex(),signature_hex=signed.hex())
        rows=self.execute(self.commands(data=bytes(changed),manifest=m))
        self.assertEqual(rows[-2]['error'],'embedded_version');self.assertEqual(rows[-1]['selections'],0)
if __name__=='__main__':unittest.main()
