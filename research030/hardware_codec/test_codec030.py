import unittest,sys,json,struct,hashlib
from pathlib import Path
import numpy as np
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from hardware_codec import codec030 as c

class CodecTests(unittest.TestCase):
    def test_contract_hash(self):
        obj=json.loads((c.HERE/'feature_contract.json').read_text())
        self.assertEqual(hashlib.sha256(json.dumps(obj,sort_keys=True,separators=(',',':')).encode()).digest(),c.SCHEMA)
    def test_all_envelopes(self):
        for kind,abi in c.ABI.items():
            model=c.bootstrap(kind);e=c.sign_envelope(model,42,'unit-test');d=c.envelope_metadata(e)
            self.assertEqual(d['version'],42);self.assertEqual(d['runtime_abi'],abi)
            self.assertEqual(d['envelope_bytes'],len(e))
            for index in (70,len(e)-1):
                tampered=bytearray(e);tampered[index]^=1
                with self.assertRaises(Exception):c.envelope_metadata(bytes(tampered))
    def test_float_threshold_endpoints(self):
        for kind in ('lr','dt','mlp_float'):
            for t in (0.,1.):
                m=c.bootstrap(kind);m['threshold']=t;c.sign_envelope(m,1,'endpoints')
            for t in (-1.,float(np.nextafter(np.float32(1),np.float32(2)))):
                m=c.bootstrap(kind);m['threshold']=t
                with self.assertRaises(ValueError):c.sign_envelope(m,1,'invalid')
    def test_integer_bounds(self):
        m=c.bootstrap('mlp_int8');m['layers'][0]['bias'][0]=2147483647
        with self.assertRaises(ValueError):c.sign_envelope(m,1,'overflow')
        m=c.bootstrap('mlp_int8');m['layers'][0]['weights'][0][0]=-128
        with self.assertRaises(ValueError):c.sign_envelope(m,1,'weight')
        for s in (0,63):
            m=c.bootstrap('mlp_int8');m['layers'][0]['shift']=s
            with self.assertRaises(ValueError):c.sign_envelope(m,1,'shift')
    def test_authenticated_bad_contract(self):
        e=c.bad_contract_envelope(c.bootstrap('lr'),2,'bad-schema')
        plen=struct.unpack_from('<I',e,8)[0]
        c.key().public_key().verify(e[16+plen:],e[16:16+plen],c.padding.PKCS1v15(),c.hashes.SHA256())
        self.assertNotEqual(e[40:72],c.SCHEMA)
        with self.assertRaises(ValueError):c.envelope_metadata(e)
    def test_real_template_patch_and_binding(self):
        templates=list((c.HERE.parent/'prebuilt').glob('*/ids_update_lab.bin'))
        self.assertEqual(len(templates),8)
        for path in templates:
            kind=path.parent.name.rsplit('_',1)[0];template=path.read_bytes()
            for v in (1,10,4294967295):
                model=c.bootstrap(kind);model['threshold']=1.
                e=c.sign_envelope(model,v,'patched')
                result=c.patch_image(template,e);meta=c.whole_manifest(result,e)
                self.assertEqual(meta['version'],v)
                self.assertEqual(meta['elf_sha256'],c.image_metadata(template)['elf_sha256'])
                self.assertEqual(result.count(e),1)
                self.assertEqual(len(result),len(template))
                damaged=bytearray(result);damaged[48]^=1
                with self.assertRaises(ValueError):c.verify_image(damaged)
            wrong='dt' if kind!='dt' else 'lr'
            with self.assertRaises(ValueError):c.patch_image(template,c.sign_envelope(c.bootstrap(wrong),2,'wrong-abi'))
if __name__=='__main__':unittest.main()
