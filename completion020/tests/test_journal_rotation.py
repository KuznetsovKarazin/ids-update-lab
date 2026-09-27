"""Native 70-update execution of the actual journal rotation runner.
No MCU identity is forged and no native timing is reported as MCU evidence.
"""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'host'))
from ids_update_lab import package,serial_runner

def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
s=load(ROOT/'tools/campaign_support.py','rotation_support_test')
r=load(ROOT/'tools/run_completion.py','rotation_campaign_test')
m=load(ROOT/'tools/check_journal_rotation.py','rotation_test')

class RotationTests(unittest.TestCase):
    def test_70_updates_and_both_journal_page_boundaries_real_cpp(self):
        with tempfile.TemporaryDirectory() as td:
            temp=Path(td);core=ROOT/'firmware/components/ids_core';inc=temp/'include';inc.mkdir()
            (inc/'model_contract.h').write_bytes((ROOT/'artifacts/lr/headers/A.h').read_bytes())
            exe=temp/'native';subprocess.run(['g++','-std=c++17','-O2','-Wall','-Wextra','-Wpedantic','-Werror','-ffp-contract=off','-I'+str(core/'include'),'-I'+str(inc),str(core/'ids_core.cpp'),str(core/'ids_tree.cpp'),str(core/'ids_protocol.cpp'),str(ROOT/'firmware/native/main.cpp'),'-lcrypto','-o',str(exe)],capture_output=True,check=True,text=True)
            family=ROOT/'artifacts/lr';experiment=s.read_json(family/'experiment.json');key=package.load_public(family/'public.pem')
            blobs={k:(family/v['package']).read_bytes() for k,v in experiment['models'].items()}
            models={k:package.verify(v,key,bytes.fromhex(experiment['schema_sha256']),8,expected_abi=2) for k,v in blobs.items()}
            c={'root':ROOT,'public':key,'package':package,'schema':experiment['schema_sha256'],'models':models,
               'digests':{k:v['payload_sha256'] for k,v in experiment['models'].items()},
               'golden':[json.loads(line) for line in (family/'golden.jsonl').read_text().splitlines()],
               'expected_chip':'native_host_NOT_MCU','measurement_origin':'native_host_NOT_MCU',
               'build':{'images':{'A':{'expected_build':'native-shared-core-v1'}}}}
            class Adapter:
                def __init__(self,port,on_read=None):
                    self.native=serial_runner.NativeTransport(exe,temp/'store',False);self.received_bytes=0
                def write(self,line):self.native.write(line)
                def readline(self,timeout):
                    line=self.native.readline(timeout)
                    if line is not None:self.received_bytes+=len(line)+1
                    return line
                def take_pending_fragment(self):return b''
                def close(self):self.native.close()
            serial=types.SimpleNamespace(SerialTransport=Adapter,synchronize_serial=lambda t,record,timeout:serial_runner.synchronize_serial(t,record,timeout,startup_wait=.01,quiet_period=.001))
            out=temp/'run';out.mkdir();api=r.legacy(ROOT);e=api.Evidence(out);link=api.Link(serial,e,5);summary=m.fresh_summary()
            try:m.execute_chain(link,e,s,c,m.series(s,c),summary,link.open('native'))
            finally:link.close();e.close()
            self.assertEqual(summary['status'],'complete');self.assertEqual(summary['measurement_origin'],'native_host_NOT_MCU')
            self.assertEqual(summary['accepted_updates'],70);self.assertEqual(summary['verified_reboots'],3)
            self.assertEqual(summary['inferred_records'],74);self.assertEqual(summary['label_mismatches'],0)
            self.assertEqual(summary['final_selector_sequence'],71);self.assertEqual(summary['final_version'],10070)
            # Both physical native journal pages have been used; first page
            # holds sequence65 after erasing its original sequence1..32 records.
            def sequence(data,index):
                row=data[index*128:(index+1)*128]
                self.assertTrue(all((row[i]^row[i+1])==255 for i in range(0,128,2)))
                plain=row[0:112:2];return int.from_bytes(plain[8:16],'little')
            page0=(temp/'store/ids_meta0.bin').read_bytes();page1=(temp/'store/ids_meta1.bin').read_bytes()
            self.assertEqual(sequence(page0,0),65);self.assertEqual(sequence(page0,6),71)
            self.assertEqual(sequence(page1,0),33);self.assertEqual(sequence(page1,31),64)
            destination=ROOT/'validation/rotation';destination.mkdir(parents=True,exist_ok=True)
            s.save(destination/'native_rotation_summary.json',summary)
            (destination/'native_events.jsonl').write_bytes((out/'events.jsonl').read_bytes())

    def test_selector_sequence_boolean_is_not_accepted_as_integer(self):
        c={'schema':'x','build':{'images':{'A':{'expected_build':'y'}}}}
        with self.assertRaises(RuntimeError):
            m.check_state({'event':'status','ready':True,'reason':'ok','version':1,'release':'A',
                          'bundle_sha256':'z','selector_sequence':True},s,c,{'version':1,'release':'A','digest':'z'},1)

if __name__=='__main__':unittest.main()
