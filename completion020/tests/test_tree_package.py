import ctypes
from dataclasses import replace
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import shutil
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'host'))
import numpy as np
from ids_update_lab import tree_package as t
from ids_update_lab import package as lr

class TreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory()
        tmp=Path(cls.temp.name)
        (tmp/'wrapper.cpp').write_text('''#include "ids_tree.h"
extern "C" int check(const unsigned char* p, unsigned n, unsigned features) {
 ids::TreeData t; return ids::decode_tree_body(p,n,features,t); }
extern "C" int predict(const unsigned char* p,unsigned n,unsigned features,const float* x,float* result) {
 ids::TreeData t; if(!ids::decode_tree_body(p,n,features,t))return 0;
 return ids::infer_tree(t,x,features,*result); }
''')
        subprocess.run(['g++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-shared','-fPIC',
            '-I'+str(ROOT/'firmware/components/ids_core/include'),str(tmp/'wrapper.cpp'),
            str(ROOT/'firmware/components/ids_core/ids_tree.cpp'),'-o',str(tmp/'tree.so')],check=True)
        cls.native=ctypes.CDLL(str(tmp/'tree.so'))
        cls.native.check.argtypes=[ctypes.c_void_p,ctypes.c_uint,ctypes.c_uint]
        cls.native.predict.argtypes=[ctypes.c_void_p,ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_void_p]
        cls.pub=lr.load_public(ROOT/'artifacts/dt/public.pem')
        cls.models={p:t.verify((ROOT/'artifacts/dt'/('release-'+p+'.sids')).read_bytes(),cls.pub) for p in ('A','B','C')}
        cls.golden=[json.loads(x) for x in (ROOT/'artifacts/dt/golden.jsonl').read_text().splitlines()]
        spec=importlib.util.spec_from_file_location('prep',ROOT/'tools/prepare_completion_artifacts.py')
        cls.prep=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.prep)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def native_valid(self,data):return bool(self.native.check(data,len(data),8))
    def test_signed_roundtrip(self):
        for model in self.models.values():
            self.assertEqual(t.parse_payload(model.payload()),model)
            self.assertTrue(self.native_valid(model.payload()))
    def test_all_golden_agree_native(self):
        for name,model in self.models.items():
            data=model.payload()
            for row in self.golden:
                x=np.asarray(row['raw'],dtype=np.float32);p=ctypes.c_float()
                self.assertTrue(self.native.predict(data,len(data),8,x.ctypes.data,ctypes.byref(p)))
                self.assertEqual(p.value,row['expected'][name]['probability'])
                self.assertEqual(int(p.value>model.threshold),row['expected'][name]['label'])
    def test_original_split_predicate_boundary(self):
        tested=0
        for phase in ('A','B'):
            source=json.loads((ROOT/'references/frozen_development'/('DT5_raw_'+phase)/'model.json').read_text())
            for i,node in enumerate(self.models[phase].nodes):
                if node.left<0:continue
                original=source['split_thresholds_float64'][i]
                value=np.float32(node.split)
                for x in (np.nextafter(value,np.float32(-np.inf),dtype=np.float32),value,np.nextafter(value,np.float32(np.inf),dtype=np.float32)):
                    self.assertEqual(float(x)<=original,x<=value)
                    tested+=1
        self.assertEqual(tested,153)
    def test_float32_floor_is_directed(self):
        a=np.float32(1.0);b=np.nextafter(a,np.float32(np.inf),dtype=np.float32)
        original=float(a)+(float(b)-float(a))*0.75
        self.assertEqual(np.float32(original),b)
        self.assertEqual(self.prep.float32_floor(original),a)
    def test_C_B_parameters(self):
        self.assertEqual(self.models['B'].nodes,self.models['C'].nodes)
        self.assertEqual(self.models['B'].threshold,self.models['C'].threshold)
        self.assertEqual(self.models['C'].version,3)
    def test_wrong_signature(self):
        with self.assertRaises(lr.PackageError):t.verify((ROOT/'artifacts/dt/bad-signature.sids').read_bytes(),self.pub)
    def test_wrong_contract(self):
        with self.assertRaises(lr.PackageError):t.verify((ROOT/'artifacts/dt/bad-contract.sids').read_bytes(),self.pub,self.models['B'].schema)
    def test_wrong_abi(self):
        with self.assertRaises(lr.PackageError):t.verify((ROOT/'artifacts/dt/release-B.sids').read_bytes(),self.pub,expected_abi=2)
    def test_reject_domain(self):
        for bad in (-1,float('inf'),float('nan'),1e100):
            row=[0.]*8;row[3]=bad
            with self.assertRaises(lr.PackageError):t.infer(self.models['A'],row)
    def test_mutated_body_rejected_host_native(self):
        base=self.models['A'].payload();cases=[]
        for offset,fmt,value in ((76,'I',0),(76,'I',128),(80,'h',0),(82,'h',0),(84,'h',8),
                (86,'H',1),(88,'f',float('nan')),(92,'f',float('inf')),(92,'f',1.1),
                (80,'h',-1)):
            data=bytearray(base);struct.pack_into('<'+fmt,data,offset,value);cases.append(bytes(data))
        cases.extend((base[:-1],base+b'\0'))
        leaf=next(i for i,node in enumerate(self.models['A'].nodes) if node.left==-1)
        for offset,fmt,value in ((80+16*leaf+4,'h',0),(80+16*leaf+8,'f',1.0)):
            data=bytearray(base);struct.pack_into('<'+fmt,data,offset,value);cases.append(bytes(data))
        for data in cases:
            with self.assertRaises(lr.PackageError):t.parse_payload(data)
            self.assertFalse(self.native_valid(data))
    def test_disconnected_cycle_rejected(self):
        # Root is leaf; two nodes form a disconnected cycle. Parent count alone
        # cannot validate a general graph, traversal must reject it too.
        nodes=(t.TreeNode(-1,-1,-1,0,0.2),t.TreeNode(2,3,0,1,0.2),
            t.TreeNode(1,4,0,1,0.2),t.TreeNode(-1,-1,-1,0,.2),t.TreeNode(-1,-1,-1,0,.2))
        model=replace(self.models['A'],nodes=nodes)
        with self.assertRaises(lr.PackageError):model.payload()
        data=t.HEADER.pack(t.PAYLOAD_MAGIC,1,3,1,8,model.schema,b'cycle'+b'\0'*11,.5,len(nodes))
        data+=b''.join(t.NODE.pack(n.left,n.right,n.feature,0,n.split,n.probability) for n in nodes)
        self.assertFalse(self.native_valid(data))
    def test_duplicate_parent_rejected(self):
        m=self.models['A'];ns=list(m.nodes);ns[0]=replace(ns[0],right=ns[0].left)
        with self.assertRaises(lr.PackageError):replace(m,nodes=tuple(ns)).payload()
    def test_threshold_strict(self):
        m=replace(self.models['A'],threshold=.5,nodes=(t.TreeNode(-1,-1,-1,0,.5),))
        self.assertEqual(t.infer(m,[0]*8),(.5,0))
    def test_contract_semantics(self):
        value=json.loads((ROOT/'artifacts/dt/feature_contract.json').read_text())
        self.assertEqual(t.contract_hash(value),self.models['A'].schema)
        value['branch_semantics']='less_than'
        with self.assertRaises(lr.PackageError):t.contract_hash(value)
    def test_frozen_LR_A_B_bytes_unchanged(self):
        for phase in ('A','B'):
            self.assertEqual((ROOT/'references/frozen_development'/('release-'+phase+'.sids')).read_bytes(),
                (ROOT/'artifacts/lr'/('release-'+phase+'.sids')).read_bytes())
    def test_LR_compatible_golden_decisions(self):
        for row in map(json.loads,(ROOT/'artifacts/lr/golden.jsonl').read_text().splitlines()):
            self.assertEqual(row['expected']['B']['label'],row['expected']['compatible_B']['label'])
            self.assertEqual(row['expected']['B'],row['expected']['C'])
    def test_real_engine_signed_updates_reboot(self):
        with tempfile.TemporaryDirectory() as tmpname:
            tmp=Path(tmpname);shutil.copyfile(ROOT/'artifacts/dt/headers/A.h',tmp/'model_contract.h')
            core=ROOT/'firmware/components/ids_core'
            exe=tmp/'dt-native'
            subprocess.run(['g++','-std=c++17','-O2','-Wall','-Wextra','-Wpedantic','-Werror','-ffp-contract=off',
                '-I'+str(core/'include'),'-I'+str(tmp),str(core/'ids_core.cpp'),str(core/'ids_protocol.cpp'),
                str(core/'ids_tree.cpp'),str(ROOT/'firmware/native/main.cpp'),'-lcrypto','-o',str(exe)],check=True)
            def command(name):return 'UPDATE '+(ROOT/'artifacts/dt'/name).read_bytes().hex()
            def inference(row):return 'INFER '+','.join(format(float(np.float32(v)),'.9g') for v in row['raw'])
            commands=[command('bad-signature.sids'),command('bad-contract.sids'),command('release-A.sids')]
            for phase in ('A','B','C'):
                if phase!='A':commands.append(command('release-'+phase+'.sids'))
                commands.extend(inference(row) for row in self.golden)
            commands.append('REBOOT')
            run=subprocess.run([str(exe),'--store',str(tmp/'store')],input='\n'.join(commands)+'\n',text=True,capture_output=True)
            self.assertEqual(run.returncode,75,run.stderr)  # native restart signal
            events=[json.loads(line) for line in run.stdout.splitlines()]
            negatives=[e for e in events if e['event']=='update' and not e['accepted']]
            self.assertEqual([e['reason'] for e in negatives],['signature','feature_contract','replay_or_downgrade'])
            updates=[e for e in events if e['event']=='update' and e['accepted']]
            self.assertEqual([e['version'] for e in updates],[2,3])
            inferences=[e for e in events if e['event']=='inference']
            self.assertEqual(len(inferences),774)
            for phase,start in (('A',0),('B',258),('C',516)):
                for row,event in zip(self.golden,inferences[start:start+258]):
                    self.assertEqual(event['label'],row['expected'][phase]['label'])
                    self.assertLessEqual(abs(event['probability']-row['expected'][phase]['probability']),5e-9)
            reboot=subprocess.run([str(exe),'--store',str(tmp/'store')],input='STATUS\n'+inference(self.golden[0])+'\n',text=True,capture_output=True,check=True)
            events=[json.loads(line) for line in reboot.stdout.splitlines()]
            self.assertTrue(events[0]['ready']);self.assertEqual(events[0]['version'],3)
            self.assertEqual(events[-1]['label'],self.golden[0]['expected']['C']['label'])

if __name__=='__main__':unittest.main()
