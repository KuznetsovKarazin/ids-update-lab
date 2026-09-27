import csv
import importlib.util
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
import numpy as np
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('diag028',ROOT/'tools/diagnose_ton028.py')
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
audit=m.load('audit_test028',ROOT/'vendor/audit_ton_full.py')

class DiagnosticTests(unittest.TestCase):
    def test_conflicting_labels_are_preserved(self):
        n0=np.array([100,1]);n1=np.array([0,3]);pred=np.array([[0],[1]])
        counts=m.weighted_counts(n0,n1,pred,[0],1/(n0+n1))[0]
        np.testing.assert_allclose(counts,[1,.25,0,.75,0])
        metric=m.metrics_from_mass(counts)
        self.assertAlmostEqual(metric['FPR'],.2);self.assertEqual(metric['recall'],1)
        self.assertEqual(metric['total_mass'],2)
    def test_frequency_cap_is_per_vector(self):
        n0=np.array([200,1]);n1=np.array([0,3]);n=n0+n1
        counts=m.weighted_counts(n0,n1,np.array([[1],[0]]),[0],np.minimum(n,100)/n)[0]
        np.testing.assert_allclose(counts,[1,100,3,0,0]);self.assertEqual(sum(counts[:4]),104)
    def test_weighted_confusions_match_expanded_rows(self):
        n0=np.array([2,1,3]);n1=np.array([1,2,0]);pred=np.array([[0,1],[1,1],[0,0]])
        a=m.weighted_counts(n0,n1,pred,[1,1],np.ones(3))
        expected=np.zeros((2,5))
        for i in range(3):
            for truth,num in ((0,n0[i]),(1,n1[i])):
                for j in range(2):expected[j,truth*2+pred[i,j]]+=num;expected[j,4]+=num*(pred[i,j]!=pred[i,1])
        np.testing.assert_array_equal(a,expected)
    def test_signed_zero_merged_invalid_excluded(self):
        raw,valid,_,_=audit.normalize_raw([['0']*8,['-0']*8,['-1']+['0']*7])
        self.assertEqual(raw[0].tobytes(),raw[1].tobytes());self.assertEqual(valid.tolist(),[True,True,False])
    def test_transaction_rollback_and_file_resume(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);db=m.database(d/'v.db');p=d/'one.csv'
            header=list(audit.FEATURES)+['ts','label','type','proto','conn_state']
            def write(bad=False):
                with p.open('w',newline='') as f:
                    w=csv.writer(f);w.writerow(header)
                    for i in range(3):w.writerow(['0']*8+[('bad' if bad and i==2 else '1556000000'),str(i%2),'normal' if i%2==0 else 'scan','tcp','S0'])
            def source():return {'file':p.name,'path':str(p),'sha256':m.sha(p),'bytes':p.stat().st_size,'mtime_ns':p.stat().st_mtime_ns}
            known=np.frombuffer(b'',dtype='V32')
            write(True)
            with self.assertRaises(ValueError):m.aggregate_file(db,source(),audit,known,1,lambda *a,**k:None)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM vectors').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM files').fetchone()[0],0)
            write();s=source();r=m.aggregate_file(db,s,audit,known,1,lambda *a,**k:None)
            r2=m.aggregate_file(db,s,audit,known,1,lambda *a,**k:None)
            self.assertEqual(r,r2);self.assertEqual(r['rows'],3)
            self.assertEqual(db.execute('SELECT n0,n1 FROM vectors').fetchone(),(2,1))
            self.assertEqual(db.execute("SELECT SUM(n) FROM hourly WHERE stage='valid_raw_contract'").fetchone()[0],3)
            db.close()
    def test_top_metadata_keeps_joint_class_type_and_absent_history(self):
        with tempfile.TemporaryDirectory() as d:
            d=Path(d);p=d/'one.csv'
            with p.open('w',newline='') as f:
                w=csv.writer(f);w.writerow(list(audit.FEATURES)+['ts','label','type','proto','conn_state'])
                w.writerow(['0']*8+['1556000000','0','normal','tcp','RSTOS0'])
                w.writerow(['0']*8+['1556000000','1','scanning','icmp','OTH'])
            s={'file':p.name,'path':str(p)}
            result=m.top_metadata([s],{b'\0'*32},audit,1,lambda *a,**k:None,d/'checkpoint.json')
            v=next(iter(result.values()));self.assertEqual(v['rows'],2)
            self.assertEqual(v['marginal_counts']['history'],{'<column_absent>':2})
            self.assertEqual(v['marginal_counts']['label'],{'0':1,'1':1})
            self.assertEqual(len(v['joint_counts']),2)

if __name__=='__main__':unittest.main(verbosity=2)
