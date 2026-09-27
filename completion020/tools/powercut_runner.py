#!/usr/bin/env python3
"""Guarded physical supply-cut series: external load switch is REQUIRED.
A user wiring declaration alone is insufficient: explicit OFF/ON probe precedes
updates. Results concern host-scheduled outages, not uniform random flash phases.
"""
from __future__ import annotations
import argparse,hashlib,json,random,time,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'host'))
from ids_update_lab import package
class Link:
    def __init__(self,port,out,kind):
        import serial
        self.s=serial.Serial(port=None,baudrate=115200,timeout=.001 if kind=='controller' else .1,write_timeout=3);self.s.dtr=False;self.s.rts=False;self.s.port=port;self.s.open();self.out=out;self.kind=kind;self.buf=b''
    def record(self,**x):
        x.update(utc_ns=time.time_ns(),monotonic_ns=time.monotonic_ns(),link=self.kind);self.out.write(json.dumps(x)+'\n');self.out.flush()
    def send(self,line):
        self.record(direction='tx',line=line);self.s.write(line.encode()+b'\n');self.s.flush()
    def read(self,seconds):
        end=time.monotonic()+seconds;events=[]
        while time.monotonic()<end:
            try:data=self.s.read(max(1,self.s.in_waiting))
            except Exception as e:self.record(direction='serial_error',error=str(e));break
            if not data:continue
            self.record(direction='rx_bytes',hex=data.hex());self.buf+=data
            while b'\n' in self.buf:
                line,self.buf=self.buf.split(b'\n',1)
                try:event=json.loads(line.decode());events.append(event)
                except (UnicodeError,ValueError):continue
        return events
    def expect(self,line,event,seconds=2):
        self.send(line);responses=self.read(seconds);match=[r for r in responses if r.get('event')==event]
        if not match:raise ValueError('No '+event+' from '+self.kind)
        return match[-1]
    def close(self):self.s.close()

def validate_wiring(w):
    if w.get('protocol')!='ids-power-wiring-v1':raise ValueError('Wrong wiring declaration format')
    for name in ('external_switch_accepts_3v3_enable','load_voltage_5V','active_high_enable','common_ground','no_USB_VBUS_bypass','no_other_power_path','esp_not_powered_by_gpio','data_path_available_when_powered'):
        if w.get(name) is not True:raise ValueError('Missing verified wiring condition: '+name)
    if w.get('controller_pin')!=15 or len(w.get('switch_model',''))<3 or 'FILL' in w['switch_model']:raise ValueError('Specify actual load-switch model/pin')
    if len(w.get('verification_notes',''))<20:raise ValueError('Describe checks for wiring and power bypass')

def check_status(s,expected_schema):
    if s.get('ready')is not True or s.get('runtime_abi')!=2 or s.get('schema')!=expected_schema or s.get('chip')!='esp32s3' or s.get('storage_layout')!=2:raise ValueError('Expected ready ABI2 ESP32 with new storage layout2')
    if s.get('policy')!='bundle':raise ValueError('Expected bundle policy')
    return s

def run(a):
    if a.mcu_port.lower()==a.controller_port.lower():raise ValueError('MCU and controller need distinct ports')
    validate_wiring(json.loads(a.wiring.read_text(encoding='utf-8-sig')))
    manifest=json.loads(a.series.read_text());items=manifest['trials']
    if len(items)!=200:raise ValueError('Physical series is frozen to200 trials')
    protocol={'trials':200,'seed':24092026,'delay_ms_inclusive':[0,80],'off_ms':2000,'cut_schedule':'controller delay after CUT acknowledgement request; MCU UPDATE sent immediately after accepted scheduling acknowledgement','power_loss_phase':'host_scheduled; actual flash instruction phase unknown','success_rule':'ready old_or_new_signed_pipeline; mixed/unready/unexpected=fail','wired_manifest_sha256':hashlib.sha256(a.wiring.read_bytes()).hexdigest()}
    public=package.load_public(ROOT/'references/artifacts019/public.pem');contract=json.loads((ROOT/'references/artifacts019/feature_contract.json').read_text());schema=package.contract_hash(contract);checked=[]
    for item in items:
        p=(a.series.parent/item['package']).resolve()
        if a.series.parent.resolve() not in p.parents:raise ValueError('Package path escapes series directory')
        blob=p.read_bytes();model=package.verify(blob,public,schema,8,2)
        if model.version!=item['version'] or hashlib.sha256(model.payload()).hexdigest()!=item['model_sha256']:raise ValueError('Series model identity mismatch')
        checked.append((item,blob,model))
    if [x[0]['version'] for x in checked]!=list(range(10001,10201)):raise ValueError('Unexpected physical-series version allocation')
    a.output.mkdir(parents=True,exist_ok=False);(a.output/'protocol.json').write_text(json.dumps(protocol,indent=2)+'\n');log=(a.output/'transcript.jsonl').open('x');mcu=ctrl=None;summary={'status':'failed','measurement_origin':'not_measured','trials':[],'physical_power_loss_tested':False,'attempted_trials':0}
    try:
        ctrl=Link(a.controller_port,log,'controller');identity=ctrl.expect('ID','controller_id')
        if identity.get('protocol')!='ids-power-v1' or identity.get('pin')!=15:raise ValueError('Wrong physical controller')
        ctrl.expect('ARM PHYSICAL','armed');ctrl.expect('ON','power_on');time.sleep(2)
        mcu=Link(a.mcu_port,log,'MCU');time.sleep(1);mcu.read(.2);initial=check_status(mcu.expect('STATUS','status'),schema.hex())
        if initial['version']>=10001:raise ValueError('Physical trial series already started; do not blindly rerun')
        ctrl.expect('OFF','power_off');time.sleep(1)
        # Flush responses produced before OFF; any response to fresh STATUS invalidates supply isolation.
        mcu.read(.2)
        bypass=False
        for _ in range(3):
            try:mcu.send('STATUS');rx=mcu.read(.2)
            except Exception:rx=[]
            bypass=bypass or any(x.get('event')=='status' for x in rx)
        mcu.close();mcu=None
        if bypass:raise ValueError('MCU replied while external power disabled: power bypass or wrong wiring')
        ctrl.expect('ON','power_on');time.sleep(2);mcu=Link(a.mcu_port,log,'MCU');time.sleep(.4);old=check_status(mcu.expect('STATUS','status'),schema.hex());summary['off_probe_no_status_response']=True
        if (old['version'],old['bundle_sha256'])!=(initial['version'],initial['bundle_sha256']):raise ValueError('Initial OFF/ON changed pipeline')
        initial_models=[package.verify((ROOT/'artifacts/lr'/('release-'+x+'.sids')).read_bytes(),public,schema,8,2) for x in ('A','B','C')]
        matches=[x for x in initial_models if x.version==old['version'] and hashlib.sha256(x.payload()).hexdigest()==old['bundle_sha256']]
        if len(matches)!=1:raise ValueError('Initial pipeline not one of frozen completion020 LR releases')
        current_model=matches[0]
        raw=json.loads((ROOT/'references/artifacts019/golden.jsonl').read_text().splitlines()[0])['raw']
        summary['measurement_origin']='actual_mcu';rng=random.Random(protocol['seed'])
        for index,(item,blob,candidate_model) in enumerate(checked):
            delay=rng.randint(0,80);intent={'trial':index+1,'delay_ms':delay,'off_ms':2000,'previous_version':old['version'],'previous_sha256':old['bundle_sha256'],'candidate':item}
            (a.output/f'intent_{index+1:03d}.json').write_text(json.dumps(intent,indent=2)+'\n')
            summary['attempted_trials']=index+1;summary['current_trial']=intent
            # Do not use expect(), which reads for seconds and would consume the whole delay.
            ctrl.send(f'CUT {delay} 2000');deadline=time.monotonic()+2;scheduled=False;scheduled_events=[]
            while time.monotonic()<deadline:
                events=ctrl.read(.002);scheduled_events.extend(events)
                if any(x.get('event')=='cut_scheduled' for x in events):scheduled=True;break
                if any(x.get('event')=='error' for x in events):raise ValueError('Controller rejected CUT')
            if not scheduled:raise ValueError('No CUT scheduling acknowledgement')
            update_send_error=None
            try:mcu.send('UPDATE '+blob.hex())
            except Exception as e:update_send_error=str(e)
            responses=mcu.read(.15);mcu.close();mcu=None
            cev=scheduled_events+ctrl.read(3)
            if not all(any(x.get('event')==name for x in cev) for name in ('power_off','power_on')):raise ValueError('Controller did not confirm OFF and restoration')
            time.sleep(1);mcu=Link(a.mcu_port,log,'MCU');time.sleep(.3);now=check_status(mcu.expect('STATUS','status'),schema.hex())
            pair=(now['version'],now['bundle_sha256']);oldpair=(old['version'],old['bundle_sha256']);newpair=(item['version'],item['model_sha256'])
            state='previous' if pair==oldpair else 'candidate' if pair==newpair else 'unexpected'
            if state=='unexpected':raise ValueError('Unexpected recovered signed model')
            selected_model=current_model if state=='previous' else candidate_model
            expected_p,expected_label=package.infer(selected_model,raw)
            inference=mcu.expect('INFER '+','.join(format(v,'.9g') for v in raw),'inference')
            if inference.get('version')!=selected_model.version or inference.get('bundle_sha256')!=now['bundle_sha256'] or inference.get('label')!=expected_label or abs(float(inference.get('probability',-1))-expected_p)>2e-6:raise ValueError('Recovered pipeline failed numeric control')
            record=dict(intent,recovered_state=state,numeric_control=inference,update_send_error=update_send_error,pre_reopen_mcu_events=responses,controller_events=cev,status=now,actual_flash_phase_verified=False,off_ack_received_before_update_send=any(x.get('event')=='power_off' for x in scheduled_events))
            summary['trials'].append(record);summary['physical_power_loss_tested']=True
            (a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
            if state=='unexpected':raise ValueError('Unexpected recovered signed model')
            old=now;current_model=selected_model;print(f'powercut {index+1}/200: {state}',flush=True)
        summary.update(status='complete',completed_trials=len(summary['trials']),final_version=old['version'])
    except Exception as e:summary['error']=str(e);summary['failed_trial']=summary.get('current_trial');raise
    finally:
        # Restoration is explicit and logged; it is NOT automatic replay of an interrupted update.
        if ctrl:
            try:ctrl.expect('ON','power_on')
            except Exception:pass
            ctrl.close()
        if mcu:mcu.close()
        log.close();(a.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
    return summary

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--mcu-port',required=True);p.add_argument('--controller-port',required=True);p.add_argument('--wiring',type=Path,required=True);p.add_argument('--series',type=Path,default=ROOT/'artifacts/powercut/series.json');p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    try:
        result=run(a);print(json.dumps({k:v for k,v in result.items() if k!='trials'}));return 0
    except Exception as e:print('error: '+str(e),file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
