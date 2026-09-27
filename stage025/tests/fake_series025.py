"""Temporary generated fixture ONLY. No hardware measurements are produced here."""
from pathlib import Path
from types import SimpleNamespace
import json


def write_fixture(root,s):
    root=Path(root);kit=root/'simulated-kit';run=root/'simulated-series';kit.mkdir();run.mkdir()
    s.save(kit/'KIT_MANIFEST.json',{'fixture_simulated_NOT_MCU':True});s.save(kit/'protocol.json',{'fixture_simulated_NOT_MCU':True})
    digest=s.sha(kit/'KIT_MANIFEST.json');pins={'fixture':'simulation-only'};board='esp32s3-a0f262ebb558';contexts={}
    def lines(path,rows):path.write_text(''.join(json.dumps(row)+'\n' for row in rows),encoding='utf-8')
    def proof(directory,name):s.save(directory/name,{'sha256':{p.relative_to(directory).as_posix():s.sha(p) for p in sorted(directory.rglob('*')) if p.is_file() and p.name!=name}})
    for configuration in s.CONFIGURATIONS:
        family,policy=configuration.split('_',1);abi=2 if family=='lr' else 3;transform='log1p' if family=='lr' else 'none'
        golden=[{'id':str(i),'raw':[float(i)]*8,'expected':{k:{'probability':.1*version,'label':0} for version,k in enumerate('ABC',1)}} for i in range(16)]
        c={'root':kit,'configuration':configuration,'erase_policy':policy,'model_family':family,'envelopes':{k:bytes(448) for k in 'ABC'},'models':{k:SimpleNamespace(version=version,release='fixture-'+k) for version,k in enumerate('ABC',1)},'policy':'bundle','policy_name':'bundle','schema':'0'*64,'experiment':{'runtime_abi':abi,'pretransform':transform},'digests':{k:str(i)*64 for i,k in enumerate('ABC',1)},'build':{'images':{'A':{'expected_build':'fixture-build-NOT-MCU'}}},'golden':golden,'kit_manifest_sha256':digest}
        contexts[configuration]=c
    def status(c,key,event='status'):
        return {'fixture_simulated_NOT_MCU':True,'event':event,'ready':True,'reason':'ok','version':c['models'][key].version,'release':'fixture-'+key,'policy':'bundle','schema':c['schema'],'feature_count':8,'bundle_sha256':c['digests'][key],'chip':'esp32s3','build':'fixture-build-NOT-MCU','data_origin':'TON_IoT_development','runtime_abi':c['experiment']['runtime_abi'],'pretransform':c['experiment']['pretransform'],'storage_layout':2,'storage_scheme':'journal_dualrail_v1','timing_schema':3,'crypto_context':'shared_warm','crypto_key_setup_us':0,'crypto_first_verify_us':0,'active_slot':1 if key=='B' else 0,'selector_sequence':{'A':1,'B':2,'C':3}[key],'erase_policy':c['erase_policy'],'model_slot_capacity_bytes':65536,'erase_sector_bytes':4096}
    rows=s.plan('series');completed=[]
    for item in rows:
        c=contexts[item['configuration']];folder=run/item['path'];folder.mkdir();provisioning=folder/'provisioning';provisioning.mkdir();events=[];observations=[];received=[]
        for name,tail in {'identity':['--after','hard_reset','flash_id'],'write_factory':['-b','460800','--after','no_reset','write_flash','@flash_args'],'erase_component_state':['--after','hard_reset','erase_region','0x3b0000','0x22000']}.items():
            (provisioning/(name+'.log')).write_text('SIMULATED TEST FIXTURE, NOT A HARDWARE LOG\nESP32-S3\nMAC: a0:f2:62:eb:b5:58\n',encoding='utf-8')
            s.save(provisioning/(name+'-intent.json'),{'argv':['python','-m','esptool','--chip','esp32s3','--port','COM13',*tail],'fixture_simulated_NOT_MCU':True})
            s.save(provisioning/(name+'-result.json'),{'returncode':0,'log_sha256':s.sha(provisioning/(name+'.log')),'fixture_simulated_NOT_MCU':True})
        initial=status(c,'A');events.append({'event':'verified_status','response':initial});received.append(initial)
        for key in 'ABC':
            if key!='A':
                total=100 if c['erase_policy']=='full_slot' else 10;timing={k:(total-8 if k=='erase' else 1) for k in s.STAGES};timing['total']=total
                counter=s.expected_storage(448,c['erase_policy']);response={'fixture_simulated_NOT_MCU':True,'event':'update','accepted':True,'reason':'ok','ready':True,'version':c['models'][key].version,'policy':'bundle','timing_schema':3,'timing_measured':True,'timing_executed_mask':511,'timing_us':timing,'latency_us':total+1,'erase_policy':c['erase_policy'],'model_slot_capacity_bytes':65536,'erase_sector_bytes':4096,'storage_metrics_schema':1,'storage_metrics_kind':'successful_flash_request_bytes',**counter};after=status(c,key)
                events.append({'event':'cost','model_key':key,'transition':'A_to_B_clean' if key=='B' else 'B_to_C_reused','configuration':c['configuration'],'erase_policy':c['erase_policy'],'timing_us':timing,'latency_us':total+1,'envelope_bytes':448,'tx_wire_bytes':904,'response':response,'status_response':after,**counter});received.extend([response,after])
            for row in c['golden']:
                response={'event':'inference','version':c['models'][key].version,'policy':'bundle','bundle_sha256':c['digests'][key],'runtime_abi':c['experiment']['runtime_abi'],'pretransform':c['experiment']['pretransform'],'data_origin':'TON_IoT_development',**row['expected'][key]}
                observations.append({'model_key':key,'record_id':row['id'],'raw':row['raw'],'expected':row['expected'][key],'response':response,'label_match':True,'probability_abs_error':0.});received.append(response)
        boot=status(c,'C','boot');after=status(c,'C');events.append({'event':'reboot_verified','boot_response':boot,'response':after});received.extend([boot,after]);observations.append(observations[-16]);received.append(observations[-1]['response'])
        summary={'fixture_simulated_NOT_MCU':True,'stage':'025','command':'series','status':'complete','measurement_origin':'actual_mcu','trial':item,'configuration':c['configuration'],'board_id':board,'kit_manifest_sha256':digest,'erase_policy':c['erase_policy'],'inferred_records':49,'label_mismatches':0,'accepted_updates':2,'verified_reboots':1,'faults_verified':0,'negative_controls_passed':0,'physical_power_loss_tested':False,'energy_measured':False,'heldout_detection_quality_measured':False,'max_probability_abs_error':0.}
        s.save(folder/'summary.json',summary);lines(folder/'events.jsonl',events);lines(folder/'observations.jsonl',observations);lines(folder/'transcript.jsonl',[{'direction':'rx','line':json.dumps(row)} for row in received]);proof(folder,'evidence_manifest.json');completed.append({'trial':item,'summary':summary})
    pilot_manifest={'stage':'025','command':'pilot','board_id':board,'kit_manifest_sha256':digest,'trial_plan':s.plan('pilot')};pilot_summary={'status':'complete','measurement_origin':'actual_mcu','completed_trials':28,'faults_verified':24,'negative_controls_passed':32,'label_mismatches':0}
    s.save(run/'pilot_manifest.json',pilot_manifest);s.save(run/'pilot_summary.json',pilot_summary)
    manifest={'stage':'025','command':'series','created_before_hardware':True,'kit_manifest_sha256':digest,'protocol_sha256':s.sha(kit/'protocol.json'),'source_pins':pins,'trial_plan':rows,'board_id':board,'port':'COM13','pilot_gate':{'manifest_sha256':s.sha(run/'pilot_manifest.json'),'summary_sha256':s.sha(run/'pilot_summary.json')}}
    summary={'stage':'025','command':'series','status':'complete','measurement_origin':'actual_mcu','board_id':board,'kit_manifest_sha256':digest,'planned_trials':120,'completed_trials':120,'attempted_trials':120,'inferred_records':5880,'label_mismatches':0,'accepted_updates':240,'verified_reboots':120,'faults_verified':0,'negative_controls_passed':0,'max_probability_abs_error':0.}
    s.save(run/'campaign_manifest.json',manifest);s.save(run/'summary.json',summary);lines(run/'completed_trials.jsonl',completed);(run/'preflight').mkdir();s.save(run/'preflight/status.json',status(contexts[s.CONFIGURATIONS[0]],'A'));proof(run,'run_evidence_manifest.json')
    return kit,run,contexts,pins,proof
