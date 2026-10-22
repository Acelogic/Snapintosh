#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Independent exact queued-blit wire/CPU-observation oracle; no GPU execution.
Failure inventory: docs/ADRENO-BLIT-ENCODING-E2E-20261019.md.
"""
import argparse,copy,importlib.util,json,struct,sys
from pathlib import Path
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('mps_wire',ROOT/'tools/decode-mps-encoding.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
require=m.require;sha=m.sha;enum=m.enum;field=m.field
CASES={'buffer-offsets','texture-buffer-rows','buffer-texture-rows','texture-texture-rows','whole-texture','rebound-buffer-chain','fill-copy-buffer','copy-fill-buffer','mps-copy-fill-render'}
CONTROLS={'bad-buffer-range','overflow-offset','unaligned-offset','overlap','short-row-pitch','bad-texture-origin','format-mismatch','unsupported-option','unsupported-level','unsupported-slice','missing-copy-abi','mipmap-refusal'}

def check(c,directory,overrides=None):
    overrides=overrides or {}
    def read(row,key='file',hashkey='sha256'):
        return overrides[row[key]] if row[key] in overrides else m.filebytes(directory,row,key,hashkey)
    require(c['status']=='QUEUED_BLIT_ENCODING_CAPTURE_ONLY' and c['gpu_submission'] is False,'blit capture boundary/status')
    require({x['name'] for x in c['cases']}==CASES and len(c['cases'])==len(CASES),'positive case matrix')
    require(c['intercepted_commits']==len(CASES)==len(c['streams']),'actual native commit count')
    require(not c['completion_handlers'],'CPU completion copy replay remains')
    output=[]
    for case in c['cases']:
        name=case['name'];work=case['work'];copies=[r for r in c['copies'] if r['case']==name]
        require(work['omitted']==0 and not work['encoding_failed'] and not work['trace_incomplete'],'omitted/failed/incomplete blit work')
        require(all(e['ended'] for e in work['encoders'].values()),'unbalanced encoder')
        require(case['released_external_owners_before_commit'],'resource lifetime case not exercised')
        snapshots={r['id']:bytearray(read(r,'initial_file','initial_sha256')) for r in case['memory']}
        require(all(len(snapshots[r['id']])==r['bytes'] for r in case['memory']),'full allocation snapshot extent')
        checks=[r for r in c['memory_checks'] if r['case']==name]
        require(checks and checks[-1]['phase']=='intercepted-native-commit','missing post-encoding CPU observation')
        initial=[r['initial_sha256'] for r in case['memory']]
        require(all(r['hashes']==initial[:len(r['hashes'])] for r in checks),'CPU memory changed during encoding')
        if case['copy_only_model']:
            if name=='fill-copy-buffer':
                source=copies[0]['expected_spans'][0]['source'];snapshots[source][16:24]=b'\x5a'*8
            for call in copies:
                require('exception' not in call,'positive copy raised')
                for span in call['expected_spans']:
                    source=snapshots[span['source']];destination=snapshots[span['destination']]
                    so,do,n=span['source_offset'],span['destination_offset'],span['bytes']
                    require(0<n<=len(source)-so and n<=len(destination)-do,'reference API span extent')
                    destination[do:do+n]=source[so:so+n]
            if name=='copy-fill-buffer':
                destination=copies[0]['expected_spans'][0]['destination'];snapshots[destination][40:48]=b'\x5a'*8
            for r in case['memory']:
                require(bytes(snapshots[r['id']])==read(r,'expected_file','expected_sha256'),'independent API expected full allocation differs')
        passes=[r for r in c['passes'] if r['case']==name];packages=[r for r in c['packages'] if r['case']==name]
        require([p['copy_ordinal'] for p in passes if 'copy_ordinal' in p]==[r['ordinal'] for r in copies],'every API copy has one ordered finished pass')
        decoded=[];operations=[];copy_count=0
        for package in packages:
            pp=[p for p in passes if p['package']==package['package']];resources={}
            for p in pp:
                for r in p['resources']:
                    if r['id'] in resources:resources[r['id']]['usage']|=r['usage']
                    else:resources[r['id']]=dict(r)
            raw=read(package);d=m.decode_package(raw,resources);base=0;data=bytearray()
            for p in pp:
                pw=read(p,'words_file','words_sha256');pd=read(p,'data_file','data_sha256')
                require(d['package'][base:base+len(pw)]==pw,'pass/package words differ')
                data.extend(b'\0'*(m.align(len(data))-len(data)));data.extend(pd)
                pkts=[x for x in d['packets'] if base<=4*x['word']<base+len(pw)]
                if 'copy_ordinal' in p:
                    call=next(r for r in copies if r['ordinal']==p['copy_ordinal']);cp=[x for x in pkts if x.get('opcode')==enum('CP_MEMCPY')]
                    require(len(cp)==len(call['expected_spans']) and cp,'copy row packet count')
                    uses={r['id']:r['usage'] for r in p['resources']}
                    for packet,want in zip(cp,call['expected_spans']):
                        require(len(packet['payload'])==5,'CP_MEMCPY shape')
                        src=m.read_reloc(d,4*(packet['word']+2),1,1);dst=m.read_reloc(d,4*(packet['word']+4),1,2)
                        actual={'source':src['resource_id'],'source_offset':src['offset'],'destination':dst['resource_id'],
                                'destination_offset':dst['offset'],'bytes':4*packet['payload'][0]}
                        require(actual==want,'copy row identity/offset/byte extent')
                        require(src['length']==dst['length']==actual['bytes'] and src['align']==dst['align']==2,'exact dword resource span')
                        require(uses.get(src['resource_id'],0)&1 and uses.get(dst['resource_id'],0)&2,'copy source READ/destination WRITE ownership')
                        if src['resource_id']==dst['resource_id']:
                            require(src['offset']+src['length']<=dst['offset'] or dst['offset']+dst['length']<=src['offset'],'overlapping copy')
                        operations.append({'kind':'CP_MEMCPY','copy_ordinal':call['ordinal'],'package':package['file'],'packet_word':packet['word'],**actual});copy_count+=1
                    def semantic(packets):
                        return [('event',field(x['payload'][0],'PKT_CP_EVENT_WRITE7_0','EVENT')) if x.get('opcode')==enum('CP_EVENT_WRITE7') else ('packet',x.get('opcode')) for x in packets]
                    before=semantic([x for x in pkts if x['word']<cp[0]['word']]);after=semantic([x for x in pkts if x['word']>cp[-1]['word']])
                    events=lambda names:[('event',enum(n)) for n in names]
                    packets=lambda names:[('packet',enum(n)) for n in names]
                    require(before==packets(['CP_THREAD_CONTROL'])+events(['CCU_CLEAN_COLOR','CCU_CLEAN_DEPTH','CACHE_CLEAN','DUMMY_EVENT','SUBPASS_FENCE','DUMMY_EVENT'])+
                        packets(['CP_WAIT_FOR_IDLE','CP_WAIT_MEM_WRITES']),'copy producer visibility boundary')
                    require(after==packets(['CP_WAIT_MEM_WRITES'])+events(['CCU_CLEAN_COLOR','CCU_CLEAN_DEPTH','CCU_INVALIDATE_COLOR','CCU_INVALIDATE_DEPTH','CACHE_INVALIDATE7','DUMMY_EVENT','SUBPASS_FENCE','DUMMY_EVENT'])+
                        packets(['CP_WAIT_FOR_IDLE','CP_CCHE_INVALIDATE','CP_WAIT_FOR_IDLE']),'copy consumer visibility boundary')
                elif 'dispatch' in p:
                    dispatch=next(r for r in c['dispatches'] if r['ordinal']==p['dispatch'])
                    program=next(r['program'] for r in c['pipelines'] if r['entry']==dispatch['pipeline'])
                    m.decode_compute(d,p,dispatch,program,base,base+len(pw));operations.append({'kind':'CP_EXEC_CS','pipeline':dispatch['pipeline']})
                else:operations.append({'kind':p['kind']})
                base+=len(pw)
            data.extend(b'\0'*(m.align(len(data))-len(data)))
            require(base==4*d['header']['ib_dwords'] and d['package'][d['data_offset']:]==data,'unaccounted pass data/words')
            decoded.append({k:v for k,v in d.items() if k!='package'}|{'file':package['file'],'sha256':sha(raw)})
        streamrow=next(r for r in c['streams'] if r['case']==name);stream=read(streamrow);at=0;ib=0;fills=0;layout=[];fill_commands=[]
        while at<len(stream):
            require(at+8<=len(stream),'short native header');typ,size=struct.unpack_from('<II',stream,at)
            require(size>=8 and at+size<=len(stream),'native command size');raw=stream[at:at+size]
            if typ==0x1002:
                require(ib<len(packages) and raw==read(packages[ib]) and packages[ib]['fills_before']==fills,'native copy/fill package ordering')
                ib+=1;layout.append('IB')
            elif typ==0x1001:
                require(size==32,'fill shape');rid,value,offset,bytes_=struct.unpack_from('<IIQQ',raw,8)
                fill_commands.append({'resource':rid,'value':value,'offset':offset,'bytes':bytes_});fills+=32;layout.append('FILL32')
            else:require(typ==0x1000 and size==8 and at+size==len(stream),'final native fence');layout.append('FENCE')
            at+=size
        require(ib==len(packages),'package not present in native stream')
        if name in ('fill-copy-buffer','copy-fill-buffer'):
            expected_layout=['FILL32','IB','FENCE'] if name=='fill-copy-buffer' else ['IB','FILL32','FENCE']
            require(layout==expected_layout and len(fill_commands)==1,'actual fill/copy ordering')
            want={'resource':copies[0]['expected_spans'][0]['source' if name=='fill-copy-buffer' else 'destination'],
                  'value':0x5a5a5a5a,'offset':16 if name=='fill-copy-buffer' else 40,'bytes':8}
            require(fill_commands[0]==want,'API fill payload differs')
        if name=='mps-copy-fill-render':
            require([x.get('pipeline') for x in operations[:2]]==list(m.ENTRY) and operations[2]['kind']=='CP_MEMCPY' and
                    operations[-1]['kind']=='AdrenoRenderPass' and layout==['IB','FILL32','IB','FENCE'],'compute/copy/fill/render ordering')
        output.append({'name':name,'packets':decoded,'operations':operations,'copy_rows':copy_count,'native_stream_layout':layout,'fill_commands':fill_commands,'copy_only_model':case['copy_only_model']})
    require({r['name'] for r in c['controls']}==CONTROLS,'negative API case matrix')
    for row in c['controls']:
        require(row['refused'] and row['partial_passes']==0 and row['work']['omitted']==1 and row['work']['encoded']==0,'unsupported request silently omitted or partially appended')
        require(all(e['ended'] for e in row['work']['encoders'].values()),'refused encoder cleanup')
    return output

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--capture',type=Path,required=True);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--reference-capture',type=Path,required=True);args=ap.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    c=json.loads(args.capture.read_text());baseline=args.capture.parent/'mps-baseline-capture.json';reference=json.loads(args.reference_capture.read_text())
    m.check_capture(json.loads(baseline.read_text()),baseline.parent,reference=reference)
    result=check(c,args.capture.parent)
    report={'status':'PASS_QUEUED_BLIT_ENCODING','boundary':'Host queued encoding and unchanged CPU bytes only; expected byte fixtures are API reference data, not GPU execution.',
            'capture_sha256':sha(args.capture.read_bytes()),'mps_baseline_sha256':sha(baseline.read_bytes()),'cases':result,'api_negative_controls':c['controls'],'mutation_negative_controls':[]}
    mutations=[]
    bad=copy.deepcopy(c);bad['passes'].pop(0);mutations.append(('missing-copy-pass',bad,None))
    bad=copy.deepcopy(c);bad['copies'][0]['expected_spans'][0]['source_offset']+=4;mutations.append(('wrong-copy-source',bad,None))
    bad=copy.deepcopy(c);bad['completion_handlers'].append({'case':'buffer-offsets'});mutations.append(('cpu-completion-copy',bad,None))
    bad=copy.deepcopy(c);bad['memory_checks'][0]['hashes'][0]='0'*64;mutations.append(('encode-time-cpu-write',bad,None))
    bad=copy.deepcopy(c);bad['controls'][-1]['work']['omitted']=0;mutations.append(('silent-mipmap-noop',bad,None))
    first=c['packages'][0];raw=bytearray(m.filebytes(args.capture.parent,first));d=result[0]['packets'][0]
    cp=next(p for p in d['packets'] if p.get('opcode')==enum('CP_MEMCPY'));struct.pack_into('<I',raw,48+4*(cp['word']+1),0xffffffff)
    firstpass=c['passes'][0];pw=bytearray(m.filebytes(args.capture.parent,firstpass,'words_file','words_sha256'));struct.pack_into('<I',pw,4*(cp['word']+1),0xffffffff)
    mutations.append(('copy-count-exceeds-span',c,{first['file']:bytes(raw),firstpass['words_file']:bytes(pw)}))
    def changed_word(name,word,value):
        raw=bytearray(m.filebytes(args.capture.parent,first))
        pw=bytearray(m.filebytes(args.capture.parent,firstpass,'words_file','words_sha256'))
        struct.pack_into('<I',raw,48+4*word,value);struct.pack_into('<I',pw,4*word,value)
        mutations.append((name,c,{first['file']:bytes(raw),firstpass['words_file']:bytes(pw)}))
    clean=next(p for p in d['packets'] if p.get('opcode')==enum('CP_EVENT_WRITE7') and
               field(p['payload'][0],'PKT_CP_EVENT_WRITE7_0','EVENT')==enum('CACHE_CLEAN'))
    mask=m.DEFS['A8XX_PKT_CP_EVENT_WRITE7_0__EVENT__MASK'];shift=m.DEFS['A8XX_PKT_CP_EVENT_WRITE7_0__EVENT__SHIFT']
    changed_word('lost-producer-visibility',clean['word']+1,(clean['payload'][0]&~mask)|(enum('DUMMY_EVENT')<<shift))
    opcode=enum('CP_NOP');count=5
    header=0x70000000|(opcode<<16)|((1^(opcode.bit_count()&1))<<23)|count|((1^(count.bit_count()&1))<<15)
    changed_word('dropped-copy-row',cp['word'],header)
    raw=bytearray(m.filebytes(args.capture.parent,first));dst=m.read_reloc(d,4*(cp['word']+4),1,2)
    reloc_at=48+d['data_offset']+d['header']['data_bytes']+32*dst['index'];raw[reloc_at+9]=1
    mutations.append(('lost-destination-write',c,{first['file']:bytes(raw)}))
    for name,bad,overrides in mutations:
        folder=args.out/'negative'/name;folder.mkdir(parents=True);(folder/'capture.json').write_text(json.dumps(bad,indent=2)+'\n')
        for f,b in (overrides or {}).items():(folder/f).write_bytes(b)
        try:check(bad,args.capture.parent,overrides)
        except ValueError as error:
            row={'name':name,'refused':True,'reason':str(error),'overrides':{k:sha(v) for k,v in (overrides or {}).items()}}
            (folder/'result.json').write_text(json.dumps(row,indent=2)+'\n');report['mutation_negative_controls'].append(row)
        else:raise ValueError('artifact corruption passed '+name)
    (args.out/'decoded.json').write_text(json.dumps(report,indent=2)+'\n')
    print(report['status']+f": {len(result)} cases; {sum(r['copy_rows'] for r in result)} copy rows; {len(c['controls'])} API controls; no GPU execution")

if __name__=='__main__':main()
