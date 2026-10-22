#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Decode actual host-MPS -> Adreno command bytes; never submit GPU work.

Failure inventory: docs/ADRENO-MPS-ENCODING-E2E-20261019.md.
This independent wire reader follows adreno-submit.h and generated XML fields.
It does not call the builder or synthesize a substitute command stream.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import struct

ROOT=Path(__file__).resolve().parents[1]
REGS=ROOT/'gpu/adreno-kext/include/AdrenoA8xxRegs.h'
DEFS={k:int(v,0) for k,v in re.findall(r'^#define (A8XX_\w+) (0x[0-9a-fA-F]+|[0-9]+)u?\s*$',REGS.read_text(),re.M)}
ENTRY=('sum_rgba_columns','sum_rgba_rows')

def require(ok, why):
    if not ok: raise ValueError(why)

def sha(b): return hashlib.sha256(b).hexdigest()
def align(n): return (n+63)&~63
def enum(n): return DEFS['A8XX_E_'+n]
def reg(n): return DEFS['A8XX_REG_'+n]
def field(value, prefix, name):
    key='A8XX_'+prefix+'__'+name
    return (value&DEFS[key+'__MASK'])>>DEFS[key+'__SHIFT']
def words(b):
    require(len(b)%4==0,'unaligned word bytes')
    return list(struct.unpack('<'+'I'*(len(b)//4),b))
def filebytes(directory,row,key='file',hashkey='sha256'):
    p=directory/row[key]
    require(p.resolve().is_relative_to(directory.resolve()),'artifact path escaped capture')
    b=p.read_bytes();require(sha(b)==row[hashkey],'artifact hash differs: '+str(p))
    return b

def packets(raw):
    w=words(raw);result=[];i=0
    while i<len(w):
        h=w[i];kind=h>>28
        if kind==4:
            count=h&127;address=(h>>8)&0x3ffff
            require(count>0 and ((h>>7)&1)==(1^(count.bit_count()&1)) and
                    ((h>>27)&1)==(1^(address.bit_count()&1)),'PKT4 parity/count')
            row={'word':i,'type':4,'register':address}
        else:
            require(kind==7 and not h&0x0f000000,'unsupported packet header')
            count=h&0x3fff;opcode=(h>>16)&127
            require(((h>>15)&1)==(1^(count.bit_count()&1)) and
                    ((h>>23)&1)==(1^(opcode.bit_count()&1)),'PKT7 parity')
            row={'word':i,'type':7,'opcode':opcode}
        require(i+1+count<=len(w),'packet extends past IB')
        row['payload']=w[i+1:i+1+count];row['dwords']=count+1
        result.append(row);i+=count+1
    return result

def registers(pkts):
    result={}
    for p in pkts:
        payload=p['payload']
        if p['type']==4:
            for i,v in enumerate(payload): result[p['register']+i]=(v,4*(p['word']+1+i))
        elif p['opcode'] in (enum('CP_CONTEXT_REG_BUNCH'),enum('CP_NON_CONTEXT_REG_BUNCH')):
            start=2 if p['opcode']==enum('CP_NON_CONTEXT_REG_BUNCH') else 0
            require((len(payload)-start)%2==0,'register bunch length')
            for i in range(start,len(payload),2): result[payload[i]]=(payload[i+1],4*(p['word']+2+i))
    return result

def decode_package(raw,resources):
    require(len(raw)>=48,'short IB header')
    h=struct.unpack_from('<12I',raw)
    typ,size,version,flags,n,data_n,reloc_n,*reserved=h
    require(typ==0x1002 and size==len(raw) and version==1 and flags==0 and not any(reserved),'IB header fields')
    require(0<n<=0x40000 and data_n<=0x100000 and data_n%64==0 and reloc_n<=16384,'IB bounds')
    data_at=align(4*n);package_n=data_at+data_n
    require(len(raw)==48+package_n+32*reloc_n,'IB allocation/relocation extent')
    package=raw[48:48+package_n]
    require(not any(package[4*n:data_at]),'nonzero packet/data padding')
    used=set();relocs=[]
    for i in range(reloc_n):
        r=dict(zip(('lo','hi','kind','access','align','hi_bits','resource_id','offset','length'),
                   struct.unpack_from('<IIBBBBIQQ',raw,48+package_n+32*i)))
        lo,hi=r['lo'],r['hi'];require(r['align']<=12 and r['length']>0,'relocation alignment/length')
        require(lo%4==0 and lo+4<=package_n and lo not in used,'relocation lo range/uniqueness');used.add(lo)
        require(not (struct.unpack_from('<I',package,lo)[0]&~((1<<r['align'])-1)),'nonzero address placeholder')
        if hi!=0xffffffff:
            require(hi%4==0 and hi+4<=package_n and hi not in used and 0<r['hi_bits']<=32,'relocation hi range/uniqueness');used.add(hi)
            require(not (struct.unpack_from('<I',package,hi)[0]&((1<<r['hi_bits'])-1)),'nonzero high address placeholder')
        else: require(r['hi_bits']==0,'single-word relocation high bits')
        if r['kind']==1:
            resource=resources.get(r['resource_id'])
            require(resource is not None and 0<r['access']<=3 and r['access']&resource['usage']==r['access'],'resource relocation ownership/usage')
            limit=resource['bytes']
        else:
            require(r['kind'] in (2,3) and r['resource_id']==0 and r['access']==1,'package/zero relocation kind/access')
            limit=package_n if r['kind']==2 else 0x4000
        require(r['offset']%(1<<r['align'])==0 and r['offset']+r['length']<=limit,'relocation target extent/alignment')
        r['index']=i;relocs.append(r)
    return {'header':dict(type=typ,bytes=size,ib_dwords=n,data_bytes=data_n,reloc_count=reloc_n),
            'packets':packets(package[:4*n]),'relocations':relocs,'data_offset':data_at,'package':package}

def read_reloc(d,at,kind=None,access=None):
    matches=[r for r in d['relocations'] if r['lo']==at]
    require(len(matches)==1,'missing/ambiguous relocation at '+str(at))
    r=matches[0]
    require(kind is None or r['kind']==kind,'relocation kind differs')
    require(access is None or r['access']==access,'relocation access differs')
    return r

def decode_compute(d,passrow,dispatch,program,base,end):
    pkts=[p for p in d['packets'] if base<=4*p['word']<end]
    execs=[p for p in pkts if p.get('opcode')==enum('CP_EXEC_CS')]
    require(len(execs)==1,'each compute pass must contain exactly one dispatch')
    execute=execs[0];groups=dispatch['groups'];threads=dispatch['threads']
    require(execute['payload']==[0]+groups,'CP_EXEC_CS geometry differs from API call')
    state=registers([p for p in pkts if p['word']<execute['word']])
    def value(name):
        require(reg(name) in state,'missing '+name)
        return state[reg(name)][0]
    require([value('SP_CS_KERNEL_GROUP_'+axis) for axis in 'XYZ']==groups,'kernel group registers')
    local=value('SP_CS_NDRANGE_0')
    require([field(local,'REG_SP_CS_NDRANGE_0','LOCALSIZE'+axis)+1 for axis in 'XYZ']==threads,'local group dimensions')
    require([value('SP_CS_NDRANGE_'+str(i)) for i in (1,3,5)]==[a*b for a,b in zip(groups,threads)],'global range registers')
    require(not any(value('SP_CS_NDRANGE_'+str(i)) for i in (2,4,6)),'nonzero dispatch offset')
    code=read_reloc(d,state[reg('SP_CS_BASE')][1],1,1)
    require(code['resource_id'] not in [dispatch['textures'][str(i)]['id'] for i in (0,1)],'shader code aliases texture')
    # Constants are followed through actual packet address fields, not searched
    # as byte substrings: stale constants elsewhere cannot satisfy this oracle.
    ubos={}
    for p in pkts:
        if p.get('opcode')!=enum('CP_LOAD_STATE6_FRAG') or len(p['payload'])!=5: continue
        v=p['payload'][0]
        if field(v,'PKT_CP_LOAD_STATE6_0','STATE_TYPE')!=enum('ST6_UBO'): continue
        require(field(v,'PKT_CP_LOAD_STATE6_0','STATE_BLOCK')==enum('SB6_CS_SHADER') and
                field(v,'PKT_CP_LOAD_STATE6_0','STATE_SRC')==enum('SS6_DIRECT') and
                field(v,'PKT_CP_LOAD_STATE6_0','NUM_UNIT')==1,'UBO load configuration')
        slot=field(v,'PKT_CP_LOAD_STATE6_0','DST_OFF');require(slot not in ubos,'duplicate UBO slot')
        r=read_reloc(d,4*(p['word']+4),2,1)
        ubos[slot]=dict(relocation=r,hex=d['package'][r['offset']:r['offset']+r['length']].hex())
    require(set(ubos)=={0,1},'application/driver UBO slots')
    expected=bytes.fromhex(dispatch['buffers']['0']['hex']);app=bytes.fromhex(ubos[0]['hex'])
    require(len(expected)==12 and app[:12]==expected and not any(app[12:]),'application constants snapshot/padding')
    subgroup=128 if program['info']['double_threadsize'] else 64
    expected_driver=groups+[1,0,0,0,subgroup]+threads+[subgroup.bit_length()-1,0,0,0,0]
    require(words(bytes.fromhex(ubos[1]['hex']))==expected_driver,'driver constants geometry/subgroup')
    descriptors={}
    for label,register,extent in [('source','SP_CS_TEXMEMOBJ_BASE',64),('sampler','SP_CS_SAMPLER_BASE',16),('destination','SP_CS_UAV_BASE',128)]:
        table=read_reloc(d,state[reg(register)][1],2,1)
        require(table['length']==extent,'descriptor table extent')
        at=table['offset']
        if label=='sampler':
            sw=words(d['package'][at:at+16])
            require(field(sw[0],'DESC_A8XX_TEX_SAMP_0','MIPMAPING_DIS')==1 and
                    field(sw[0],'DESC_A8XX_TEX_SAMP_0','XY_MIN')==enum('A6XX_TEX_NEAREST') and
                    field(sw[0],'DESC_A8XX_TEX_SAMP_0','XY_MAG')==enum('A6XX_TEX_NEAREST') and
                    field(sw[1],'DESC_A8XX_TEX_SAMP_1','UNNORM_COORDS')==1,'sampler descriptor filtering/coordinates')
            descriptors[label]={'offset':at,'words':sw};continue
        slot=0 if label=='source' else 1;access=1 if slot==0 else 2
        if slot:
            require(not any(d['package'][at:at+64]),'unused UAV slot0 is nonzero');at+=64
        r=read_reloc(d,at,1,access);texture=dispatch['textures'][str(slot)]
        require(r['resource_id']==texture['id'],'texture binding/relocation identity')
        tw=words(d['package'][at:at+64])
        require(field(tw[2],'DESC_A8XX_TEX_MEMOBJ_2','WIDTH')==texture['width'] and
                field(tw[2],'DESC_A8XX_TEX_MEMOBJ_2','HEIGHT')==texture['height'],'texture dimensions')
        require(field(tw[1],'DESC_A8XX_TEX_MEMOBJ_1','TYPE')==enum('A6XX_TEX_2D') and
                field(tw[1],'DESC_A8XX_TEX_MEMOBJ_1','DEPTH')==1,'texture type/depth')
        descriptors[label]={'offset':at,'words':tw,'relocation':r}
    # Require visibility after this dispatch, before the next pass can start.
    after=[p for p in pkts if p['word']>execute['word']]
    events=[field(p['payload'][0],'PKT_CP_EVENT_WRITE7_0','EVENT') for p in after if p.get('opcode')==enum('CP_EVENT_WRITE7')]
    require(events==[enum(n) for n in ('CACHE_CLEAN','CACHE_INVALIDATE7','DUMMY_EVENT','SUBPASS_FENCE','DUMMY_EVENT')],
            'compute image-store visibility event order')
    waits=[p['opcode'] for p in after if p.get('opcode')!=enum('CP_EVENT_WRITE7')]
    require(waits==[enum(n) for n in ('CP_WAIT_FOR_IDLE','CP_CCHE_INVALIDATE','CP_WAIT_FOR_IDLE','CP_WAIT_MEM_WRITES')],
            'compute completion/cache visibility wait order')
    return {'dispatch':dispatch['ordinal'],'pipeline':dispatch['pipeline'],'groups':groups,'threads':threads,
            'code':code,'ubos':ubos,'descriptors':descriptors,'visibility_events':events,'visibility_waits':waits}

def check_capture(c,directory,overrides=None,reference=None):
    overrides=overrides or {}
    def read(row,key='file',hashkey='sha256'):
        return overrides[row[key]] if row[key] in overrides else filebytes(directory,row,key,hashkey)
    require(c['status']=='ORDERED_ENCODING_CAPTURE_ONLY' and c['gpu_submission'] is False,'capture completion boundary')
    require(c['intercepted_commits']==len(c['cases'])==12,'complete MPS/manual commit count')
    require(len(c['streams'])==12,'native command streams missing')
    programs={}
    for entry in ENTRY:
        rows=[p for p in c['pipelines'] if p['entry']==entry]
        require(rows and all(p['compiled'] for p in rows),'real MPS pipeline compilation')
        require(len({p['air_sha256'] for p in rows})==1,'ambiguous callback AIR')
        for p in rows: read(p,'air_file','air_sha256')
        programs[entry]=rows[0]['program']
        for row in rows:
            machine=read(row,'machine_file','machine_sha256')
            require(machine==bytes.fromhex(row['program']['code_hex']),'program/machine upload bytes disagree')
            if reference is not None:
                prior=[p for p in reference['pipelines'] if p['entry']==entry and p['air_sha256']==row['air_sha256']]
                require(prior and all(bytes.fromhex(p['program']['code_hex'])==machine for p in prior),'IR3 machine code changed from retained integral capture')
            cs=row['program'].get('cs',{})
            require({'force_linear_dispatch','round_robin_mode','local_size_variable','local_size'}<=set(cs),'missing authoritative compute reflection')
            require(isinstance(cs['local_size'],list) and len(cs['local_size'])==3,'compute local size reflection')
            bindings=row['sidecar'].get('reflection',{}).get('bindings',[])
            require(any(b.get('kind')=='ubo' and b.get('metal_index')==0 and b.get('minimum_bytes')==12 for b in bindings),
                    'observed 12-byte MPS application UBO bound')
    output=[]
    for case in c['cases']:
        name=case['name'];work=case['work']
        require(work['omitted']==0 and not work['encoding_failed'] and not work['trace_incomplete'],'omitted or incomplete work: '+name)
        dispatches=[r for r in c['dispatches'] if r['case']==name]
        require([r['pipeline'] for r in dispatches]==list(ENTRY),'column then row API order: '+name)
        require(all(r['threads']==[64,1,1] and 'exception' not in r for r in dispatches),'dispatch success/local geometry')
        if name=='offset-clip': constants=[(1,2,0,0,5,7),(0,0,2,1,5,7)]
        else:
            w,h=map(int,name.split('x')) if re.fullmatch(r'\d+x\d+',name) else (9,11)
            constants=[(0,0,0,0,w,h)]*2
        for i,dispatch in enumerate(dispatches):
            require(bytes.fromhex(dispatch['buffers']['0']['hex'])==struct.pack('<6H',*constants[i]),'real API constants: '+name)
            size=constants[i][4+i]
            require(dispatch['groups']==[(size+63)//64,1,1],'axis-specific MPS geometry: '+name)
        require(dispatches[0]['textures']['1']['id']==dispatches[1]['textures']['0']['id'],'intermediate texture rebinding')
        published=[r for r in c['published_resources'] if r['case']==name]
        intermediate=dispatches[0]['textures']['1']['id']
        require(any(r['id']==intermediate and r['usage']==3 for r in published),'actual resource publication misses intermediate READ|WRITE union')
        require(len({dispatches[0]['textures']['0']['id'],dispatches[0]['textures']['1']['id'],dispatches[1]['textures']['1']['id']})==3,'distinct source/intermediate/destination')
        passes=[r for r in c['passes'] if r['case']==name]
        compute=[p for p in passes if 'dispatch' in p]
        require([p['dispatch'] for p in compute]==[d['ordinal'] for d in dispatches],'both dispatches appended in order')
        packages=[p for p in c['packages'] if p['case']==name]
        decoded=[];computations=[]
        for package in packages:
            pp=[p for p in passes if p['package']==package['package']]
            require(len(pp)==package['pass_count'],'package pass count')
            resources={}
            for p in pp:
                for r in p['resources']:
                    if r['id'] in resources: resources[r['id']]['usage']|=r['usage']
                    else: resources[r['id']]=dict(r)
            raw=read(package)
            d=decode_package(raw,resources)
            base=0;data=bytearray()
            for p in pp:
                pw=read(p,'words_file','words_sha256');pd=read(p,'data_file','data_sha256')
                require(d['package'][base:base+len(pw)]==pw,'finished pass differs from packaged words')
                data.extend(b'\0'*(align(len(data))-len(data)));data.extend(pd)
                if 'dispatch' in p:
                    dispatch=next(x for x in dispatches if x['ordinal']==p['dispatch'])
                    uses={r['id']:r['usage'] for r in p['resources']}
                    require(uses.get(dispatch['textures']['0']['id'])==1 and uses.get(dispatch['textures']['1']['id'])==2,'per-pass source READ/destination WRITE')
                    computation=decode_compute(d,p,dispatch,programs[dispatch['pipeline']],base,base+len(pw))
                    code=next(r for r in p['resources'] if r['id']==computation['code']['resource_id'])
                    code_bytes=read(code,'contents_file','contents_sha256')
                    pipeline=next(r for r in c['pipelines'] if r['entry']==dispatch['pipeline'])
                    machine=read(pipeline,'machine_file','machine_sha256')
                    require(code_bytes[:len(machine)]==machine and not any(code_bytes[len(machine):]),'uploaded code differs from compiled machine bytes')
                    computations.append(computation)
                base+=len(pw)
            require(base==4*d['header']['ib_dwords'],'unaccounted packet work')
            data.extend(b'\0'*(align(len(data))-len(data)))
            require(d['package'][d['data_offset']:]==data,'dispatch data changed during packaging')
            decoded.append({k:v for k,v in d.items() if k!='package'}|{'sha256':sha(raw),'file':package['file']})
        require(len(computations)==2,'missing encoded compute pass')
        streamrows=[r for r in c['streams'] if r['case']==name];require(len(streamrows)==1,'one final native stream per case')
        stream=read(streamrows[0]);at=0;seen=[];fill_bytes=0;layout=[]
        while at<len(stream):
            require(at+8<=len(stream),'short kernel command')
            typ,size=struct.unpack_from('<II',stream,at);require(size>=8 and at+size<=len(stream),'kernel command extent')
            raw=stream[at:at+size]
            if typ==0x1002:
                require(len(seen)<len(packages),'unaccounted IB in native stream')
                p=packages[len(seen)]
                require(raw==read(p) and fill_bytes==p['fills_before'],'actual native stream package/fill order')
                seen.append(p['file']);layout.append('IB')
            elif typ==0x1001:
                require(size==32,'FILL32 extent');rid,pattern,off,length=struct.unpack_from('<IIQQ',raw,8)
                require(rid and length and (off|length)%4==0,'FILL32 geometry')
                fill_bytes+=size;layout.append('FILL32')
            else:
                require(typ==0x1000 and size==8 and at+size==len(stream),'terminal fence only');layout.append('FENCE')
            at+=size
        require(len(seen)==len(packages),'native stream omitted package')
        if name=='compute-fill-render-compute':
            require(len(packages)>=2 and layout[0]=='IB' and 'FILL32' in layout[1:-1],'compute/fill ordering')
            require(any(p['kind']=='AdrenoRenderPass' for p in passes),'render pass missing from mixed case')
            blits=[e for e in work['encoders'].values() if e['kind']=='blit']
            require(len(blits)==1 and blits[0]['encoded']==1 and blits[0]['omitted']==0 and blits[0]['ended'],
                    'mixed GPU fill was not accounted as encoded work')
        if name in ('app-bytes-snapshot','compute-fill-render-compute'):
            require(all(case.get(k) is True for k in ('released_external_owners_before_commit','mutated_inline_storage_before_dispatch','cleared_bindings_before_commit')),'lifetime/mutation scenario not exercised')
        output.append({'name':name,'work':work,'packages':decoded,'compute':computations,'native_stream_layout':layout})
    required={'short-inline','missing-source','zero-grid','overflow-grid','oversized-local','commit-open-encoder',
              'compute-blit-overlap','blit-compute-overlap','blit-render-overlap','commit-open-blit'}
    require({r['name'] for r in c['controls']}==required,'API refusal control coverage')
    require(all(r['refused'] and r['native_commits']==0 for r in c['controls']),'refusal reached native commit')
    return output

def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--capture',type=Path,required=True);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--reference-capture',type=Path,required=True)
    args=ap.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    c=json.loads(args.capture.read_text());reference=json.loads(args.reference_capture.read_text())
    cases=check_capture(c,args.capture.parent,reference=reference)
    report={'status':'PASS_MPS_ORDERED_ENCODING','boundary':'Host encoding only; no GPU execution, numeric shader output, A16 access or display proof.',
            'capture_sha256':sha(args.capture.read_bytes()),'decoder_sha256':sha(Path(__file__).read_bytes()),'registers_sha256':sha(REGS.read_bytes()),
            'reference_capture_sha256':sha(args.reference_capture.read_bytes()),'ir3_unchanged_from_reference':True,
            'cases':cases,'api_negative_controls':c['controls'],'mutation_negative_controls':[]}
    # Mutate retained real evidence; each control must fail the same production
    # artifact oracle. Persist mutations so refusals are independently repeatable.
    mutations=[]
    bad=copy.deepcopy(c);bad['passes']=[p for p in bad['passes'] if p.get('dispatch')!=0];mutations.append(('drop-column',bad,None))
    bad=copy.deepcopy(c);bad['passes']=[p for p in bad['passes'] if p.get('dispatch')!=1];mutations.append(('drop-row',bad,None))
    bad=copy.deepcopy(c);bad['dispatches'][0],bad['dispatches'][1]=bad['dispatches'][1],bad['dispatches'][0];mutations.append(('reverse-dispatches',bad,None))
    bad=copy.deepcopy(c);bad['dispatches'][1]['textures']['0']=copy.deepcopy(bad['dispatches'][0]['textures']['0']);mutations.append(('wrong-intermediate',bad,None))
    bad=copy.deepcopy(c);bad['dispatches'][0]['buffers']['0']['hex']='ed'*12;mutations.append(('borrowed-app-bytes',bad,None))
    bad=copy.deepcopy(c);bad['cases'][0]['work']['omitted']=1;mutations.append(('unaccounted-omission',bad,None))
    first=c['packages'][0];raw=bytearray(filebytes(args.capture.parent,first));n,data_n,reloc_n=struct.unpack_from('<III',raw,16);reloc_at=48+align(4*n)+data_n
    struct.pack_into('<I',raw,reloc_at,align(4*n)+data_n);mutations.append(('relocation-outside-package',c,{first['file']:bytes(raw)}))
    raw=bytearray(filebytes(args.capture.parent,first));decoded=cases[0]['packages'][0]
    dispatch_word=next(p['word'] for p in decoded['packets'] if p.get('opcode')==enum('CP_EXEC_CS'))
    barrier=next(p for p in decoded['packets'] if p['word']>dispatch_word and p.get('opcode')==enum('CP_EVENT_WRITE7') and p['payload'] and field(p['payload'][0],'PKT_CP_EVENT_WRITE7_0','EVENT')==enum('CACHE_INVALIDATE7'))
    struct.pack_into('<I',raw,48+4*(barrier['word']+1),enum('DUMMY_EVENT'))
    firstpass=next(p for p in c['passes'] if p.get('dispatch')==0)
    passwords=bytearray(filebytes(args.capture.parent,firstpass,'words_file','words_sha256'))
    struct.pack_into('<I',passwords,4*(barrier['word']+1),enum('DUMMY_EVENT'))
    mutations.append(('lost-image-store-visibility',c,{first['file']:bytes(raw),firstpass['words_file']:bytes(passwords)}))
    for name,bad,override in mutations:
        folder=args.out/'negative'/name;folder.mkdir(parents=True)
        (folder/'capture.json').write_text(json.dumps(bad,indent=2)+'\n')
        for filename,b in (override or {}).items(): (folder/filename).write_bytes(b)
        try: check_capture(bad,args.capture.parent,override,reference)
        except ValueError as error:
            row={'name':name,'refused':True,'reason':str(error),'capture_sha256':sha((folder/'capture.json').read_bytes()),
                 'overrides':{k:sha(v) for k,v in (override or {}).items()}}
            report['mutation_negative_controls'].append(row);(folder/'result.json').write_text(json.dumps(row,indent=2)+'\n')
        else: raise ValueError('negative control passed: '+name)
    (args.out/'decoded.json').write_text(json.dumps(report,indent=2)+'\n')
    print(report['status']+f": {len(cases)} cases; {len(c['controls'])} API and {len(mutations)} artifact refusal controls; no GPU execution")

if __name__=='__main__': main()
