# SPDX-License-Identifier: MIT
"""Decode the byte-qualified 26A428 native device-open serialization queue.

Read-only, for an independently audited stopped kernel. The caller supplies
kernel virtual reads and the immutable kernel's instruction reader. A queue
owner and observed sleepers identify dependency, not permanence or deadlock.
"""
import struct

HEAD=0xfffffe000c6d6c58
WAIT_RETURN=0xfffffe000c0458e0
TTY_RETURN=0xfffffe000bf146d8
TTY_WITNESSES={
    0xfffffe000bf14690:0xd538d093, 0xfffffe000bf14694:0xb9451a68,
    0xfffffe000bf146a0:0x9100200a, 0xfffffe000bf146b0:0xf900f413,
    0xfffffe000bf146c8:0xaa0003f4, 0xfffffe000bf146cc:0xaa1303e1,
    0xfffffe000bf146d4:0x97e7d943,
    0xfffffe000b90ad30:0xa9064ff4, 0xfffffe000b90ad34:0xa9077bfd,
    0xfffffe000b90ad38:0x9101c3fd, 0xfffffe000b90ad70:0x91002277,
    0xfffffe000b90ad80:0xf94002fa, 0xfffffe000b90ad84:0x12006f56,
    0xfffffe000b90b170:0xaa1703e1,
}
WITNESSES={
    0xfffffe000bb902ac:0xaa1703e0, 0xfffffe000bb902b0:0x52840001,
    0xfffffe000bb902b4:0x9412d519,
    0xfffffe000c045734:0xaa0103f4, 0xfffffe000c045738:0xaa0003f6,
    0xfffffe000c045750:0xd538d093, 0xfffffe000c045754:0xf9000813,
    0xfffffe000c045758:0x29035016,
    0xfffffe000c04578c:0xb0003488, 0xfffffe000c045790:0xf9462d15,
    0xfffffe000c045798:0xf900001f, 0xfffffe000c04579c:0xb0003488,
    0xfffffe000c0457a0:0xf9463109, 0xfffffe000c0457a4:0xf9000409,
    0xfffffe000c0457a8:0xf9000120, 0xfffffe000c0457ac:0xf9063100,
    0xfffffe000c0457e4:0xf94002b5, 0xfffffe000c0457ec:0xb9401aa8,
    0xfffffe000c0457f8:0xb9401ea8, 0xfffffe000c045808:0xb94022a8,
    0xfffffe000c045810:0xb90022a8, 0xfffffe000c045814:0xf9400aa1,
    0xfffffe000c0458d0:0xaa1503e0, 0xfffffe000c0458dc:0x97e33875,
}

def collect(read,u32,kernel_threads,processes):
    for address,word in WITNESSES.items():
        if u32(address)!=word:
            raise ValueError(f'device-open instruction witness differs at {address:x}')
    def pointer(value):return 0xffff800000000000<=value<0xfffffffffffffff8 and value%8==0
    def exact(address,size):
        if not pointer(address):raise ValueError('invalid device-open kernel pointer')
        raw=read(address,size)
        if len(raw)!=size:raise ValueError('short device-open kernel read')
        return raw
    identities={};thread_rows={};observed=[]
    def add(thread,pid,name):
        address=int(thread['thread'],16)
        if not pointer(address) or address in identities:
            raise ValueError('invalid or duplicate captured thread identity')
        identity=dict(thread=hex(address),tid=thread['tid'],pid=pid,name=name,
                      on_cpu=thread.get('on_cpu',thread.get('on_cpu_at_stop')))
        identities[address]=identity
        thread_rows[address]=thread
        event=int(thread['wait_event'],16)
        matched=any(int(f['raw_lr'],16)==WAIT_RETURN for f in thread.get('frames',[]))
        observed.append((identity,event,matched))
    for t in kernel_threads:add(t,0,t.get('name','kernel'))
    for p in processes:
        for t in p['threads']:add(t,p['pid'],p['name'])
    head=exact(HEAD,16);node,tail=struct.unpack('<2Q',head)
    previous=HEAD;seen=set();keys=set();records=[]
    while node:
        if node in seen or len(seen)>=256:raise ValueError('device-open queue cycle or budget exhausted')
        seen.add(node);raw=exact(node,40)
        following,back,owner,device,kind,waiters,reserved=struct.unpack('<3Q4I',raw)
        if back!=previous or not pointer(owner):raise ValueError('invalid device-open backlink or owner')
        if (device,kind) in keys:raise ValueError('duplicate active device-open key')
        keys.add((device,kind))
        sleepers=[identity for identity,event,matched in observed if event==node and matched]
        other_events=[identity for identity,event,matched in observed if event==node and not matched]
        if len(sleepers)>waiters:raise ValueError('device-open waiter counter is too small')
        records.append(dict(address=hex(node),next=hex(following),previous_link=hex(back),
            owner_thread=hex(owner),owner=identities.get(owner),device=hex(device),
            kind=hex(kind),waiters=waiters,reserved=reserved,
            observed_sleepers=sleepers,unqualified_event_matches=other_events,raw_hex=raw.hex()))
        previous=node;node=following
    if tail!=previous:raise ValueError('invalid device-open tail pointer')
    if exact(HEAD,16)!=head:raise ValueError('device-open queue head changed while stopped')
    for record in records:
        if exact(int(record['address'],16),40).hex()!=record['raw_hex']:
            raise ValueError('device-open queue record changed while stopped')
        owner=int(record['owner_thread'],16);thread=thread_rows.get(owner)
        if thread is None:continue
        frames=[f for f in thread.get('frames',[]) if int(f['raw_lr'],16)==TTY_RETURN]
        if not frames:continue
        if len(frames)!=1:raise ValueError('ambiguous native tty-lock frame')
        for address,word in TTY_WITNESSES.items():
            if u32(address)!=word:raise ValueError('native tty-lock witness differs')
        # tty_lock preserves its argument in x20 and its current thread in x19.
        # The slow mutex callee saves them at its FP-16 and FP-8, respectively.
        fp=int(frames[0]['fp'],16);saved=exact(fp-16,16)
        tty,saved_thread=struct.unpack('<2Q',saved)
        event=int(thread['wait_event'],16)
        if saved_thread!=owner or event!=tty+8 or not pointer(tty):
            raise ValueError('tty argument, saved thread and wait event disagree')
        header=exact(tty,16);stored=exact(tty+0x1e8,8)
        state=struct.unpack_from('<Q',header,8)[0];ctid=state&0xfffffff
        tty_owner,=struct.unpack('<Q',stored)
        ctid_raw=exact(tty_owner+0x518,4) if tty_owner else None
        actual=struct.unpack('<I',ctid_raw)[0] if ctid_raw is not None else 0
        qualified=bool(tty_owner and ctid and actual==ctid)
        if (exact(fp-16,16)!=saved or exact(tty,16)!=header or
                exact(tty+0x1e8,8)!=stored or
                (ctid_raw is not None and exact(tty_owner+0x518,4)!=ctid_raw)):
            raise ValueError('tty mutex ownership changed while stopped')
        record['tty_wait']=dict(tty=hex(tty),wait_event=hex(event),mutex_hex=header.hex(),
            saved_registers_hex=saved.hex(),saved_registers_address=hex(fp-16),
            encoded_compact_id=ctid,stored_owner=hex(tty_owner),stored_owner_compact_id=actual,
            owner_qualified=qualified,owner=identities.get(tty_owner) if qualified else None,
            boundary='Native tty pointer recovered from callee-saved registers and matched to '
                     'the mutex wait event. A stored tty owner is qualified only when its '
                     'compact thread ID matches the mutex owner encoding; otherwise no owner is claimed.')
    return dict(head=hex(HEAD),head_hex=head.hex(),records=records,complete=True,
        instruction_witnesses=len(WITNESSES),
        boundary='Byte-qualified native owner/current-thread and linked-list layout; '
                 'two identical stopped reads. Sleepers require both matching event and '
                 'the exact device-open wait return. Unknown owners and unmatched events '
                 'remain unqualified; an observed dependency is not proof of deadlock.')
