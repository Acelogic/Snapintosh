#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resolve Mach port names and IPC waits to receiving tasks in a stopped J700 26A428 guest.

Answers "who is this thread waiting on?" for a stopped guest: for any process
and Mach port name it walks task->itk_space->is_table->ipc_entry->ipc_port and
binds the port's receive right to the receiving task (pid/name), the launchd
service label when the port carries one, the messages queued on it and what
the receiver's threads are doing. For every thread blocked in a Mach receive it
follows the special-reply-port sync linkage (MACH_RCV_SYNC_WAIT) and the
receive turnstile's inheritor chain to the thread, workloop or port that owes
the reply.

Modes (none of which writes guest state or calls guest code):
  --self-test   offline: pins every layout word against the kernelcache AND the
                UUID-identical KDK kernel, checks every offset against the KDK
                DWARF, and runs the decoder over synthetic kernel memory.
  --dry-run     offline: prints the capture plan for --prefix; opens no link.
  (default)     stopped-state capture over --device, bounded reads only.

All offsets were derived from Apple's KDK kernel.release.t8140 (LC_UUID
F9F468D7-1F50-354A-BECD-6BD6C1C834AD, byte-identical to com.apple.kernel in the
J700 kernelcache, see tools/kc-symbolicate.py) by disassembling the functions
named in WITNESSES and reading its dSYM DWARF (DWARF_FIELDS). PAC is stripped
for lookup only; nothing is authenticated. Reciprocal links (task<->space,
thread<->thread_ro, kqworkloop<->turnstile, port<->turnstile) are checked at
run time and failures are recorded as errors, never guessed around.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
KERNEL_SHA = 'dc9019ae39187b36936c2c513b485e513f15cd966b5c887ac88ffd2925976c62'
KDK_KERNEL = Path('/Library/Developer/KDKs/KDK_27.0_26A428.kdk/System/Library/Kernels/kernel.release.t8140')
# Kernelcache minus KDK segment bases (tools/kc-symbolicate.py segment maps).
TEXT_EXEC_DELTA = 0xfffffe000b86c000 - 0xfffffe0007320000
DATA_CONST_DELTA = 0xfffffe0007d58000 - 0xfffffe0007138000
# ipc_port_get_receiver_task+140/+144 and +212/+216: adrp/ldr of the two
# kernel-owned spaces (KDK dSYM names them ipc_space_kernel / ipc_space_reply).
IPC_SPACE_KERNEL = 0xfffffe0007175838 + DATA_CONST_DELTA   # 0xfffffe0007d95838
IPC_SPACE_REPLY = 0xfffffe0007176018 + DATA_CONST_DELTA    # 0xfffffe0007d96018
# KDK 0xfffffe0007351dcc ipc_mqueue_receive_continue (ipc_mqueue.c:880).
RECEIVE_CONTINUE = 0xfffffe0007351dcc + TEXT_EXEC_DELTA    # 0xfffffe000b89ddcc

# (label, KDK VA, instruction word). The kernelcache VA is KDK VA+TEXT_EXEC_DELTA.
WITNESSES = (
    # ipc_entry_lookup (inlined is_active_table), KDK 0xfffffe0007345324
    ('ipc_entry_lookup+4 ldr x16,[x0,#0x48]! space->is_table', 0xfffffe0007345328, 0xf8448c10),
    ('ipc_entry_lookup+16 movk x17,#0xb8b5 is_table PAC disc', 0xfffffe0007345334, 0xf2f716b1),
    ('ipc_entry_lookup+32 tbnz x16,#46 kalloc-array zone form', 0xfffffe0007345344, 0xb77000d0),
    ('ipc_entry_lookup+40 ubfiz x9,x16,#14,#14 large size', 0xfffffe000734534c, 0xd3723609),
    ('ipc_entry_lookup+44 and x8,x16,#~0x3fff large base', 0xfffffe0007345350, 0x9272c608),
    ('ipc_entry_lookup+48 orr x8,x8,#1<<46 large base', 0xfffffe0007345354, 0xb2520108),
    ('ipc_entry_lookup+56 and x8,x16,#0x10 zone size', 0xfffffe000734535c, 0x927c0208),
    ('ipc_entry_lookup+60 orr x8,x8,#0x20', 0xfffffe0007345360, 0xb27b0108),
    ('ipc_entry_lookup+64 and x9,x16,#0xf zone shift', 0xfffffe0007345364, 0x92400e09),
    ('ipc_entry_lookup+68 lsl x9,x8,x9', 0xfffffe0007345368, 0x9ac92109),
    ('ipc_entry_lookup+72 and x8,x16,#~0x1f zone base', 0xfffffe000734536c, 0x927bea08),
    ('ipc_entry_lookup+80 mov w11,#0x18 sizeof(ipc_entry)', 0xfffffe0007345374, 0x5280030b),
    ('ipc_entry_lookup+88 add x11,x11,#0x18 bound', 0xfffffe000734537c, 0x9100616b),
    ('ipc_entry_lookup+100 index*3', 0xfffffe0007345388, 0x8b0a0549),
    ('ipc_entry_lookup+104 base+index*24', 0xfffffe000734538c, 0x8b090d00),
    ('ipc_entry_lookup+108 ldr w8,[x0,#8] ie_bits', 0xfffffe0007345390, 0xb9400808),
    ('ipc_entry_lookup+112 and w9,w8,#0xfc000000 gen', 0xfffffe0007345394, 0x12061509),
    ('ipc_entry_lookup+116 orr w9,w9,#0x3000000 roll', 0xfffffe0007345398, 0x32080529),
    ('ipc_entry_lookup+120 lsl w10,w1,#24 name gen', 0xfffffe000734539c, 0x53081c2a),
    ('ipc_entry_lookup+124 and w8,w8,#0x1f0000 type', 0xfffffe00073453a0, 0x12101108),
    # ipc_mqueue_receive_on_thread_and_unlock, KDK 0xfffffe0007351924
    ('receive+916 ldr w8,[x20] waitq bits', 0xfffffe0007351cb8, 0xb9400288),
    ('receive+920 and w8,w8,#7 waitq_type', 0xfffffe0007351cbc, 0x12000908),
    ('receive+924 cmp w8,#3 WQT_PORT', 0xfffffe0007351cc0, 0x71000d1f),
    ('receive+932 sub x24,x20,#0x10 port=waitq-0x10', 0xfffffe0007351cc8, 0xd1004298),
    ('receive+936 add x1,x20,#8 rcv turnstile slot', 0xfffffe0007351ccc, 0x91002281),
    ('receive+984 mov w8,#2 kThreadWaitPortReceive', 0xfffffe0007351cfc, 0x52800048),
    ('receive+988 strb w8,[x19,#0x58d] pending_block_hint', 0xfffffe0007351d00, 0x39163668),
    ('receive+996 mov x1,#0 IPC_MQUEUE_RECEIVE event', 0xfffffe0007351d08, 0xd2800001),
    # waitq_assert_wait64_locked, KDK 0xfffffe000742663c
    ('assert_wait+180 cmp w8,#3 WQT_PORT', 0xfffffe00074266f0, 0x71000d1f),
    ('assert_wait+188 ldr x24,[x19,#8] port waitq_ts', 0xfffffe00074266f8, 0xf9400678),
    ('assert_wait+500 str x25,[x20,#0x18] thread->wait_event', 0xfffffe0007426830, 0xf9000e99),
    ('assert_wait+504 str x19,[x20,#0x28] thread->waitq', 0xfffffe0007426834, 0xf9001693),
    # ipc_port_link_special_reply_port, KDK 0xfffffe000735828c
    ('link_srp+128 ldrb w8,[x20] io_type', 0xfffffe000735830c, 0x39400288),
    ('link_srp+136 cmp w8,#0xb IOT_SPECIAL_REPLY_PORT', 0xfffffe0007358314, 0x71002d1f),
    ('link_srp+156 tst w8,#0x7000 ip_sync_link_state', 0xfffffe0007358328, 0x7214091f),
    ('link_srp+192 ldr x16,[x8,#0x58]! ip_sync_inheritor_port', 0xfffffe000735834c, 0xf8458d10),
    ('link_srp+196 movk x8,#0xa1c0 inheritor PAC disc', 0xfffffe0007358350, 0xf2f43808),
    ('link_srp+404 str x17,[x20,#0x58]', 0xfffffe0007358420, 0xf9002e91),
    ('link_srp+408 ldr w8,[x20,#0x10]', 0xfffffe0007358424, 0xb9401288),
    ('link_srp+412 and w8,w8,#0xffff8fff', 0xfffffe0007358428, 0x12117108),
    ('link_srp+416 orr w8,w8,#0x1000 PORT_SYNC_LINK_PORT', 0xfffffe000735842c, 0x32140108),
    # ipc_port_get_receiver_task, KDK 0xfffffe0007358d9c
    ('receiver_task+120 ldrb w8,[x19,#1] io_state', 0xfffffe0007358e14, 0x39400668),
    ('receiver_task+124 and w8,w8,#7', 0xfffffe0007358e18, 0x12000908),
    ('receiver_task+128 sub w8,w8,#1', 0xfffffe0007358e1c, 0x51000508),
    ('receiver_task+132 cmp w8,#1 IN_SPACE{,_IMMOVABLE}', 0xfffffe0007358e20, 0x7100051f),
    ('receiver_task+144 ldr x10,[x8,#0x838] ipc_space_kernel', 0xfffffe0007358e2c, 0xf9441d0a),
    ('receiver_task+152 ldr x8,[x9,#0x48]! ip_receiver', 0xfffffe0007358e34, 0xf8448d28),
    ('receiver_task+168 movk x17,#0x97f6 ip_receiver disc', 0xfffffe0007358e44, 0xf2f2fed1),
    ('receiver_task+244 ldr x8,[x16,#0x50]! is_task', 0xfffffe0007358e90, 0xf8450e08),
    ('receiver_task+260 movk x17,#0xc547 is_task disc', 0xfffffe0007358ea0, 0xf2f8a8f1),
    # ikm_header, KDK 0xfffffe000734dfc4
    ('ikm_header+4 ldrb w8,[x0,#0x3f] ikm_type', 0xfffffe000734dfc8, 0x3940fc08),
    ('ikm_header+8 lsr w8,w8,#6', 0xfffffe000734dfcc, 0x53067d08),
    ('ikm_header+12 cmp w8,#1', 0xfffffe000734dfd0, 0x7100051f),
    ('ikm_header+24 add x16,x0,#0x40 inline header', 0xfffffe000734dfdc, 0x91010010),
    ('ikm_header+32 ldr x16,[x0,#0xe8]! ikm_kdata', 0xfffffe000734dfe4, 0xf84e8c10),
    ('ikm_header+44 movk x17,#0x289d kdata disc', 0xfffffe000734dff0, 0xf2e513b1),
    # get_threadtask, KDK 0xfffffe00074393b8
    ('get_threadtask+12 ldr x1,[x0,#0x420] t_tro', 0xfffffe00074393c4, 0xf9421001),
    ('get_threadtask+108 ldr x8,[x1] tro_owner', 0xfffffe0007439424, 0xf9400028),
    ('get_threadtask+112 cmp x8,x0 owner==thread', 0xfffffe0007439428, 0xeb00011f),
    ('get_threadtask+120 ldr x0,[x1,#0x28] tro_task', 0xfffffe0007439430, 0xf9401420),
    # get_task_ipcspace inlined in audit_session code, KDK 0xfffffe00079128a8
    ('get_task_ipcspace ldr x16,[x8,#0x318] itk_space', 0xfffffe00079128a8, 0xf9418d10),
    ('get_task_ipcspace movk x17,#0x8280 itk_space disc', 0xfffffe00079128b4, 0xf2f05011),
    # mach_port_get_service_port_info, KDK 0xfffffe000736a06c
    ('service_info+80 ldr x16,[x21,#8] io label', 0xfffffe000736a0bc, 0xf94006b0),
    ('service_info+120 cmp w8,#4 IOT_WEAK_SERVICE_PORT', 0xfffffe000736a0e4, 0x7100111f),
    ('service_info+128 cmp w8,#3 IOT_BOOTSTRAP_PORT', 0xfffffe000736a0ec, 0x71000d1f),
    ('service_info+136 cmp w8,#2 IOT_SERVICE_PORT', 0xfffffe000736a0f4, 0x7100091f),
    ('service_info+144 ldrb w8,[x16,#0x15] ispl_domain', 0xfffffe000736a0fc, 0x39405608),
    ('service_info+152 ldr x20,[x16,#0x18] ispl_service_name', 0xfffffe000736a104, 0xf9400e14),
)

# Offsets used by the decoder, each checked against the KDK DWARF by --self-test.
L = dict(
    task_itk_space=0x318, task_bsd_info_ro=0x3f8,
    space_is_table=0x48, space_is_task=0x50,
    entry_size=0x18, entry_object=0x0, entry_bits=0x8,
    obj_type=0x0, obj_state=0x1, obj_label=0x8,
    port_waitq=0x10, port_waitq_ts=0x18, port_messages=0x28, port_seqno=0x30,
    port_receiver_name=0x34, port_msgcount=0x38, port_qlimit=0x3a, port_imq_union=0x40,
    port_receiver=0x48, port_kobject=0x50, port_sync_inheritor=0x58, port_pid_union=0x60,
    port_send_turnstile=0x70, port_context=0x78, port_mscount=0x84, port_srights=0x88,
    port_sorights=0x8c, port_size=0x90, pset_wqset=0x10,
    thread_wait_event=0x18, thread_waitq=0x28, thread_turnstile=0x30,
    thread_inheritor=0x38, thread_continuation=0xe0, thread_kernel_stack=0xf0,
    thread_recv_msg_addr=0x378, thread_ith_option=0x390, thread_ith_object=0x398,
    thread_ith_state=0x3a0, thread_ith_receiver_name=0x3b0, thread_task_threads=0x410,
    thread_t_tro=0x420, thread_special_reply_port=0x450, thread_id=0x510,
    thread_pending_block_hint=0x58d, thread_block_hint=0x58e, thread_size=0x5f8,
    tro_owner=0x0, tro_proc=0x18, tro_task=0x28,
    proc_ro=0x18, proc_pid=0x60, proc_comm=0x5bc, proc_name=0x5cd, proc_size=0x7c0,
    proc_ro_pr_proc=0x0, proc_ro_pr_task=0x8,
    ts_inheritor=0x10, ts_proprietor=0x48, ts_refcount=0x50, ts_type_gencount=0x54,
    ts_prim_count=0x58, ts_inheritor_flags=0x5c, ts_priority=0x5d, ts_size=0x60,
    kqwl_kq_p=0x18, kqwl_owner=0xd0, kqwl_turnstile=0xe0, kqwl_dynamicid=0xe8,
    kmsg_type_byte=0x3f, kmsg_inline=0x40, kmsg_kdata=0xe8,
    ispl_domain=0x15, ispl_name=0x18, ibpl_name=0x8,
)
# (key in L, DWARF type, dotted field path) - field paths through anonymous
# unions are written with the leaf name only; the checker searches recursively.
DWARF_FIELDS = (
    ('task_itk_space', 'task', 'itk_space'), ('task_bsd_info_ro', 'task', 'bsd_info_ro'),
    ('space_is_table', 'ipc_space', 'is_table'), ('space_is_task', 'ipc_space', 'is_task'),
    ('entry_object', 'ipc_entry', 'ie_object'), ('entry_bits', 'ipc_entry', 'ie_bits'),
    ('obj_label', 'ipc_object', 'iol_pointer'),
    ('port_waitq', 'ipc_port', 'ip_waitq'), ('port_waitq_ts', 'waitq', 'waitq_ts', 0x10),
    ('port_messages', 'ipc_port', 'ip_messages'),
    ('port_seqno', 'ipc_mqueue', 'imq_seqno', 0x28),
    ('port_receiver_name', 'ipc_mqueue', 'imq_receiver_name', 0x28),
    ('port_msgcount', 'ipc_mqueue', 'imq_msgcount', 0x28),
    ('port_qlimit', 'ipc_mqueue', 'imq_qlimit', 0x28),
    ('port_imq_union', 'ipc_mqueue', 'imq_srp_owner_thread', 0x28),
    ('port_receiver', 'ipc_port', 'ip_receiver'), ('port_kobject', 'ipc_port', 'ip_kobject'),
    ('port_sync_inheritor', 'ipc_port', 'ip_sync_inheritor_port'),
    ('port_pid_union', 'ipc_port', 'ip_pdrequest'),
    ('port_send_turnstile', 'ipc_port', 'ip_send_turnstile'),
    ('port_context', 'ipc_port', 'ip_context'), ('port_mscount', 'ipc_port', 'ip_mscount'),
    ('port_srights', 'ipc_port', 'ip_srights'), ('port_sorights', 'ipc_port', 'ip_sorights'),
    ('pset_wqset', 'ipc_pset', 'ips_wqset'),
    ('thread_wait_event', 'thread', 'wait_event'), ('thread_waitq', 'thread', 'waitq'),
    ('thread_turnstile', 'thread', 'turnstile'), ('thread_inheritor', 'thread', 'inheritor'),
    ('thread_continuation', 'thread', 'continuation'),
    ('thread_kernel_stack', 'thread', 'kernel_stack'),
    ('thread_recv_msg_addr', 'thread', 'recv_msg_addr'),
    ('thread_ith_option', 'thread', 'option'), ('thread_ith_object', 'thread', 'object'),
    ('thread_ith_state', 'thread', 'state@0x3a0'),
    ('thread_ith_receiver_name', 'thread', 'receiver_name'),
    ('thread_task_threads', 'thread', 'task_threads'), ('thread_t_tro', 'thread', 't_tro'),
    ('thread_special_reply_port', 'thread', 'ith_special_reply_port'),
    ('thread_id', 'thread', 'thread_id'),
    ('thread_pending_block_hint', 'thread', 'pending_block_hint'),
    ('thread_block_hint', 'thread', 'block_hint'),
    ('tro_owner', 'thread_ro', 'tro_owner'), ('tro_proc', 'thread_ro', 'tro_proc'),
    ('tro_task', 'thread_ro', 'tro_task'),
    ('proc_ro', 'proc', 'p_proc_ro'), ('proc_pid', 'proc', 'p_pid'),
    ('proc_comm', 'proc', 'p_comm'), ('proc_name', 'proc', 'p_name'),
    ('proc_ro_pr_proc', 'proc_ro', 'pr_proc'), ('proc_ro_pr_task', 'proc_ro', 'pr_task'),
    ('ts_inheritor', 'waitq', 'waitq_inheritor'), ('ts_proprietor', 'turnstile', 'ts_proprietor'),
    ('ts_refcount', 'turnstile', 'ts_refcount'), ('ts_type_gencount', 'turnstile', 'ts_type_gencount'),
    ('ts_prim_count', 'turnstile', 'ts_prim_count'),
    ('ts_inheritor_flags', 'turnstile', 'ts_inheritor_flags'),
    ('ts_priority', 'turnstile', 'ts_priority'),
    ('kqwl_kq_p', 'kqueue', 'kq_p'), ('kqwl_owner', 'kqworkloop', 'kqwl_owner'),
    ('kqwl_turnstile', 'kqworkloop', 'kqwl_turnstile'),
    ('kqwl_dynamicid', 'kqworkloop', 'kqwl_dynamicid'),
    ('kmsg_inline', 'ipc_kmsg', 'ikm_big_data'), ('kmsg_kdata', 'ipc_kmsg', 'ikm_kdata'),
    ('ispl_domain', 'ipc_service_port_label', 'ispl_domain'),
    ('ispl_name', 'ipc_service_port_label', 'ispl_service_name'),
    ('ibpl_name', 'ipc_bootstrap_port_label', 'ispl_service_name'),
)
DWARF_SIZES = dict(ipc_port=0x90, ipc_entry=0x18, turnstile=0x60, thread=0x5f8, proc=0x7c0,
                   ipc_space=0x80, thread_ro=0x38, kqworkloop=0x108, ipc_kmsg=0x100)

IOT = ['PORT_SET', 'PORT', 'SERVICE_PORT', 'BOOTSTRAP_PORT', 'WEAK_SERVICE_PORT',
       'CONNECTION_PORT', 'CONNECTION_PORT_WITH_PORT_ARRAY', 'NOTIFICATION_PORT',
       'EXCEPTION_PORT', 'TIMER_PORT', 'REPLY_PORT', 'SPECIAL_REPLY_PORT', 'WEAK_REPLY_PORT',
       'IKOT_THREAD_CONTROL', 'IKOT_THREAD_READ', 'IKOT_THREAD_INSPECT', 'IKOT_THREAD_RESUME',
       'IKOT_TASK_CONTROL', 'IKOT_TASK_READ', 'IKOT_TASK_INSPECT', 'IKOT_TASK_NAME',
       'IKOT_TASK_RESUME', 'IKOT_TASK_ID_TOKEN', 'IKOT_TASK_FATAL', 'IKOT_HOST',
       'IKOT_HOST_PRIV', 'IKOT_CLOCK', 'IKOT_PROCESSOR', 'IKOT_PROCESSOR_SET',
       'IKOT_PROCESSOR_SET_NAME', 'IKOT_EVENTLINK', 'IKOT_FILEPORT', 'IKOT_SEMAPHORE',
       'IKOT_VOUCHER', 'IKOT_WORK_INTERVAL', 'IKOT_MEMORY_OBJECT', 'IKOT_NAMED_ENTRY',
       'IKOT_MAIN_DEVICE', 'IKOT_IOKIT_IDENT', 'IKOT_IOKIT_CONNECT', 'IKOT_IOKIT_OBJECT',
       'IKOT_UEXT_OBJECT', 'IKOT_EXCLAVES_RESOURCE', 'IKOT_ARCADE_REG', 'IKOT_AU_SESSIONPORT',
       'IKOT_HYPERVISOR', 'IKOT_KCDATA', 'IKOT_UND_REPLY', 'IKOT_UX_HANDLER', 'IKOT_VIRTUAL_ENV']
IO_STATE = ['INACTIVE', 'IN_SPACE', 'IN_SPACE_IMMOVABLE', 'IN_LIMBO', 'IN_LIMBO_PD',
            'IN_TRANSIT', 'IN_TRANSIT_PD']
WQT = ['INVALID', 'QUEUE', 'TURNSTILE', 'PORT', 'SELECT', 'PORT_SET', 'SELECT_SET']
TS_TYPE = ['NONE', 'KERNEL_MUTEX', 'ULOCK', 'PTHREAD_MUTEX', 'SYNC_IPC', 'WORKLOOPS',
           'WORKQS', 'KNOTE', 'SLEEP_INHERITOR', 'EPOCH_KERNEL', 'EPOCH_USER', 'THREADPAIR']
# xnu osfmk/ipc/ipc_port.h PORT_SYNC_LINK_*; 1 is written by the pinned
# ipc_port_link_special_reply_port and 4/2/3 are the values compared in
# ipc_port_adjust_special_reply_port_locked (KDK 0xfffffe0007357a90/ad8..aec).
SYNC_LINK = ['ANY', 'PORT', 'WORKLOOP_KNOTE', 'WORKLOOP_STASH', 'RCV_THREAD', 'NO_LINKAGE']
BLOCK_HINT = ['None', 'KernelMutex', 'PortReceive', 'PortSetReceive', 'PortSend',
              'PortSendInTransit', 'Semaphore', 'KernelRWLockRead', 'KernelRWLockWrite',
              'KernelRWLockUpgrade', 'UserLock', 'PThreadMutex', 'PThreadRWLockRead',
              'PThreadRWLockWrite', 'PThreadCondVar', 'ParkedWorkQueue', 'WorkloopSyncWait',
              'OnProcess', 'SleepWithInheritor', 'Eventlink', 'Compressor',
              'ParkedBoundWorkQueue', 'PageBusy', 'PLReqInProgress', 'PagerReady',
              'PagingActivity', 'MappingInProgress', 'MemoryBlocked', 'PagingInProgress',
              'PageInThrottle', 'ExclaveCore', 'ExclaveKit', 'VMEntryExclEvent',
              'VMEntrySharedEvent', 'VMEntryKUnwireEvent', 'Threadpair']
RIGHT_BITS = ((0x10000, 'send'), (0x20000, 'receive'), (0x40000, 'send_once'),
              (0x80000, 'port_set'), (0x100000, 'dead_name'))
PORT_FLAG_BITS = ((5, 'fullwaiters'), (6, 'sprequests'), (7, 'spimportant'), (8, 'impdonation'),
                  (9, 'tempowner'), (10, 'guarded'), (11, 'strict_guard'),
                  (15, 'sync_bootstrap_checkin'), (16, 'tg_block_tracking'),
                  (17, 'has_watchport'), (23, 'srp_lost_link'), (24, 'srp_msg_sent'),
                  (25, 'enforce_reply_semantics'))
KERNEL_LOW = 0xfffffe0000000000


def name_of(table, index):
    return table[index] if 0 <= index < len(table) else f'unknown({index})'


def strip(value):
    """Clear a kernel pointer's PAC bits for lookup (bits 47..63); bit 46 is kept."""
    return value | 0xffff800000000000 if value else 0


def kptr(value, what='pointer', alignment=8):
    if not KERNEL_LOW <= value < 0xfffffffffffff000 or value % alignment:
        raise ValueError(f'{what} {value:#x} is not an aligned kernel pointer')
    return value


def decode_table(raw):
    """kalloc-array pointer (after PAC strip) -> (entry base, byte size), per ipc_entry_lookup."""
    if raw & (1 << 46):
        return raw & ~0x1f, (0x20 | (raw & 0x10)) << (raw & 0xf)
    return (raw & ~0x3fff) | (1 << 46), (raw & 0x3fff) << 14


def rights(bits):
    return [n for b, n in RIGHT_BITS if bits & b]


class Graph:
    """Read-only IPC decoder over a bounded kernel virtual-memory reader."""

    def __init__(self, read, processes, *, space_kernel=0, space_reply=0, max_hops=8):
        self._read = read
        self.processes = processes
        self.space_kernel, self.space_reply = space_kernel, space_reply
        self.max_hops = max_hops
        self.by_task = {int(p['task'], 16): p for p in processes if p.get('task_present')}
        self.by_thread = {}
        for p in processes:
            for t in p.get('threads', []):
                self.by_thread[int(t['thread'], 16)] = (p, t)
        self.srp_owner = {}  # SRP -> (pid, tid), filled by thread decoding
        self.kernel_vas = set()

    def read(self, va, size):
        raw = self._read(va, size)
        if len(raw) != size:
            raise ValueError(f'short read at {va:#x}')
        return raw

    def q(self, va):
        return struct.unpack('<Q', self.read(va, 8))[0]

    def u32(self, va):
        return struct.unpack('<I', self.read(va, 4))[0]

    def cstr(self, va, limit=128):
        out = b''
        while len(out) < limit:
            take = min(limit-len(out), 0x40-(va+len(out)) % 0x40)
            chunk = self.read(va+len(out), take)
            if b'\0' in chunk:
                return (out+chunk.split(b'\0', 1)[0]).decode('utf-8', 'replace')
            out += chunk
        return out.decode('utf-8', 'replace')+'...'

    # -- identities ----------------------------------------------------------------
    def proc_identity(self, proc, task=None):
        proc = kptr(proc, 'proc')
        pid = struct.unpack('<i', self.read(proc+L['proc_pid'], 4))[0]
        comm = self.read(proc+L['proc_comm'], 17).split(b'\0', 1)[0].decode('utf-8', 'replace')
        row = dict(proc=hex(proc), pid=pid, name=comm)
        ro = strip(self.q(proc+L['proc_ro']))
        if ro:
            pr_proc, pr_task = struct.unpack('<2Q', self.read(ro+L['proc_ro_pr_proc'], 16))
            row['proc_ro'] = hex(ro)
            row['proc_ro_reciprocal'] = strip(pr_proc) == proc and (task is None or strip(pr_task) == task)
        return row

    def task_identity(self, task):
        task = kptr(task, 'task')
        p = self.by_task.get(task)
        if p is not None:
            return dict(task=hex(task), pid=p['pid'], name=p['name'], source='inventory')
        row = dict(task=hex(task), source='task-0x7c0 proc, not in captured inventory')
        try:
            row.update(self.proc_identity(task-L['proc_size'], task))
        except ValueError as error:
            row['error'] = str(error)
        return row

    def thread_identity(self, thread):
        thread = kptr(thread, 'thread')
        tro = strip(self.q(thread+L['thread_t_tro']))
        owner, = struct.unpack('<Q', self.read(tro+L['tro_owner'], 8))
        if strip(owner) != thread:
            raise ValueError(f'thread {thread:#x}: thread_ro owner differs (not a thread)')
        proc, = struct.unpack('<Q', self.read(tro+L['tro_proc'], 8))
        task, = struct.unpack('<Q', self.read(tro+L['tro_task'], 8))
        tid = self.q(thread+L['thread_id'])
        row = dict(thread=hex(thread), tid=tid, task=hex(strip(task)))
        known = self.by_thread.get(thread)
        if known:
            row.update(pid=known[0]['pid'], name=known[0]['name'])
        elif proc:
            try:
                ident = self.proc_identity(strip(proc), strip(task))
                row.update(pid=ident['pid'], name=ident['name'])
            except ValueError as error:
                row['identity_error'] = str(error)
        else:
            row.update(pid=0, name='kernel_task')
        return row

    # -- spaces and entries -------------------------------------------------------
    def space_of(self, task):
        space = strip(self.q(task+L['task_itk_space']))
        kptr(space, 'itk_space')
        if strip(self.q(space+L['space_is_task'])) != task:
            raise ValueError('task->itk_space->is_task reciprocal link differs')
        return space

    def table(self, space):
        raw = self.q(space+L['space_is_table'])
        if not raw:
            raise ValueError('space has no entry table (inactive)')
        base, size = decode_table(strip(raw))
        kptr(base, 'is_table base')
        if not 0x18 <= size <= 0x18 << 20:
            raise ValueError(f'implausible is_table size {size:#x}')
        return dict(raw=hex(raw), base=hex(base), bytes=size, count=size//0x18)

    def lookup(self, space, name):
        table = self.table(space)
        index = name >> 8
        if not index or (index+1)*0x18 > table['bytes']:
            raise ValueError(f'name {name:#x} index outside is_table ({table["count"]} entries)')
        entry = int(table['base'], 16)+index*0x18
        raw = self.read(entry, 0x18)
        obj, bits = struct.unpack_from('<QI', raw)
        row = dict(name=hex(name), index=index, entry=hex(entry), bits=hex(bits),
                   rights=rights(bits), urefs=bits & 0xffff, object=hex(strip(obj)), table=table)
        if ((bits & 0xfc000000) | 0x03000000) != (name << 24) & 0xffffffff:
            row['error'] = 'generation differs: stale name (ipc_entry_lookup would return NULL)'
        elif not bits & 0x1f0000:
            row['error'] = 'entry type is MACH_PORT_TYPE_NONE (free slot)'
        return row

    def entries(self, space, limit=8192):
        table = self.table(space)
        base, count = int(table['base'], 16), min(table['count'], limit)
        out = []
        for start in range(1, count, 512):
            n = min(512, count-start)
            raw = self.read(base+start*0x18, n*0x18)
            for i in range(n):
                obj, bits = struct.unpack_from('<QI', raw, i*0x18)
                if bits & 0x1f0000 and obj:
                    gen = (bits >> 24) & 0xfc
                    out.append(((start+i) << 8 | gen | 3, bits, strip(obj)))
        return table, out

    # -- objects -------------------------------------------------------------------
    def label(self, obj, io_type):
        raw = self.q(obj+L['obj_label'])
        row = dict(label=hex(raw))
        if io_type in (2, 4) and raw:
            lbl = kptr(strip(raw), 'service label')
            row['service_domain'] = self.read(lbl+L['ispl_domain'], 1)[0]
            ptr = self.q(lbl+L['ispl_name'])
            row['service_name'] = self.cstr(strip(ptr)) if ptr else None
        elif io_type == 3 and raw:
            lbl = kptr(strip(raw), 'bootstrap label')
            ptr = self.q(lbl+L['ibpl_name'])
            row['service_name'] = self.cstr(strip(ptr)) if ptr else None
        return row

    def port(self, port, depth=0, seen=None):
        """Decode one port; follow its receiver, sync linkage and turnstile (bounded)."""
        seen = set() if seen is None else seen
        port = kptr(port, 'port')
        raw = self.read(port, L['port_size'])
        io_type, state = raw[0], raw[1] & 7
        wq, = struct.unpack_from('<I', raw, 0x10)
        g = lambda off: struct.unpack_from('<Q', raw, off)[0]
        row = dict(port=hex(port), io_type=name_of(IOT, io_type), io_type_raw=io_type,
                   io_state=name_of(IO_STATE, state), header_hex=raw[:0x20].hex())
        if io_type == 0:
            row['pset'] = True
            return row
        row['waitq_type'] = name_of(WQT, wq & 7)
        if wq & 7 != 3:
            row['error'] = 'port waitq is not WQT_PORT'
            return row
        row['flags'] = [n for b, n in PORT_FLAG_BITS if wq >> b & 1]
        row.update(receiver_name=hex(struct.unpack_from('<I', raw, 0x34)[0]),
                   seqno=struct.unpack_from('<I', raw, 0x30)[0],
                   msgcount=struct.unpack_from('<H', raw, 0x38)[0],
                   qlimit=struct.unpack_from('<H', raw, 0x3a)[0],
                   context=hex(g(0x78)),
                   mscount=struct.unpack_from('<I', raw, 0x84)[0],
                   srights=struct.unpack_from('<I', raw, 0x88)[0],
                   sorights=struct.unpack_from('<I', raw, 0x8c)[0])
        if io_type >= 13:
            row['kobject'] = hex(g(0x50))
        try:
            row.update(self.label(port, io_type))
        except ValueError as error:
            row['label_error'] = str(error)
        if port in seen or depth > self.max_hops:
            row['truncated'] = 'cycle or hop bound'
            return row
        seen.add(port)
        u48 = strip(g(0x48))
        if state in (1, 2):
            if u48 and u48 == self.space_kernel:
                row['receiver'] = dict(kernel=True, space=hex(u48))
            elif u48 and u48 == self.space_reply:
                row['receiver'] = dict(kernel=True, space=hex(u48), reply_space=True)
            elif u48:
                try:
                    task = strip(self.q(u48+L['space_is_task']))
                    rec = self.task_identity(task)
                    rec['space'] = hex(u48)
                    rec['task_space_reciprocal'] = strip(self.q(task+L['task_itk_space'])) == u48
                    row['receiver'] = rec
                except ValueError as error:
                    row['receiver_error'] = str(error)
        elif state in (5, 6) and u48:
            row['in_transit_destination'] = self._safe(self.port, u48, depth+1, seen)
        if io_type == 11:
            link = (wq >> 12) & 7
            srp = dict(sync_link_state=name_of(SYNC_LINK, link),
                       owner_thread_raw=hex(g(0x40)), inheritor_raw=hex(g(0x58)))
            owner = strip(g(0x40))
            if owner:
                srp['owner_thread'] = self._safe(self.thread_identity, owner)
            target = strip(g(0x58))
            if link == 1 and target:
                srp['destination'] = self._safe(self.port, target, depth+1, seen)
            elif link == 3 and target:
                srp['stashed_turnstile'] = self._safe(self.turnstile, target, depth+1)
            elif link == 2 and target:
                srp['knote'] = hex(target)
            row['special_reply'] = srp
        rcv_ts = g(0x18)
        if rcv_ts:
            row['receive_turnstile'] = self._safe(self.turnstile, strip(rcv_ts), depth+1)
        if row['msgcount']:
            row['messages'] = self._safe(self.messages, port, row['msgcount'])
        return row

    def messages(self, port, count, limit=4):
        head = self.q(port+L['port_messages'])
        out, kmsg = [], strip(head)
        for _ in range(min(count, limit)):
            kptr(kmsg, 'kmsg')
            kind = self.read(kmsg+L['kmsg_type_byte'], 1)[0] >> 6
            header = kmsg+L['kmsg_inline'] if kind in (0, 1) else strip(self.q(kmsg+L['kmsg_kdata']))
            bits, size, remote, local, voucher, msgid = struct.unpack('<2I2Q2I', self.read(header, 0x20))
            row = dict(kmsg=hex(kmsg), ikm_type=kind, msgh_bits=hex(bits), msgh_size=size,
                       remote_port=hex(strip(remote)), local_port=hex(strip(local)),
                       voucher=hex(voucher), msgh_id=msgid, msgh_id_hex=hex(msgid & 0xffffffff))
            owner = self.srp_owner.get(strip(local))
            if owner:
                row['reply_port_owner'] = owner
            out.append(row)
            kmsg = strip(self.q(kmsg))
            if kmsg == strip(head):
                break
        return out

    def turnstile(self, ts, depth=0):
        chain = []
        seen = set()
        while ts and len(chain) <= self.max_hops:
            kptr(ts, 'turnstile')
            if ts in seen:
                chain.append(dict(turnstile=hex(ts), cycle=True))
                break
            seen.add(ts)
            raw = self.read(ts, L['ts_size'])
            g = lambda off: struct.unpack_from('<Q', raw, off)[0]
            inheritor, proprietor = g(0x10), g(0x48)
            ttype = struct.unpack_from('<I', raw, 0x54)[0] & 0xff
            flags = raw[0x5c]
            row = dict(turnstile=hex(ts), type=name_of(TS_TYPE, ttype),
                       waitq_type=name_of(WQT, struct.unpack_from('<I', raw, 0)[0] & 7),
                       inheritor=hex(inheritor), inheritor_flags=hex(flags),
                       proprietor=hex(proprietor), priority=raw[0x5d],
                       prim_count=struct.unpack_from('<I', raw, 0x58)[0])
            prop = strip(proprietor)
            if prop and ttype == 4:
                try:
                    kptr(prop, 'port proprietor')
                    rcv, send = self.q(prop+L['port_waitq_ts']), self.q(prop+L['port_send_turnstile'])
                    row['proprietor_port'] = dict(port=hex(prop),
                        role='receive' if strip(rcv) == ts else 'send' if strip(send) == ts else None,
                        receiver_name=hex(self.u32(prop+L['port_receiver_name'])),
                        io_type=name_of(IOT, self.read(prop, 1)[0]))
                    if row['proprietor_port']['role']:
                        state = self.read(prop+1, 1)[0] & 7
                        space = strip(self.q(prop+L['port_receiver']))
                        if state in (1, 2) and space and space not in (self.space_kernel, self.space_reply):
                            row['proprietor_port']['receiver'] = self.task_identity(
                                strip(self.q(space+L['space_is_task'])))
                except ValueError as error:
                    row['proprietor_error'] = str(error)
            elif prop and ttype == 5:
                try:
                    kptr(prop, 'kqworkloop')
                    wl = self.read(prop, 0x108)
                    wg = lambda off: struct.unpack_from('<Q', wl, off)[0]
                    kq = dict(kqworkloop=hex(prop), dynamicid=hex(wg(0xe8)),
                              reciprocal=strip(wg(0xe0)) == ts, owner_raw=hex(wg(0xd0)))
                    if wg(0x18):
                        kq['process'] = self.proc_identity(strip(wg(0x18)))
                    if wg(0xd0):
                        kq['owner'] = self._safe(self.thread_identity, strip(wg(0xd0)))
                    row['proprietor_workloop'] = kq
                except ValueError as error:
                    row['proprietor_error'] = str(error)
            chain.append(row)
            if flags & 4 and inheritor:
                row['inheritor_thread'] = self._safe(self.thread_identity, strip(inheritor))
                break
            if flags & 0x40:
                row['inheritor_is'] = 'workq (thread request, no thread bound yet)'
                break
            if flags & 8 and inheritor:
                ts = strip(inheritor)
                continue
            break
        return chain

    def _safe(self, fn, *args):
        try:
            return fn(*args)
        except ValueError as error:
            return dict(error=str(error))

    # -- threads -------------------------------------------------------------------
    def thread_wait(self, thread, follow=True):
        thread = kptr(thread, 'thread')
        raw = self.read(thread, L['thread_size'])
        g = lambda off: struct.unpack_from('<Q', raw, off)[0]
        waitq = g(0x28)
        cont = g(0xe0)
        self.kernel_vas.add(strip(cont))
        row = dict(thread=hex(thread), tid=g(0x510), wait_event=hex(g(0x18)), waitq=hex(waitq),
                   continuation=hex(cont), in_receive_continue=cont == RECEIVE_CONTINUE,
                   pending_block_hint=name_of(BLOCK_HINT, raw[0x58d]),
                   block_hint=name_of(BLOCK_HINT, raw[0x58e]),
                   ith_option=hex(g(0x390)), ith_object=hex(g(0x398)),
                   ith_recv_msg_addr=hex(g(0x378)),
                   ith_receiver_name=hex(struct.unpack_from('<I', raw, 0x3b0)[0]),
                   special_reply_port=hex(strip(g(0x450))), turnstile=hex(g(0x30)),
                   inheritor=hex(g(0x38)))
        srp = strip(g(0x450))
        if srp and thread in self.by_thread:
            p, t = self.by_thread[thread]
            self.srp_owner[srp] = dict(pid=p['pid'], name=p['name'], tid=t['tid'])
        if not waitq:
            return row
        try:
            wtype = self.u32(waitq) & 7
        except ValueError as error:
            row['waitq_error'] = str(error)
            return row
        row['waitq_type'] = name_of(WQT, wtype)
        if not follow:
            if wtype == 3:
                port = waitq-L['port_waitq']
                row['waiting_on_port'] = hex(port)
                try:
                    row['waiting_on_port_type'] = name_of(IOT, self.read(port, 1)[0])
                    row['waiting_on_port_name'] = hex(self.u32(port+L['port_receiver_name']))
                    lbl = self.label(port, self.read(port, 1)[0])
                    if lbl.get('service_name'):
                        row['waiting_on_service'] = lbl['service_name']
                except ValueError as error:
                    row['waiting_on_port_error'] = str(error)
            return row
        if wtype == 3:
            row['port'] = self._safe(self.port, waitq-L['port_waitq'])
        elif wtype == 5:
            row['port_set'] = hex(waitq-L['pset_wqset'])
        elif wtype == 2:
            row['turnstile_chain'] = self._safe(self.turnstile, waitq)
        return row


def owner_answer(wait):
    """Collapse a decoded wait into 'who owes the reply' (pid/name/thread) where proven."""
    port = wait.get('port') or {}
    srp = port.get('special_reply') or {}
    dest = srp.get('destination') or {}
    answer = {}
    if dest.get('receiver'):
        answer['destination_port'] = dest['port']
        answer['destination_receiver'] = dest['receiver']
        if dest.get('service_name'):
            answer['destination_service'] = dest['service_name']
        answer['destination_queue'] = dict(msgcount=dest.get('msgcount'), qlimit=dest.get('qlimit'))
        if dest.get('messages'):
            answer['queued_request_ids'] = [m['msgh_id_hex'] for m in dest['messages']]
    for chain in (port.get('receive_turnstile'), srp.get('stashed_turnstile')):
        if isinstance(chain, list):
            for hop in chain:
                if hop.get('inheritor_thread'):
                    answer['servicing_thread'] = hop['inheritor_thread']
                if hop.get('proprietor_workloop', {}).get('process'):
                    answer['servicing_workloop'] = hop['proprietor_workloop']
    return answer


def candidate_names(state):
    """Mach port names the saved EL0 registers of mach_msg/mach_msg2 can carry."""
    regs = {int(k): int(v, 16) for k, v in (state or {}).get('registers', {}).items()}
    out = {}
    def add(value, source):
        if 0 < value < 0xffffffff and value >> 8:
            out[value] = out[value]+'; '+source if value in out else source
    # mach_msg2_trap: x3 = remote|local<<32, x5 = desc_count|rcv_name<<32
    add(regs.get(3, 0) & 0xffffffff, 'x3 low: remote / sync-wait destination')
    add(regs.get(3, 0) >> 32, 'x3 high: local (reply)')
    add(regs.get(5, 0) >> 32, 'x5 high: receive name')
    add(regs.get(14, 0) & 0xffffffff, 'x14 low (callee copy)')
    add(regs.get(23, 0) & 0xffffffff, 'x23 low (callee copy)')
    return list(out.items())


def user_frames(read_user, fp, limit=64, max_gap=0x100000):
    """Frame-pointer chain like tools/user-frame-chain.py, but admitting parent gaps up to
    1 MiB: libdispatch's _dispatch_mach_send_and_wait_for_reply keeps a >16 KiB reply buffer
    on its stack, which is exactly where the shared walker's 0x4000 gap bound stopped."""
    rows, reason = [], 'frame limit'
    for _ in range(limit):
        if not 0 < fp < (1 << 47)-16 or fp & 15:
            reason = 'non-user or unaligned frame pointer'
            break
        try:
            previous, lr = struct.unpack('<2Q', read_user(fp, 16))
        except ValueError as error:
            reason = str(error)
            break
        pc = lr & ((1 << 47)-1)
        row = dict(fp=hex(fp), previous_fp=hex(previous), raw_lr=hex(lr), lookup_pc=hex(pc),
                   return_address_authenticated=False)
        if 4 <= pc and not pc & 3:
            try:
                size = min(64, 0x4000-((pc-4) & 0x3fff))
                row['return_site_va'] = hex(pc-4)
                row['return_site_hex'] = read_user(pc-4, size).hex()
            except ValueError as error:
                row['return_site_error'] = str(error)
        rows.append(row)
        if not previous:
            reason = 'null parent'
            break
        if previous <= fp or previous-fp > max_gap:
            reason = 'non-monotonic or distant parent'
            break
        fp = previous
    return dict(frames=rows, end=reason,
                boundary='ABI frame candidates; PAC stripped for lookup, not authenticated')


def collect(processes, read, instruction, *, focus=('WindowServer', 'loginwindow'),
            targets=(), table_for=('WindowServer',), scan=True, read_user_for=None,
            symbolize=None, max_hops=8):
    for label, kdk_va, word in WITNESSES:
        if instruction(kdk_va+TEXT_EXEC_DELTA) != word:
            raise ValueError(f'port-receiver witness differs: {label}')
    space_kernel = strip(struct.unpack('<Q', read(IPC_SPACE_KERNEL, 8))[0])
    space_reply = strip(struct.unpack('<Q', read(IPC_SPACE_REPLY, 8))[0])
    gr = Graph(read, processes, space_kernel=space_kernel, space_reply=space_reply,
               max_hops=max_hops)
    by_name = {}
    for p in processes:
        by_name.setdefault(p['name'], []).append(p)
    result = dict(space_kernel=hex(space_kernel), space_reply=hex(space_reply),
                  focus=[], targets=[], pending_sync_replies=[], blocked_sends=[],
                  wait_census={}, tables=[], receivers={})
    # Pre-register every thread's special reply port so queued requests can be attributed.
    all_waits = {}
    for p in processes:
        for t in p.get('threads', []):
            try:
                all_waits[int(t['thread'], 16)] = gr.thread_wait(int(t['thread'], 16), follow=False)
            except ValueError as error:
                all_waits[int(t['thread'], 16)] = dict(error=str(error))
    receivers = set()

    def note(obj):
        if isinstance(obj, dict):
            if 'pid' in obj and 'task' in obj and isinstance(obj.get('pid'), int):
                receivers.add(obj['pid'])
            for v in obj.values():
                note(v)
        elif isinstance(obj, list):
            for v in obj:
                note(v)

    def resolve(p, name, source):
        row = dict(pid=p['pid'], process=p['name'], name=hex(name), source=source)
        try:
            space = gr.space_of(int(p['task'], 16))
            row['space'] = hex(space)
            entry = gr.lookup(space, name)
            row['entry'] = entry
            if 'error' not in entry and ('send' in entry['rights'] or 'receive' in entry['rights']
                                         or 'send_once' in entry['rights']):
                row['port'] = gr._safe(gr.port, int(entry['object'], 16))
        except ValueError as error:
            row['error'] = str(error)
        note(row)
        return row

    for pname in focus:
        for p in by_name.get(pname, []):
            if not p.get('task_present'):
                continue
            prow = dict(pid=p['pid'], name=p['name'], threads=[])
            for t in p.get('threads', []):
                thread = int(t['thread'], 16)
                trow = dict(tid=t['tid'], saved_user_pc=(t.get('saved_user_state') or {}).get('pc'))
                trow['wait'] = gr._safe(gr.thread_wait, thread)
                trow['answer'] = owner_answer(trow['wait'])
                note(trow)
                names = candidate_names(t.get('saved_user_state'))
                trow['register_names'] = [resolve(p, n, s) for n, s in names]
                state = t.get('saved_user_state')
                if read_user_for and state:
                    try:
                        read_user = read_user_for(p)
                        buf = int(state['registers']['0'], 16)
                        hdr = read_user(buf, 0x18)
                        bits, size, remote, local, voucher, msgid = struct.unpack('<6I', hdr)
                        trow['user_message_buffer'] = dict(address=hex(buf), msgh_bits=hex(bits),
                            msgh_size=size, remote_name=hex(remote), local_name=hex(local),
                            voucher_name=hex(voucher), msgh_id=msgid, msgh_id_hex=hex(msgid),
                            boundary='x0 is the RECEIVE buffer as of the stop. In libdispatch '
                                     '_dispatch_mach_send_and_wait_for_reply (host 26A428 '
                                     '0x1806e7ce0..0x1806e7d50) it is a fresh alloca on the stack, '
                                     'not the sent request: its msgh_id is NOT the request id. '
                                     'Use destination queued_request_ids instead.')
                    except (ValueError, KeyError) as error:
                        trow['user_message_buffer_error'] = str(error)
                prow['threads'].append(trow)
            result['focus'].append(prow)
    for pid, name in targets:
        for p in processes:
            if p['pid'] == pid and p.get('task_present'):
                result['targets'].append(resolve(p, name, 'requested'))
    if scan:
        census = {}
        for p in processes:
            for t in p.get('threads', []):
                w = all_waits.get(int(t['thread'], 16), {})
                key = f"{w.get('waitq_type', 'none')}/{w.get('pending_block_hint', '?')}"
                census[key] = census.get(key, 0)+1
                if w.get('waitq_type') != 'PORT':
                    continue
                port_type = w.get('waiting_on_port_type')
                if port_type == 'SPECIAL_REPLY_PORT' and p['name'] not in focus:
                    full = gr._safe(gr.thread_wait, int(t['thread'], 16))
                    srp = (full.get('port') or {}).get('special_reply') or {}
                    if srp.get('sync_link_state') not in (None, 'ANY', 'NO_LINKAGE'):
                        row = dict(pid=p['pid'], name=p['name'], tid=t['tid'], wait=full,
                                   answer=owner_answer(full))
                        note(row)
                        result['pending_sync_replies'].append(row)
                elif w.get('pending_block_hint') in ('PortSend', 'PortSendInTransit'):
                    full = gr._safe(gr.thread_wait, int(t['thread'], 16))
                    row = dict(pid=p['pid'], name=p['name'], tid=t['tid'], wait=full)
                    note(row)
                    result['blocked_sends'].append(row)
        result['wait_census'] = census
    for pname in table_for:
        for p in by_name.get(pname, []):
            if not p.get('task_present'):
                continue
            trow = dict(pid=p['pid'], name=p['name'])
            try:
                space = gr.space_of(int(p['task'], 16))
                table, ents = gr.entries(space)
                trow['table'] = table
                rows, by_receiver = [], {}
                for name, bits, obj in ents:
                    r = rights(bits)
                    item = dict(name=hex(name), rights=r, urefs=bits & 0xffff, object=hex(obj))
                    if 'port_set' in r or 'dead_name' in r:
                        rows.append(item)
                        continue
                    try:
                        raw = gr.read(obj, 0x50)
                        item['io_type'] = name_of(IOT, raw[0])
                        item['io_state'] = name_of(IO_STATE, raw[1] & 7)
                        item['msgcount'] = struct.unpack_from('<H', raw, 0x38)[0]
                        lbl = gr.label(obj, raw[0])
                        if lbl.get('service_name'):
                            item['service_name'] = lbl['service_name']
                        space_ptr = strip(struct.unpack_from('<Q', raw, 0x48)[0])
                        if raw[1] & 7 in (1, 2) and space_ptr:
                            if space_ptr in (space_kernel, space_reply):
                                who = 'kernel'
                            else:
                                ident = gr.task_identity(strip(gr.q(space_ptr+L['space_is_task'])))
                                who = f"{ident.get('pid')}:{ident.get('name')}"
                            item['receiver'] = who
                            if 'receive' not in r:
                                agg = by_receiver.setdefault(who, dict(send=0, send_once=0, services=set()))
                                agg['send'] += 'send' in r
                                agg['send_once'] += 'send_once' in r
                                if item.get('service_name'):
                                    agg['services'].add(item['service_name'])
                    except ValueError as error:
                        item['error'] = str(error)
                    rows.append(item)
                trow['by_receiver'] = {k: dict(send=v['send'], send_once=v['send_once'],
                                               services=sorted(v['services']))
                                       for k, v in sorted(by_receiver.items())}
                trow['entries'] = rows
            except ValueError as error:
                trow['error'] = str(error)
            result['tables'].append(trow)
    for pid in sorted(receivers):
        for p in processes:
            if p['pid'] != pid:
                continue
            rows = []
            for t in p.get('threads', []):
                w = dict(all_waits.get(int(t['thread'], 16), {}))
                w['saved_user_pc'] = (t.get('saved_user_state') or {}).get('pc')
                w['kernel_frames'] = [f.get('raw_lr') for f in t.get('frames', [])][:12]
                for f in t.get('frames', [])[:12]:
                    gr.kernel_vas.add(strip(int(f['raw_lr'], 16)))
                rows.append(w)
            result['receivers'][str(pid)] = dict(name=p['name'], threads=rows)
    if symbolize:
        try:
            result['kernel_symbols'] = symbolize(sorted(v for v in gr.kernel_vas if v))
        except Exception as error:  # symbolication is advisory only
            result['kernel_symbols_error'] = str(error)
    result['boundary'] = ('Stopped-state, read-only IPC decode. PAC stripped for lookup, not '
                          'authenticated. A receiver identity, queued message or turnstile '
                          'inheritor is not by itself proof of deadlock; the receiver threads '
                          'section says what that process was doing at the stop.')
    return result


# -- offline verification -------------------------------------------------------------
def kernel_images():
    xref = runpy.run_path(str(ROOT/'tools/kc-xref.py'))
    sym = runpy.run_path(str(ROOT/'tools/kc-symbolicate.py'))
    kc = xref['Kernelcache'](sym['KERNELCACHE'])
    if hashlib.sha256(kc.data).hexdigest() != KERNEL_SHA:
        raise SystemExit('kernelcache identity differs')
    kdk = xref['Kernelcache'](KDK_KERNEL)
    return kc, kdk, sym


def check_witnesses():
    kc, kdk, sym = kernel_images()
    s = sym['Symbolicator']()   # refuses mismatching LC_UUIDs
    if (s.kc_segs['__TEXT_EXEC'][0]-s.kdk_segs['__TEXT_EXEC'][0] != TEXT_EXEC_DELTA or
            s.kc_segs['__DATA_CONST'][0]-s.kdk_segs['__DATA_CONST'][0] != DATA_CONST_DELTA):
        raise SystemExit('segment delta differs')
    bad = [(label, hex(va), hex(word), hex(kdk.u32(va)), hex(kc.u32(va+TEXT_EXEC_DELTA)))
           for label, va, word in WITNESSES
           if not kdk.u32(va) == kc.u32(va+TEXT_EXEC_DELTA) == word]
    if bad:
        raise SystemExit(f'witness mismatch: {bad}')
    # the two adrp targets resolve to the named globals in the kernelcache itself
    def adrp(va):
        w = kc.u32(va)
        imm = ((w >> 5) & 0x7ffff) << 2 | (w >> 29) & 3
        imm -= (imm & 1 << 20) << 1
        return (va & ~0xfff)+(imm << 12)
    if (adrp(0xfffffe0007358e28+TEXT_EXEC_DELTA)+0x838 != IPC_SPACE_KERNEL or
            adrp(0xfffffe0007358e70+TEXT_EXEC_DELTA)+0x18 != IPC_SPACE_REPLY):
        raise SystemExit('ipc_space_kernel/reply adrp targets differ')
    names = s.resolve([IPC_SPACE_KERNEL, IPC_SPACE_REPLY, RECEIVE_CONTINUE])
    need = ('ipc_space_kernel', 'ipc_space_reply', 'ipc_mqueue_receive_continue')
    if not all(n in line for n, line in zip(need, names)):
        raise SystemExit(f'KDK symbols differ: {names}')
    return len(WITNESSES), names


LLDB_DUMP = r'''
import lldb, json
def walk(t, base, out, depth):
    t = t.GetCanonicalType()
    for i in range(t.GetNumberOfFields()):
        f = t.GetFieldAtIndex(i)
        off = base + f.GetOffsetInBytes()
        if f.name: out.setdefault(f.name, []).append(off)
        c = f.GetType().GetCanonicalType()
        if depth < 4 and c.GetTypeClass() in (lldb.eTypeClassStruct, lldb.eTypeClassUnion) and (not f.name or c.GetByteSize() <= 0x100):
            walk(c, off, out, depth+1)
def __lldb_init_module(debugger, d):
    t = debugger.GetSelectedTarget(); res = {}
    for n in NAMES:
        tl = t.FindTypes(n); ty = None
        for j in range(tl.GetSize()):
            if tl.GetTypeAtIndex(j).GetByteSize() > 0: ty = tl.GetTypeAtIndex(j); break
        if ty is None: continue
        out = {}; walk(ty, 0, out, 0)
        res[n] = dict(size=ty.GetByteSize(), fields=out)
    print('DWARF_LAYOUT=' + json.dumps(res))
'''


def check_dwarf(scratch):
    names = sorted({t for _, t, *_ in DWARF_FIELDS} | set(DWARF_SIZES))
    script = Path(scratch)/'port_receiver_dwarf.py'
    script.write_text(LLDB_DUMP.replace('NAMES', repr(names)))
    out = subprocess.run(['xcrun', 'lldb', '-b', '-o', f'target create {KDK_KERNEL}',
                          '-o', f'command script import {script}', '-o', 'quit'],
                         capture_output=True, text=True, check=True).stdout
    rows = [s[len('DWARF_LAYOUT='):] for s in out.splitlines() if s.startswith('DWARF_LAYOUT=')]
    if len(rows) != 1:
        raise SystemExit('KDK DWARF layout unavailable')
    d = json.loads(rows[0])
    bad = []
    for key, tname, field, *base in DWARF_FIELDS:
        at = None
        if '@' in field:
            field, at = field.split('@')
            at = int(at, 16)
        offs = [o+(base[0] if base else 0) for o in d.get(tname, {}).get('fields', {}).get(field, [])]
        if L[key] not in offs or (at is not None and at not in offs):
            bad.append((key, tname, field, hex(L[key]), [hex(o) for o in offs]))
    for tname, size in DWARF_SIZES.items():
        if d.get(tname, {}).get('size') != size:
            bad.append((tname, 'size', hex(size), d.get(tname, {}).get('size')))
    if bad:
        raise SystemExit(f'DWARF layout mismatch: {bad}')
    return len(DWARF_FIELDS)+len(DWARF_SIZES)


class FakeMemory:
    """Sparse synthetic kernel memory for the offline decoder test."""

    def __init__(self):
        self.pages = {}

    def put(self, va, data):
        for i, b in enumerate(data):
            page = (va+i) & ~0x3fff
            self.pages.setdefault(page, bytearray(0x4000))[(va+i) & 0x3fff] = b

    def q(self, va, value):
        self.put(va, struct.pack('<Q', value))

    def read(self, va, size):
        out = bytearray()
        for i in range(size):
            page = self.pages.get((va+i) & ~0x3fff)
            if page is None:
                raise ValueError(f'unmapped guest RAM at {va+i:#x}')
            out.append(page[(va+i) & 0x3fff])
        return bytes(out)


def synthetic_test():
    """Decoder test over synthetic memory.

    Failure modes this must catch (written before the decoder):
      1. PAC bits left in a pointer -> reads land outside mapped memory.
      2. kalloc-array large form mis-decoded (bit 46 clear) -> wrong base/count.
      3. Entry generation ignored -> a stale name resolves to a reused slot.
      4. MACH_PORT_TYPE_NONE entry treated as a right.
      5. Receiver taken from ip_receiver while the port is IN_TRANSIT.
      6. task<->space reciprocity not checked -> wrong process attributed.
      7. SRP sync linkage state misread -> destination missed or invented.
      8. thread pointer accepted without thread_ro owner reciprocity.
      9. Turnstile inheritor chain cycles -> unbounded loop.
     10. Queued kmsg header read from the wrong place (inline vs kdata).
     11. Service label name missed for IOT_SERVICE_PORT.
    """
    m = FakeMemory()
    pac = lambda v, tag=0x5a: v & ~0xffff800000000000 | (tag << 56) | (0x3a << 48)  # PAC bits set
    ws_proc, srv_proc = 0xfffffe2000000000, 0xfffffe2000010000
    ws_task, srv_task = ws_proc+0x7c0, srv_proc+0x7c0
    ws_space, srv_space = 0xfffffe2000020000, 0xfffffe2000020100
    kspace, rspace = 0xfffffe2000020200, 0xfffffe2000020300
    ws_table = 0xfffffe2000030000        # large-form table: 0x2000 entries? keep 4 pages
    srv_table = 0xfffffe2000040000
    srp, dest, stale = 0xfffffe2000050000, 0xfffffe2000050100, 0xfffffe2000050200
    ws_thread, srv_thread = 0xfffffe2000060000, 0xfffffe2000061000
    ws_tro, srv_tro = 0xfffffe2000062000, 0xfffffe2000062100
    rcv_ts, wl_ts, wl = 0xfffffe2000070000, 0xfffffe2000070100, 0xfffffe2000070200
    label, sname = 0xfffffe2000080000, 0xfffffe2000080100
    kmsg = 0xfffffe2000090000
    for proc, task, pid, comm in ((ws_proc, ws_task, 164, b'WindowServer'), (srv_proc, srv_task, 99, b'opendirectoryd')):
        m.put(proc+0x60, struct.pack('<i', pid))
        m.put(proc+0x5bc, comm+b'\0')
        m.q(proc+0x18, 0)
    m.q(ws_task+0x318, pac(ws_space))
    m.q(srv_task+0x318, pac(srv_space))
    m.q(ws_space+0x50, pac(ws_task))
    m.q(srv_space+0x50, pac(srv_task))
    # WindowServer table in large kalloc form: 4 pages -> raw low bits 4, bit46 clear.
    m.q(ws_space+0x48, pac((ws_table & ~(1 << 46)) | 4))
    m.put(ws_table, bytes(4*0x4000))
    m.q(srv_space+0x48, pac(srv_table | (1 << 46) | 0x10 | 4))   # zone form: 0x30<<4 = 0x300 bytes
    def entry(table, name, obj, bits):
        e = table+(name >> 8)*0x18
        m.q(e, pac(obj))
        m.put(e+8, struct.pack('<I', bits | (name & 0xff) << 24))
    entry(ws_table, 0x903, srp, 0x20000 | 1)             # receive right on the SRP
    entry(ws_table, 0x3f03, dest, 0x10000 | 2)           # send right to the service
    entry(ws_table, 0x4007, stale, 0x10000 | 1)          # gen 0x07 stored; looked up as 0x4003
    entry(ws_table, 0x5003, stale, 0)                    # free slot
    entry(srv_table, 0x1103, dest, 0x20000)
    def port(p, io_type, state, wq, receiver, name, u58=0, u40=0, ts=0, msgcount=0, lbl=0, head=0):
        raw = bytearray(0x90)
        raw[0], raw[1] = io_type, state
        struct.pack_into('<Q', raw, 8, pac(lbl) if lbl else 0)
        struct.pack_into('<I', raw, 0x10, wq)
        struct.pack_into('<Q', raw, 0x18, ts)
        struct.pack_into('<Q', raw, 0x28, head)
        struct.pack_into('<I', raw, 0x34, name)
        struct.pack_into('<HH', raw, 0x38, msgcount, 5)
        struct.pack_into('<Q', raw, 0x40, u40)
        struct.pack_into('<Q', raw, 0x48, pac(receiver) if receiver else 0)
        struct.pack_into('<Q', raw, 0x58, pac(u58) if u58 else 0)
        m.put(p, bytes(raw))
    port(srp, 11, 1, 3 | 1 << 12 | 1 << 24, ws_space, 0x903, u58=dest, u40=pac(ws_thread), ts=rcv_ts)
    port(dest, 2, 1, 3, srv_space, 0x1103, msgcount=1, lbl=label, head=kmsg)
    port(stale, 1, 5, 3, dest, 0x4007)                  # IN_TRANSIT: 0x48 is a destination
    m.q(label+0x18, sname)
    m.put(label+0x15, b'\x02')
    m.put(sname, b'com.apple.opendirectoryd.api\0')
    m.q(kmsg, kmsg)                                        # single-element ring
    m.put(kmsg+0x3f, bytes([0x80]))                        # IKM_TYPE_KDATA_OOL -> kdata
    m.q(kmsg+0xe8, pac(kmsg+0x800))
    m.put(kmsg+0x800, struct.pack('<2I2Q2I', 0x1513, 0x48, dest, srp, 0, 0x10000000))
    # receive turnstile -> workloop turnstile -> cycle back (must terminate)
    for ts, inh, flags, ttype, prop in ((rcv_ts, wl_ts, 8, 4, srp), (wl_ts, rcv_ts, 8, 5, wl)):
        raw = bytearray(0x60)
        struct.pack_into('<I', raw, 0, 2)
        struct.pack_into('<Q', raw, 0x10, inh)
        struct.pack_into('<Q', raw, 0x48, prop)
        struct.pack_into('<I', raw, 0x54, ttype)
        raw[0x5c] = flags
        m.put(ts, bytes(raw))
    m.q(wl+0x18, srv_proc)
    m.q(wl+0xd0, srv_thread)
    m.q(wl+0xe0, wl_ts)
    m.q(wl+0xe8, 0x7777)
    m.put(wl+0x100, b'\0'*8)
    for th, tro, proc, task, tid in ((ws_thread, ws_tro, ws_proc, ws_task, 1101), (srv_thread, srv_tro, srv_proc, srv_task, 2000)):
        raw = bytearray(0x5f8)
        struct.pack_into('<Q', raw, 0x420, tro)
        struct.pack_into('<Q', raw, 0x510, tid)
        m.put(th, bytes(raw))
        m.q(tro, th)
        m.q(tro+0x18, proc)
        m.q(tro+0x28, task)
    wraw = bytearray(m.read(ws_thread, 0x5f8))
    struct.pack_into('<Q', wraw, 0x28, srp+0x10)
    struct.pack_into('<Q', wraw, 0xe0, RECEIVE_CONTINUE)
    struct.pack_into('<Q', wraw, 0x450, pac(srp))
    wraw[0x58d] = 2
    m.put(ws_thread, bytes(wraw))
    m.q(IPC_SPACE_KERNEL, kspace)
    m.q(IPC_SPACE_REPLY, rspace)
    processes = [
        dict(pid=164, name='WindowServer', proc=hex(ws_proc), task=hex(ws_task), task_present=True,
             threads=[dict(thread=hex(ws_thread), tid=1101, wait_event='0x0', frames=[],
                           saved_user_state=dict(pc='0x188018c20', registers={
                               '0': '0x16bdf1ab0', '3': '0x3f03', '5': '0x90300000000',
                               '14': '0x903', '23': '0x3f03'}))]),
        dict(pid=99, name='opendirectoryd', proc=hex(srv_proc), task=hex(srv_task), task_present=True,
             threads=[dict(thread=hex(srv_thread), tid=2000, wait_event='0x0', frames=[])])]
    words = {kdk+TEXT_EXEC_DELTA: w for _, kdk, w in WITNESSES}
    out = collect(processes, m.read, words.get, targets=[(164, 0x4003), (164, 0x5003), (164, 0x3f03)])
    ws = out['focus'][0]['threads'][0]
    ws.setdefault('wait', {}).setdefault('port', {}).setdefault('special_reply', {}).setdefault('destination', {}).setdefault('messages', [{}])
    ws['wait']['port']['special_reply'].setdefault('owner_thread', {})
    ans = ws['answer']
    checks = {
        'srp decoded': ws['wait']['port'].get('io_type') == 'SPECIAL_REPLY_PORT',
        'sync link PORT': ws['wait']['port']['special_reply'].get('sync_link_state') == 'PORT',
        'destination receiver (1,6,7)': ans.get('destination_receiver', {}).get('pid') == 99,
        'task/space reciprocal (6)': ans.get('destination_receiver', {}).get('task_space_reciprocal') is True,
        'service label (11)': ans.get('destination_service') == 'com.apple.opendirectoryd.api',
        'kdata kmsg header (10)': ans.get('queued_request_ids') == ['0x10000000'],
        'queued reply attributed': ws['wait']['port']['special_reply']['destination']['messages'][0]
                                   .get('reply_port_owner', {}).get('tid') == 1101,
        'workloop owner found, cycle bounded (8,9)': ans.get('servicing_workloop', {})
                                   .get('process', {}).get('pid') == 99,
        'srp owner thread (8)': ws['wait']['port']['special_reply']['owner_thread'].get('tid') == 1101,
        'register x3 -> 0x3f03': any(r['name'] == '0x3f03' and r.get('port', {}).get('receiver', {})
                                     .get('name') == 'opendirectoryd' for r in ws['register_names']),
        'large table decode (2)': ws['register_names'][0].get('entry', {}).get('table', {}).get('count') == 4*0x4000//0x18,
        'stale generation refused (3)': 'generation' in out['targets'][0].get('entry', {}).get('error', ''),
        'free slot refused (4)': 'error' in out['targets'][1].get('entry', {'error': 1}),
        'receiver section lists server threads': '99' in out['receivers'],
        'service table aggregate': out['tables'][0].get('by_receiver', {}).get('99:opendirectoryd', {})
                                   .get('services') == ['com.apple.opendirectoryd.api'],
    }
    # (5) in-transit port must not produce a receiver
    g = Graph(m.read, processes, space_kernel=kspace, space_reply=rspace)
    t = g.port(stale)
    checks['in-transit follows destination (5)'] = ('receiver' not in t and
        t['in_transit_destination'].get('receiver', {}).get('pid') == 99)
    # (8) a non-thread pointer must be refused
    try:
        g.thread_identity(dest)
        checks['non-thread refused (8)'] = False
    except ValueError:
        checks['non-thread refused (8)'] = True
    failed = [k for k, v in checks.items() if not v]
    if failed:
        raise SystemExit(f'synthetic decoder test failed: {failed}\n{json.dumps(ws, indent=1)[:4000]}')
    return len(checks)


# -- stopped-state capture --------------------------------------------------------------
def open_stopped(args):
    """Bounded read-only readers over the audited stopped guest (capture-kernel-waits pattern)."""
    sys.path.insert(0, str(ROOT/'probes'))
    import run
    import xnuboot as xb
    base = ROOT/'build'/args.prefix
    launch = json.loads(Path(f'{base}-launch.json').read_text())
    if launch.get('exit_code') != int(os.environ.get('SNAP_STOPPED_EXIT', '9')) or not launch.get('finished'):
        raise SystemExit('launch record is not a finished stopped exit')
    try:
        os.kill(launch['pid'], 0)
    except ProcessLookupError:
        pass
    else:
        raise SystemExit('guest launcher still exists')
    audit = json.loads(Path(f'{base}-audit.json').read_text())
    service = audit['service']
    owner = (service[1] & 0xffffffff)-1
    if service[1] >> 32 != 1 or not 0 <= owner < 6:
        raise SystemExit('requires an audited normal stop owner')
    stop = json.loads(Path(f'{base}-cpu{owner}-stop.json').read_text())
    if stop['cpu'] != owner or stop['snapshot_kind'] not in (1, 2, 3, 4):
        raise SystemExit('requires a terminal stop owner register snapshot')
    register_field = 'last_exc' if stop['snapshot_kind'] == 4 else 'async_regs'
    resident_kind = 0 if stop['snapshot_kind'] == 4 else stop['snapshot_kind']
    kernel = runpy.run_path(str(ROOT/'tools/kc-xref.py'))['Kernelcache'](xb.DEFAULT_KERNELCACHE)
    if hashlib.sha256(kernel.data).hexdigest() != KERNEL_SHA:
        raise SystemExit('kernel identity differs')
    layout = subprocess.run(['clang', '--target=aarch64-unknown-none-elf', '-ffreestanding',
        '-mgeneral-regs-only', '-Ishadow', '-Icompat', '-Xclang', '-fdump-record-layouts',
        '-fsyntax-only', 'probes/xnuboot.c'], cwd=ROOT, capture_output=True, text=True,
        check=True).stdout
    def record(kind):
        blocks = [b for b in layout.split('*** Dumping AST Record Layout')
                  if re.search(r'^\s*0 \| struct '+kind+r'\n', b)]
        if len(blocks) != 1:
            raise SystemExit(f'ambiguous monitor layout for {kind}')
        return blocks[0]
    def field(kind, name):
        found = re.findall(r'^\s*(\d+) \|   .+ '+name+r'$', record(kind), re.M)
        if len(found) != 1:
            raise SystemExit(f'ambiguous monitor field {kind}.{name}')
        return int(found[0])
    stride = int(re.findall(r'\[sizeof=(\d+),', record('vcpu'))[0])
    cpu_offset = field('context', 'vcpus')+owner*stride
    if args.device.startswith('/dev/'):
        sys.path.insert(0, str(ROOT.parent/'q1n1/tools'))
        import q1n1proxy
        cap = int(os.environ.get('SNAP_CDC_READ_CAP', '4096'))
        assert cap in (512, 1024, 2048, 4096)
        original = q1n1proxy.Proxy.readmem
        def bounded(self, address, size, live=False):
            if size <= cap:
                return original(self, address, size, live=live)
            return b''.join(original(self, address+i, min(cap, size-i), live=live)
                            for i in range(0, size, cap))
        q1n1proxy.Proxy.readmem = bounded
    proxy = run.connect(args.device, tries=1)
    info = proxy.bootinfo()
    work, _ = run.resident_work(proxy, info)
    def read(pa, size):
        if not 0 < size <= 0x200000:
            raise ValueError('invalid physical read size')
        return b''.join(proxy.readmem(pa+i, min(65536, size-i), live=True)
                        for i in range(0, size, 65536))
    monitor = (ROOT/'build/xnuboot.bin').read_bytes()
    if (hashlib.sha256(monitor).hexdigest() != audit['monitor_sha256'] or
            read(info['heap_base']+run.CODE_AT, len(monitor)) != monitor):
        raise SystemExit('resident monitor differs')
    services = struct.unpack('<8Q', read(work+field('context', 'services'), 64))
    kind, = struct.unpack('<Q', read(work+cpu_offset+field('vcpu', 'async_captured'), 8))
    acquired, = struct.unpack('<Q', read(work+cpu_offset+field('vcpu', 'service_acquires'), 8))
    owner_audit = next(r for r in audit['cpu_rows'] if r['slot'] == owner)
    if list(services) != service or kind != resident_kind or acquired != owner_audit['service_acquires']:
        raise SystemExit('resident owner state differs from audited stop')
    if stop['snapshot_kind'] == 4:
        # Same terminal-exception check as capture-kernel-waits.
        exceptions, = struct.unpack('<Q', read(work+cpu_offset+field('vcpu', 'exceptions'), 8))
        if not exceptions:
            raise SystemExit('terminal guest snapshot has no recorded exception')
    current =struct.unpack('<36Q', read(work+cpu_offset+field('vcpu', register_field), 288))
    if tuple(current[31:]) != tuple(int(stop[k], 16) for k in ('sp', 'pstate', 'pc', 'esr', 'far')) or any(
            current[i] != int(stop['registers'][str(i)], 16) for i in range(31)):
        raise SystemExit('resident stop differs')
    g = audit['geometry']
    params_pa, = struct.unpack('<Q', read(work+field('context', 'params'), 8))
    params = struct.unpack(f'<{xb.PARAMS_WORDS}Q', read(params_pa, xb.PARAMS_WORDS*8))
    if (params[0], params[30], params[31]) != (g['root'], g['ram_low'], g['ram_high']):
        raise SystemExit('resident geometry differs')
    pages = {}
    def ram(pa, size):
        if not g['ram_low'] <= pa < pa+size <= g['ram_high']:
            raise ValueError('read outside guest RAM')
        out = bytearray()
        while size:
            page, off = pa & ~0xfff, pa & 0xfff
            if page not in pages:
                if len(pages) >= args.page_budget:
                    raise ValueError('capture page budget exceeded')
                pages[page] = read(page, 4096)
            take = min(size, 4096-off)
            out += pages[page][off:off+take]
            pa += take
            size -= take
        return bytes(out)
    def va_read(va, size):
        if not 0 < size <= 0x4000:
            raise ValueError('invalid virtual read size')
        out = bytearray()
        while size:
            table = g['root']
            for shift in (36, 25, 14):
                desc, = struct.unpack('<Q', ram(table+8*((va >> shift) & 2047), 8))
                if desc & 3 != 3:
                    raise ValueError('unmapped guest RAM')
                table = desc & 0x0000ffffffffc000
            take = min(size, 0x4000-(va & 0x3fff))
            out += ram(table+(va & 0x3fff), take)
            va += take
            size -= take
        return bytes(out)
    def recheck():
        # Same stop identity as capture-kernel-waits' ownership recheck.
        if (struct.unpack('<8Q', read(work+field('context', 'services'), 64)) != services or
                struct.unpack('<36Q', read(work+cpu_offset+field('vcpu', register_field), 288)) != current or
                struct.unpack('<Q', read(work+cpu_offset+field('vcpu', 'async_captured'), 8))[0] != kind or
                struct.unpack('<Q', read(work+cpu_offset+field('vcpu', 'service_acquires'), 8))[0] != acquired or
                struct.unpack(f'<{xb.PARAMS_WORDS}Q', read(params_pa, xb.PARAMS_WORDS*8)) != params):
            raise SystemExit('resident stop changed during capture')
        if proxy.exceptions:
            raise SystemExit('proxy exception during capture')
    return dict(proxy=proxy, kernel=kernel, audit=audit, geometry=g, params=params, read=read,
                ram=ram, va_read=va_read, pages=pages, recheck=recheck)


def capture(args):
    s = open_stopped(args)
    kernel, va_read, audit, g = s['kernel'], s['va_read'], s['audit'], s['geometry']
    try:
        topology = runpy.run_path(str(ROOT/'tools/cpu-topology.py'))['collect'](
            va_read, s['ram'], kernel.u32, loader_bootargs_pa=int(audit['firmware']['bootargs_pa'], 16),
            result_area_va=s['params'][29])
        on_cpu = {int(c['thread'], 16) for c in topology['cpu_data_entries'] if c.get('thread')}
        if kernel.u32(0xfffffe000bec01c8) != 0xb9402020:
            raise SystemExit('native proc_ppid layout witness differs')
        user_state = runpy.run_path(str(ROOT/'tools/user-state.py'))['make_reader'](va_read, kernel.u32)
        describe = lambda value: dict(va=hex(value | 0xffff000000000000 if value else 0))
        inventory = runpy.run_path(str(ROOT/'tools/process-waits.py'))['collect'](
            va_read, describe, on_cpu, args.pid_limit, user_state=user_state)
        processes = inventory['processes']
        read_user_for = None
        user_memory_error = None
        bind = None
        if not args.no_user_memory:
            # A refused binding (e.g. --ownership-user-roots on an audit without a
            # complete ownership section) must not cost the kernel-side IPC answer.
            try:
                bind = runpy.run_path(str(ROOT/'tools/process-user-memory.py'))['make_reader'](
                    va_read, s['read'] if args.ownership_user_roots else s['ram'], kernel.u32,
                    audit['root_switch']['roots'], g['ram_low'], g['ram_high'],
                    ownership_audit=audit if args.ownership_user_roots else None)
            except (ValueError, KeyError) as error:
                user_memory_error = f'user memory binding refused: {error}'
        if bind is not None:
            cache = {}
            def read_user_for(p):
                if p['pid'] not in cache:
                    cache[p['pid']] = bind(int(p['task'], 16))[0]
                return cache[p['pid']]
            for p in processes:
                if p['name'] in args.focus and p.get('task_present'):
                    for t in p['threads']:
                        state = t.get('saved_user_state')
                        if state:
                            try:
                                t['user_frame_chain'] = user_frames(read_user_for(p), int(state['fp'], 16))
                                t['user_frame_chain']['saved_pc'] = state['pc']
                                t['user_frame_chain']['saved_pc_hex'] = read_user_for(p)(int(state['pc'], 16), 64).hex()
                            except ValueError as error:
                                t['user_frame_chain_error'] = str(error)
        # Symbolication is advisory: a missing KDK must not discard the capture.
        try:
            symbolizer = runpy.run_path(str(ROOT/'tools/kc-symbolicate.py'))['Symbolicator']()
            symbolize = lambda vas: dict(zip([hex(v) for v in vas], symbolizer.resolve(vas)))
        except (Exception, SystemExit) as error:
            symbolize = None
            symbolizer_error = f'kernel symbolizer unavailable: {error}'
        else:
            symbolizer_error = None
        targets = [(int(p), int(n, 16)) for p, n in (t.split(':') for t in args.target)]
        result = collect(processes, va_read, kernel.u32, focus=tuple(args.focus), targets=targets,
                         table_for=tuple(args.table_for), read_user_for=read_user_for,
                         symbolize=symbolize)
        result['user_frames'] = {str(p['pid']): {str(t['tid']): t.get('user_frame_chain') or
                                                 t.get('user_frame_chain_error')
                                                 for t in p['threads']}
                                 for p in processes if p['name'] in args.focus}
        if user_memory_error:
            result['user_memory_error'] = user_memory_error
        if symbolizer_error:
            result['kernel_symbols_error'] = symbolizer_error
        result['process_count'] = len(processes)
        result['process_names'] = {str(p['pid']): p['name'] for p in processes}
        s['recheck']()
    finally:
        s['proxy'].link.close()
    result.update(kernel_sha256=KERNEL_SHA, monitor_sha256=audit['monitor_sha256'],
                  prefix=args.prefix, pages_read=len(s['pages']),
                  witnesses=len(WITNESSES), layout=dict((k, hex(v)) for k, v in L.items()))
    return result


DSC = Path('/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e')


def symbolize_user(capture_path):
    """Offline: exact-byte match the captured user return sites against the host shared
    cache (same 26A428 build), then name each unslid site with ipsw a2s. Host-only."""
    capture = json.loads(Path(capture_path).read_text())
    resolver = runpy.run_path(str(ROOT/'tools/resolve-user-frame-sites.py'))['resolve']
    out = {}
    for pid, threads in capture.get('user_frames', {}).items():
        for tid, chain in threads.items():
            if not isinstance(chain, dict):
                continue
            items = [dict(live_va=int(f['return_site_va'], 16), lookup_pc=int(f['lookup_pc'], 16),
                          code=bytes.fromhex(f['return_site_hex']))
                     for f in chain.get('frames', []) if f.get('return_site_hex')]
            if chain.get('saved_pc_hex'):
                pc = int(chain['saved_pc'], 16)
                items.insert(0, dict(live_va=pc, lookup_pc=pc+4, code=bytes.fromhex(chain['saved_pc_hex'])))
            res = resolver(items, DSC)
            rows = []
            for site in res['sites']:
                row = dict(live_site=site['live_va'])
                unique = {m['unslid_site'] for m in site['matches'] if not res['common_slide']
                          or m['slide'] == res['common_slide']}
                if len(unique) == 1:
                    unslid = unique.pop()
                    row['unslid_site'] = unslid
                    text = subprocess.run(['ipsw', 'dyld', 'a2s', str(DSC), unslid, '--no-color'],
                                          capture_output=True, text=True).stdout.strip().splitlines()
                    row['symbol'] = text[-1] if text else None
                else:
                    row['unresolved'] = f'{len(unique)} candidate sites (executable, ambiguous or not in cache)'
                rows.append(row)
            out[f'{pid}/{tid}'] = dict(common_slide=res['common_slide'], end=chain.get('end'), sites=rows)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--self-test', action='store_true', help='offline layout/witness/decoder checks')
    ap.add_argument('--dry-run', action='store_true', help='print the capture plan only')
    ap.add_argument('--device')
    ap.add_argument('--prefix')
    ap.add_argument('--output-suffix', default='port-receiver')
    ap.add_argument('--focus', action='append', default=None, metavar='NAME',
                    help='process to decode fully (default WindowServer, loginwindow)')
    ap.add_argument('--target', action='append', default=[], metavar='PID:NAME',
                    help='extra (pid, hex port name) to resolve, e.g. 164:0x3f03')
    ap.add_argument('--table-for', action='append', default=None, metavar='NAME',
                    help='enumerate every right of this process (default WindowServer)')
    ap.add_argument('--pid-limit', type=int, default=256)
    ap.add_argument('--page-budget', type=int, default=12288)
    ap.add_argument('--no-user-memory', action='store_true',
                    help='skip user message-buffer and user frame reads')
    ap.add_argument('--ownership-user-roots', action='store_true',
                    help='admit uncached user roots from the ownership audit (as capture-kernel-waits)')
    ap.add_argument('--scratch', default=os.environ.get('TMPDIR', '/tmp'))
    ap.add_argument('--symbolize-user', type=Path, metavar='CAPTURE_JSON',
                    help='offline: name captured user frames via the host shared cache')
    args = ap.parse_args()
    args.focus = args.focus or ['WindowServer', 'loginwindow']
    args.table_for = args.table_for if args.table_for is not None else ['WindowServer']
    for t in args.target:
        if not re.fullmatch(r'\d{1,5}:0x[0-9a-fA-F]{1,8}', t):
            ap.error('--target must be PID:0xNAME')
    if args.symbolize_user:
        target = args.symbolize_user.with_name(args.symbolize_user.stem+'-user-symbols.json')
        if target.exists():
            raise SystemExit(f'{target} exists')
        result = symbolize_user(args.symbolize_user)
        target.write_text(json.dumps(result, indent=1)+'\n')
        for key, row in result.items():
            print(key, row['common_slide'], [r.get('symbol') or r.get('unresolved') for r in row['sites']])
        return
    if args.self_test:
        count, names = check_witnesses()
        fields = check_dwarf(args.scratch)
        cases = synthetic_test()
        print(json.dumps(dict(result='PORT_RECEIVER_SELF_TEST_PASSED', witnesses=count,
                              dwarf_checks=fields, synthetic_checks=cases, symbols=names), indent=1))
        return
    if not args.prefix or not re.fullmatch(r'[a-z0-9-]+', args.prefix):
        ap.error('--prefix required ([a-z0-9-]+)')
    if not re.fullmatch(r'[a-z0-9-]+', args.output_suffix):
        ap.error('invalid --output-suffix')
    output = ROOT/'build'/f'{args.prefix}-{args.output_suffix}.json'
    base = ROOT/'build'/args.prefix
    if args.dry_run:
        files = {n: Path(f'{base}-{n}.json').exists() for n in ('launch', 'audit')}
        print(json.dumps(dict(
            mode='dry-run: no device contact', prefix=args.prefix, output=str(output),
            output_exists=output.exists(), required_files_present=files,
            device=args.device, focus=args.focus, targets=args.target, table_for=args.table_for,
            steps=[
                'check launch record finished/exit code, launcher gone; audited stop owner, '
                'resident monitor hash, registers and geometry (capture-kernel-waits checks)',
                f'pin {len(WITNESSES)} kernelcache words (+ tools used: process-waits, user-state, '
                'cpu-topology, process-user-memory, user-frame-chain)',
                f'inventory PIDs 1..{args.pid_limit} with saved EL0 registers',
                'for each focus-process thread: decode thread->waitq (port/pset/turnstile); for a '
                'special reply port follow ip_sync_inheritor (PORT_SYNC_LINK_*) to the destination '
                'port, its receiver task/pid/name, launchd service label, queued kmsg headers '
                '(msgh_id, reply port owner) and the receive-turnstile inheritor chain '
                '(thread / kqworkloop->proc)',
                'resolve saved x3/x5/x14/x23 port names through the process is_table',
                'read the x0 user message header (unless --no-user-memory)',
                'scan all threads: pending special-reply sync waits and blocked sends',
                'enumerate the whole is_table of --table-for processes, aggregate rights by receiver',
                'list every receiver process thread (wait object, continuation, saved pc)',
                'recheck the resident stop; write JSON; no guest writes'],
            page_budget=args.page_budget), indent=1))
        return
    if not args.device or not (args.device.startswith('/dev/cu.usb') or args.device.startswith('udp://en')):
        ap.error('--device must be /dev/cu.usb* or udp://en*')
    if output.exists():
        raise SystemExit('output exists; choose a fresh --output-suffix')
    result = capture(args)
    output.write_text(json.dumps(result, indent=1)+'\n')
    for p in result['focus']:
        for t in p['threads']:
            print(json.dumps(dict(pid=p['pid'], name=p['name'], tid=t['tid'], answer=t['answer'],
                                  names=[(r['name'], (r.get('port') or {}).get('receiver'),
                                          (r.get('port') or {}).get('service_name'))
                                         for r in t['register_names']])))
    print(f'wrote {output}')


if __name__ == '__main__':
    main()
