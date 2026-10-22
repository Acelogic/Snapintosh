/* SPDX-License-Identifier: MIT */
/* Report-to-key translation; the contract and layouts are in hid-keyboard.h. */
#include "hid-keyboard.h"

#include <string.h>

static int held(const uint8_t keys[6], uint8_t usage)
{
    for (unsigned i = 0; i < 6; i++)
        if (keys[i] == usage)
            return 1;
    return 0;
}

/* A usable key usage: an actual key, inside the descriptor's logical range. */
static int key(uint8_t usage)
{
    return usage >= 0x04u && usage <= HID_KBD_MAX_KEY;
}

int hid_kbd_translate(struct hid_kbd_state *s, const uint8_t *r, uint32_t len,
                      hid_kbd_emit_fn emit, void *ctx)
{
    if (!s || !r || !len || !emit)
        return HID_KBD_BAD_LENGTH;
    if (r[0] == HID_KBD_REPORT_KEYS) {
        uint8_t mods, keys[6];
        if (len != HID_KBD_KEYS_BYTES)
            return HID_KBD_BAD_LENGTH;
        for (unsigned i = 0; i < 6; i++)
            if (r[3 + i] == HID_KBD_ROLLOVER)
                return HID_KBD_ROLLOVER_REPORT;      /* too many keys: keep the last good state */
        mods = r[1];
        for (unsigned i = 0; i < 6; i++) {
            keys[i] = key(r[3 + i]) ? r[3 + i] : 0u;
            for (unsigned j = 0; j < i; j++)
                if (keys[j] == keys[i])
                    keys[i] = 0u;                /* a usage listed twice is one key */
        }
        for (unsigned b = 0; b < 8; b++)
            if ((s->modifiers & (1u << b)) && !(mods & (1u << b)))
                emit(ctx, HID_KBD_PAGE_KEYBOARD, 0xe0u + b, 0);
        for (unsigned i = 0; i < 6; i++)
            if (s->keys[i] && !held(keys, s->keys[i]))
                emit(ctx, HID_KBD_PAGE_KEYBOARD, s->keys[i], 0);
        for (unsigned b = 0; b < 8; b++)
            if (!(s->modifiers & (1u << b)) && (mods & (1u << b)))
                emit(ctx, HID_KBD_PAGE_KEYBOARD, 0xe0u + b, 1);
        for (unsigned i = 0; i < 6; i++)
            if (keys[i] && !held(s->keys, keys[i]))
                emit(ctx, HID_KBD_PAGE_KEYBOARD, keys[i], 1);
        s->modifiers = mods;
        memcpy(s->keys, keys, sizeof(keys));
        return HID_KBD_EVENTS;
    }
    if (r[0] == HID_KBD_REPORT_CONSUMER) {
        uint16_t usage;
        if (len != HID_KBD_CONSUMER_BYTES)
            return HID_KBD_BAD_LENGTH;
        usage = (uint16_t)(r[1] | r[2] << 8);
        if (usage == s->consumer)
            return HID_KBD_EVENTS;
        if (s->consumer)
            emit(ctx, HID_KBD_PAGE_CONSUMER, s->consumer, 0);
        if (usage)
            emit(ctx, HID_KBD_PAGE_CONSUMER, usage, 1);
        s->consumer = usage;
        return HID_KBD_EVENTS;
    }
    return HID_KBD_IGNORED;
}

void hid_kbd_release_all(struct hid_kbd_state *s, hid_kbd_emit_fn emit, void *ctx)
{
    if (!s || !emit)
        return;
    for (unsigned b = 0; b < 8; b++)
        if (s->modifiers & (1u << b))
            emit(ctx, HID_KBD_PAGE_KEYBOARD, 0xe0u + b, 0);
    for (unsigned i = 0; i < 6; i++)
        if (s->keys[i])
            emit(ctx, HID_KBD_PAGE_KEYBOARD, s->keys[i], 0);
    if (s->consumer)
        emit(ctx, HID_KBD_PAGE_CONSUMER, s->consumer, 0);
    memset(s, 0, sizeof(*s));
}
