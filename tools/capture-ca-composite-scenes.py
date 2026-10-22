#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture real CA composite layer paths without accessing the A16.

Failure inventory: docs/ADRENO-CA-COMPOSITE-20260928.md.
Reuse the checked first-commit interception; do not submit to the host GPU.
"""
from pathlib import Path
import hashlib

ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / 'tools/capture-ca-desktop-scenes.py'
assert hashlib.sha256(BASE.read_bytes()).hexdigest() == '953e4f8fda60197602eec95e1b759eab39e5245c32c243e8e18638b0899e57d7'
source = BASE.read_text()
for old, new in {
    '@[@"opacity", @"rounded", @"text", @"gradient"]':
        '@[@"desktop", @"shadow", @"mask", @"transform"]',
    "for scene in ['opacity', 'rounded', 'text', 'gradient']:":
        "for scene in ['desktop', 'shadow', 'mask', 'transform']:",
}.items():
    assert source.count(old) == 1, old
    source = source.replace(old, new)
scope = dict(__file__=__file__, __name__='composite_capture')
exec(compile(source, str(BASE), 'exec'), scope)
scope['SCENES'] = r'''
            [child removeFromSuperlayer];
            CGColorRef pale = CGColorCreateGenericRGB(0.85, 0.91, 1, 0.92);
            CGColorRef dark = CGColorCreateGenericRGB(0.04, 0.07, 0.14, 1);
            CGColorRef white = CGColorCreateGenericRGB(1, 1, 1, 1);
            CGColorRef clear = CGColorCreateGenericRGB(0, 0, 0, 0);
            CAGradientLayer *wall = [CAGradientLayer layer];
            wall.frame = root.bounds; wall.colors = @[(__bridge id)blue, (__bridge id)orange];
            wall.startPoint = CGPointMake(0, 0); wall.endPoint = CGPointMake(1, 1);
            [root addSublayer:wall];
            CALayer *menu = [CALayer layer]; menu.frame = CGRectMake(0, 142, 256, 18);
            menu.backgroundColor = pale; menu.opacity = 0.75; [root addSublayer:menu];
            CALayer *window = [CALayer layer]; window.frame = CGRectMake(16, 28, 180, 104);
            window.backgroundColor = pale; window.cornerRadius = 8; window.masksToBounds = YES;
            [root addSublayer:window];
            CAGradientLayer *header = [CAGradientLayer layer];
            header.frame = CGRectMake(0, 82, 180, 22);
            header.colors = @[(__bridge id)blue, (__bridge id)dark];
            header.startPoint = CGPointMake(0, 0.5); header.endPoint = CGPointMake(1, 0.5);
            [window addSublayer:header];
            CATextLayer *title = [CATextLayer layer]; title.frame = CGRectMake(8, 84, 164, 18);
            title.string = @"Snapintosh"; title.fontSize = 13; title.contentsScale = 1;
            title.foregroundColor = white; title.alignmentMode = kCAAlignmentCenter;
            [window addSublayer:title];
            CATextLayer *body = [CATextLayer layer]; body.frame = CGRectMake(10, 30, 158, 40);
            body.string = @"Adreno + Metal\nNative CA composition"; body.fontSize = 12;
            body.contentsScale = 1; body.wrapped = YES; body.foregroundColor = dark;
            [window addSublayer:body];
            CALayer *button = [CALayer layer]; button.frame = CGRectMake(104, 9, 62, 18);
            button.cornerRadius = 6; button.backgroundColor = blue; button.opacity = 0.7;
            [window addSublayer:button];
            CALayer *icon = [CALayer layer]; icon.frame = CGRectMake(200, 87, 40, 40);
            icon.backgroundColor = orange; icon.cornerRadius = 9;
            icon.borderColor = white; icon.borderWidth = 2; icon.opacity = 0.8;
            [root addSublayer:icon];
            if ([scene isEqualToString:@"shadow"]) {
                window.masksToBounds = NO; window.shadowColor = dark;
                window.shadowOpacity = 0.75; window.shadowRadius = 7;
                window.shadowOffset = CGSizeMake(5, -5);
            } else if ([scene isEqualToString:@"mask"]) {
                CAGradientLayer *mask = [CAGradientLayer layer]; mask.frame = window.bounds;
                mask.colors = @[(__bridge id)clear, (__bridge id)white, (__bridge id)white];
                mask.locations = @[@0, @0.4, @1];
                mask.startPoint = CGPointMake(0, 0.5); mask.endPoint = CGPointMake(1, 0.5);
                window.mask = mask;
            } else if ([scene isEqualToString:@"transform"]) {
                CATransform3D perspective = CATransform3DIdentity; perspective.m34 = -1.0 / 500.0;
                window.transform = CATransform3DRotate(perspective, 0.22, 0, 1, 0);
            }
            CGColorRelease(pale); CGColorRelease(dark); CGColorRelease(white); CGColorRelease(clear);
'''

if __name__ == '__main__':
    scope['main']()
