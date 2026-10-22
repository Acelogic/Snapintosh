#!/bin/zsh
# SPDX-License-Identifier: MIT
# verify6's fixtures (../verify6/work/fixtures, ported): Metal on this Mac vs this tree's build/air2ir3 + build/nirexec
# (presence set and llvmpipe pixel per case), then the sidecar check (cache format 5).  BIN= / NX= / MT= override the
# binaries.  The .air / .metallib are built from the .metal sources into scratch/v6fixtures.
# fix round 5 (verify6's findings): poison_select 4 present mismatches, cv_neg 2 pixel, cv_charm128 3 pixel, cv_shortm32768 4 pixel,
# absent_read 2 pixel, overflow_body 2 pixel, pun_probe 0 wrong (31 'internal' refusals), poison_absorb 2 present; sidecar_check 6 of 7 bad.
# fix round 6: 0 present / pixel mismatches in every fixture, pun_probe 143/143, sidecar_check 0 bad of 7.
H=${0:a:h}; S=${0:a:h:h:h:h}/scratch/v6fixtures; mkdir -p $S
for f in poison_select poison_absorb cv_neg cv_charm128 cv_shortm32768 cv_uneg absent_read overflow_body pun_probe fmf_poison int_clamp int_convert; do
  xcrun -sdk macosx metal -c $H/$f.metal -o $S/$f.air && xcrun -sdk macosx metallib $S/$f.air -o $S/$f.metallib
  [[ -f $H/$f.cases ]] && C=$H/$f.cases || { C=$S/$f.cases; print "0=1\n0=0" > $C; }
  python3 $H/fixrun.py $S/$f $C | grep -v '^REFUSED' | tail -6
done
python3 $H/sidecar_check.py
