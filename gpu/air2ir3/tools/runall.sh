#!/bin/zsh
# SPDX-License-Identifier: MIT
# runall.sh - every check of this tree, in order, on this Mac (~55 min; round 6 adds verify6's fixtures and fc6 runs; the sweep ~7, the randomized
# unset-constant tests ~22 (fcrand seeds 1, 2, 17, 23; fcv4 verify4's four runs + three fresh seeds;
# fcv5 verify5's 16 runs), the XR grids ~2, the clean-tree rebuild ~4).  Build first: src/build.sh all (includes the Swift tools).  Logs go to
# results/*.log; the numbers in COVERAGE.md come from here.  Run it in the background:
#   zsh tools/runall.sh > results/runall.log 2>&1 &
set -e
ROOT=${0:a:h:h}; cd $ROOT
step() { echo "== $1 ($(date +%H:%M:%S))"; }
step sweep;        rm -rf cache results/fixed; python3 tools/sweep.py --out results/fixed --cache cache > results/sweep-fixed.log 2>&1
step cachecheck;   python3 tools/cachecheck.py cache --reload 200 > results/cachecheck.json
step cachekey;     python3 tools/cachekey.py > results/cachekey.txt
step regress;      python3 tests/regress.py > results/regress.txt 2>&1
step fcrand;       python3 tests/fcrand.py --shaders 400 --cases 24 --seed 1 > results/fcrand.log 2>&1
step fcrand2;      python3 tests/fcrand.py --shaders 400 --cases 24 --seed 2 --out results/fcrand-seed2.json > results/fcrand-seed2.log 2>&1
step fcrand17;     python3 tests/fcrand.py --shaders 400 --cases 24 --seed 17 --out results/fcrand-seed17.json > results/fcrand-seed17.log 2>&1
step fcrand23;     python3 tests/fcrand.py --shaders 400 --cases 24 --seed 23 --out results/fcrand-seed23.json > results/fcrand-seed23.log 2>&1
# verify4's generator (int/float/ushort/short constants, conditions the old sample set could not see):
# its four runs with its seeds and sizes, then fresh seeds in each mode
step fcv4;         { python3 tests/fcv4.py --mode hole --seed 41 --shaders 60 --cases 6 && \
                     python3 tests/fcv4.py --mode hole --seed 45 --shaders 150 --cases 8 && \
                     python3 tests/fcv4.py --mode mixed --seed 44 --shaders 150 --cases 8 && \
                     python3 tests/fcv4.py --mode pred --seed 43 --shaders 60 --cases 6 && \
                     python3 tests/fcv4.py --mode hole --seed 101 --shaders 150 --cases 8 && \
                     python3 tests/fcv4.py --mode mixed --seed 102 --shaders 150 --cases 8 && \
                     python3 tests/fcv4.py --mode pred --seed 103 --shaders 150 --cases 8; } > results/fcv4.log 2>&1
# verify5's generator (12 constant types; fix round 5): its body / pred / shadow runs with its seeds and sizes
# (pred 51-53 and shadow 61-62 ran with NOCONV=1, which filters out conversions / isnan / helpers)
step fcv5;         { for r in "body 21" "body 22" "body 23" "body 24" "body 11" "body 12" "body 13" "pred 31" "pred 32" "shadow 41" "shadow 42"; do
                       set -- ${=r}; python3 tests/fcv5.py --mode $1 --seed $2 --shaders 200 --cases 12 || true; done
                     for r in "pred 51" "pred 52" "pred 53" "shadow 61" "shadow 62"; do
                       set -- ${=r}; NOCONV=1 python3 tests/fcv5.py --mode $1 --seed $2 --shaders 200 --cases 12 || true; done; } > results/fcv5.log 2>&1
                   python3 tests/fcv5.py --summary > results/fcv5-summary.txt
# verify6's fixtures and its nine randomized fc6 runs (fix round 6)
step v6fixtures;   zsh tests/fixtures/v6/run_fixtures.sh > results/v6fixtures.txt 2>&1
step fc6;          zsh tests/fc6-runs.sh > results/fc6.log 2>&1
step xrrand;       python3 tools/xrrand.py > results/xrrand.log 2>&1
step xr5;          python3 tools/xr5.py > results/xr5.log 2>&1
step coverage;     python3 tools/coverage.py > results/coverage.md
# fix round 6: against the compiler that ran on the A16 (render run 2: fix4 + air2ir3-abi6-final.patch), round 5 and round 4
step rounddiff;    { python3 tools/rounddiff.py results/abi6 'A16 render run 2 (fix4 + ABI 6)' results/rounddiff.json && \
                     python3 tools/rounddiff.py results/fix5 'fix round 5' results/rounddiff-fix5.json && \
                     python3 tools/rounddiff.py results/fix4 'fix round 4' results/rounddiff-fix4.json; } > results/rounddiff.txt
step a16check;     python3 tools/a16check.py --ref ${A16REF:-../../adreno-render-fix/work/fix4abi6/build/air2ir3} > results/a16check.txt 2>&1 || python3 tools/a16check.py > results/a16check.txt 2>&1
step fix2diff;     python3 tools/fix2diff.py > results/fix2diff.txt
step p7check;      python3 tools/p7check.py > results/p7check.txt 2>&1
step unsetdiff;    python3 tools/unsetdiff.py > results/unsetdiff.txt
step exec;         python3 tools/exec.py > results/exec.log 2>&1
step nirdiff;      python3 tools/nirdiff.py > results/nirdiff.log 2>&1
step qcrefl;       python3 vtools/qcrefl.py > results/qcrefl.txt
step reflcmp;      python3 vtools/reflcmp.py 2000 > results/reflcmp.log 2>&1
step diffscenes;   python3 vtools/diffscenes.py > results/diffscenes.log 2>&1
step apitest;      python3 tools/apitest.py > results/apitest.log 2>&1
step cleanroom;    zsh tools/cleanroom.sh > results/cleanroom.log 2>&1
step done
