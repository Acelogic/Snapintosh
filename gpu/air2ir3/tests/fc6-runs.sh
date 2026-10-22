#!/bin/zsh
# SPDX-License-Identifier: MIT
# verify6's nine fc6 runs (work/fc6/runs1-3.log), same seeds / modes / sizes, against this tree
cd ${0:a:h:h}
export PYTHONHASHSEED=0   # the generator iterates sets of strings: fixed hash seed = the same shaders every run
for r in "pred 2 NOCALL" "shadow 3 NOCALL" "body 4 -" "body 5 -" "pred 7 NOCALL,SAFE" "shadow 8 NOCALL,SAFE" "body 9 SAFE" "pred 11 NOCALL" "shadow 12 NOCALL"; do
  set -- ${=r}
  env_=(); [[ $3 == *NOCALL* ]] && env_+=(NOCALL=1); [[ $3 == *SAFE* ]] && env_+=(SAFE=1)
  echo "== $1 $2 ${env_[*]} $(date +%H:%M:%S)"
  env $env_ python3 tests/fc6.py --mode $1 --seed $2 --shaders 150 --cases 10 || true
done
echo "== done $(date +%H:%M:%S)"
