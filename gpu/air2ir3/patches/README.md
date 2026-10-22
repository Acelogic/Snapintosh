# Mesa patches

The files in this directory modify [Mesa](https://gitlab.freedesktop.org/mesa/mesa)
at the pinned revision `bbeb2dca9feed6ac88d71234a9dc5ae8aeed4275`.
`tools/mesa-setup.sh` checks out that revision and applies them.

Each patch is licensed under the licence of the file it modifies. All of them
are MIT:

| Patch | Files it modifies | Upstream copyright |
| --- | --- | --- |
| `0000-build-nir-and-ir3-without-drivers-parser-stub.patch`, `ir3_parse_stub.c`, `ir3_parser.h` | `src/compiler/nir/meson.build`, `src/freedreno/ir3/meson.build` | Copyright © 2017 Intel Corporation; Copyright © 2018 Rob Clark |
| `0001-ir3-ra-predicates-match-reloaded-def-in-live-in-merge.patch` | `src/freedreno/ir3/ir3_ra_predicates.c` | Copyright 2024 Igalia S.L. |
| `0002-glsl-bison-2.3-compat.patch` | `src/compiler/glsl/glcpp/glcpp-parse.y`, `src/compiler/glsl/glsl_parser.yy` | Copyright © 2010 Intel Corporation; Copyright © 2008, 2009 Intel Corporation |
| `0003-ir3-legalize-opt-jump-flow-lists-built-once.patch` | `src/freedreno/ir3/ir3_legalize.c` | Copyright © 2014 Rob Clark <robclark@freedesktop.org> |

These patches serve this project's build and have not been proposed upstream.
Mesa's contribution rules, including its policy on AI-assisted changes, apply
if they ever are.
