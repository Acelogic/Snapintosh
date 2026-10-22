// SPDX-License-Identifier: MIT
// Single-stage entry point for the unchanged standalone renderer serializer.
// Reads only compiler-produced artifacts, never untrusted cache input.
#define main retained_p7_export_main
#include "export_p7_shaders.cpp"
#undef main

int main(int argc, char **argv) {
  if (argc != 3) return 2;
  struct fd_dev_id id = {};
  id.chip_id = 0x44070041;
  const struct fd_dev_info *info = fd_dev_info_raw(&id);
  if (!info) return 2;
  glsl_type_singleton_init_or_ref();
  struct ir3_compiler_options options = {};
  options.bindless_fb_read_descriptor = 4;
  options.bindless_fb_read_slot = 55;
  options.lower_base_vertex = true;
  options.push_ubo_with_preamble = true;
  options.disable_cache = true;
  ir3_compiler *compiler = ir3_compiler_create(nullptr, &id, info, &options);
  if (!compiler) return 2;
  auto blob = slurp(argv[1]);
  struct blob_reader reader;
  blob_reader_init(&reader, blob.data(), blob.size());
  auto *variant = ir3_retrieve_variant(&reader, compiler, nullptr);
  if (!variant || reader.overrun || reader.current != reader.end) return 3;
  auto sidecar = slurp(argv[2]);
  puts("{");
  variant_json(stdout, "variant", variant, std::string(sidecar.begin(), sidecar.end()), fd_dev_gpu_id(&id));
  puts("\n}");
  ir3_compiler_destroy(compiler);
  glsl_type_singleton_decref();
  return 0;
}
