#pragma once

#include <memory>

#include "source/extensions/common/http_wasm/context.h"
#include "source/extensions/common/http_wasm/vm_runtime.h"
#include "source/extensions/common/http_wasm/word.h"
#include "absl/strings/string_view.h"
#include "absl/strings/numbers.h"

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

class Context;

// Any currently executing Wasm call context.
Context* contextOrEffectiveContext();
namespace exports {
// ABI functions exported from host to wasm.
Word get_config(Word value_ptr_ptr, Word value_size_ptr);
Word enable_features(Word features);
Word log_enabled(Word level);
void log(Word level, Word address, Word size);
Word get_method(Word name, Word name_len);
void set_method(Word name, Word name_len);
Word get_uri(Word uri, Word uri_len);
void set_uri(Word uri, Word uri_len);
Word get_protocol_version(Word buf, Word buf_len);
int64_t get_header_names(Word kind, Word buffer, Word buffer_length);
int64_t get_header_values(Word kind, Word name, Word name_len, Word value, Word value_len);
void add_header_value(Word kind, Word name, Word name_len, Word value, Word value_len);
void set_header_value(Word kind, Word name, Word name_len, Word value, Word value_len);
void remove_header(Word kind, Word name, Word name_len);
int64_t read_body(Word kind, Word buffer, Word buffer_length);
void write_body(Word kind, Word buffer, Word buffer_length);
Word get_status_code();
void set_status_code(Word);

// Runtime environment functions exported from envoy to wasm .
Word wasi_unstable_path_open(Word fd, Word dir_flags, Word path, Word path_len, Word oflags,
                             int64_t fs_rights_base, int64_t fg_rights_inheriting, Word fd_flags,
                             Word nwritten_ptr);
Word wasi_unstable_fd_prestat_get(Word fd, Word buf_ptr);
Word wasi_unstable_fd_prestat_dir_name(Word fd, Word path_ptr, Word path_len);
Word wasi_unstable_fd_write(Word fd, Word iovs, Word iovs_len, Word nwritten_ptr);
Word wasi_unstable_fd_read(Word, Word, Word, Word);
Word wasi_unstable_fd_seek(Word, int64_t, Word, Word);
Word wasi_unstable_fd_close(Word);
void wasi_unstable_proc_exit(Word);
Word wasi_unstable_clock_time_get(Word, uint64_t, Word);
Word wasi_unstable_fd_fdstat_get(Word fd, Word statOut);
Word wasi_unstable_environ_get(Word, Word);
Word wasi_unstable_environ_sizes_get(Word count_ptr, Word buf_size_ptr);
Word wasi_unstable_args_get(Word argc_ptr, Word argv_buf_size_ptr);
Word wasi_unstable_args_sizes_get(Word argc_ptr, Word argv_buf_size_ptr);
Word wasi_unstable_fd_filestat_get(Word fd, Word statOut);
Word wasi_unstable_fd_pread(Word fd, Word iovs, Word iovs_len, int64_t offset, Word nread_ptr);
Word wasi_unstable_fd_readdir(Word fd, Word buf, Word buf_len, int64_t cookie, Word bufused_ptr);
Word wasi_unstable_path_filestat_get(Word fd, Word flags, Word path, Word path_len, Word buf);
Word wasi_unstable_path_remove_directory(Word fd, Word path, Word path_len);
Word wasi_unstable_path_unlink_file(Word fd, Word path, Word path_len);

#define FOR_ALL_HOST_FUNCTIONS(_f)                                                                 \
  _f(get_config) _f(enable_features) _f(log_enabled) _f(log) _f(read_body) _f(write_body)          \
      _f(get_method) _f(set_method) _f(get_uri) _f(set_uri) _f(get_protocol_version)               \
          _f(get_header_names) _f(get_header_values) _f(set_header_value) _f(add_header_value)     \
              _f(remove_header) _f(get_status_code) _f(set_status_code)

#define FOR_ALL_WASI_FUNCTIONS(_f)                                                                 \
  _f(fd_write) _f(fd_read) _f(fd_seek) _f(fd_close) _f(fd_fdstat_get) _f(environ_get)              \
      _f(environ_sizes_get) _f(args_get) _f(args_sizes_get) _f(path_open) _f(fd_prestat_get)       \
          _f(fd_prestat_dir_name) _f(clock_time_get) _f(proc_exit) _f(fd_filestat_get)             \
              _f(fd_pread) _f(fd_readdir) _f(path_filestat_get) _f(path_remove_directory)          \
                  _f(path_unlink_file)

// Helpers to generate a stub to pass to VM, in place of a restricted WASI capability.
#define _CREATE_WASI_STUB(_fn)                                                                     \
  template <typename F> struct _fn##Stub;                                                          \
  template <typename... Args> struct _fn##Stub<Word(Args...)> {                                    \
    static Word stub(Args...) {                                                                    \
      auto context = contextOrEffectiveContext();                                                  \
      context->runtime()->logger()->error("Attempted call to restricted WASI capability: " #_fn);  \
      return 76; /* __WASI_ENOTCAPABLE */                                                          \
    }                                                                                              \
  };                                                                                               \
  template <typename... Args> struct _fn##Stub<void(Args...)> {                                    \
    static void stub(Args...) {                                                                    \
      auto context = contextOrEffectiveContext();                                                  \
      context->runtime()->logger()->error("Attempted call to restricted WASI capability: " #_fn);  \
    }                                                                                              \
  };
FOR_ALL_WASI_FUNCTIONS(_CREATE_WASI_STUB)
#undef _CREATE_WASI_STUB

} // namespace exports
} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
