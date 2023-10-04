#include "source/extensions/common/http_wasm/guest.h"
#include "word.h"

#include <cstdint>
#include <openssl/rand.h>

#include <fstream>
#include <memory>
#include <iostream>
#include <unistd.h>
#include <utility>
#include <vector>
#include <string_view>
namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {

thread_local Context* current_context_ = nullptr;

// Any currently executing Wasm call context.
Context* contextOrEffectiveContext() { return current_context_; };
namespace exports {

// Administrative ABIs...
Word get_config(Word value_ptr, Word value_size) {
  auto* context = contextOrEffectiveContext();
  auto value = context->getConfiguration();
  if (value.size() > value_size) {
    return 0;
  }
  context->runtime()->setMemory(value_ptr, value.size(), (void*)value.data());
  return value.size();
}

Word enable_features(Word features) {
  // TODO: implement
  return 3;
}

// Logging ABIs...
Word log_enabled(Word log_level) {
  auto* context = contextOrEffectiveContext();
  return context->runtime()->cmpLogLevel(static_cast<LogLevel>(log_level.u64_));
}

void log(Word level, Word address, Word size) {
  int32_t signedLevel = static_cast<int32_t>(level.u64_);
  if (signedLevel >= static_cast<int32_t>(LogLevel::Max)) { // Max is none logs
    return;
  }
  auto* context = contextOrEffectiveContext();
  auto message = context->runtime()->getMemory(address, size);
  if (!message) {
    return;
  }
  context->log(signedLevel, message.value());
}

// Header ABIs...
Word get_method(Word buf, Word buf_len) {
  auto* context = contextOrEffectiveContext();
  std::vector<std::string_view> values;
  auto result = context->getHeaderMapValue(WasmHeaderMapType::RequestHeaders, ":method", values);
  if (result != WasmResult::Ok) {
    return 0;
  }
  if ((values.size() == 0) || (values.size() > 1)) {
    return 0;
  }
  if (values[0].size() > buf_len) {
    return 0;
  }
  context->runtime()->setMemory(buf, values[0].size(), (void*)values[0].data());
  return values[0].size();
}

void set_method(Word buf, Word buf_len) {
  auto* context = contextOrEffectiveContext();
  auto value = context->runtime()->getMemory(buf, buf_len);
  context->replaceHeaderMapValue(WasmHeaderMapType::RequestHeaders, ":method", value.value());
}

Word get_uri(Word uri, Word uri_len) {
  auto* context = contextOrEffectiveContext();
  std::vector<std::string_view> values;
  auto result = context->getHeaderMapValue(WasmHeaderMapType::RequestHeaders, ":path", values);
  if (result != WasmResult::Ok) {
    return 0;
  }
  if ((values.size() == 0) || (values.size() > 1)) {
    return 0;
  }
  if (values[0].size() > uri_len) {
    return 0;
  }
  context->runtime()->setMemory(uri, values[0].size(), (void*)values[0].data());
  return values[0].size();
}

void set_uri(Word buf, Word buf_len) {
  auto* context = contextOrEffectiveContext();
  auto value = context->runtime()->getMemory(buf, buf_len);
  context->replaceHeaderMapValue(WasmHeaderMapType::RequestHeaders, ":path", value.value());
}

Word get_protocol_version(Word buf, Word buf_len) {
  auto* context = contextOrEffectiveContext();

  // TODO: get the protocol version from the request headers.
  std::string_view version = "HTTP/1.1";
  if (version.size() > buf_len) {
    return 0;
  }
  context->runtime()->setMemory(buf, version.size(), (void*)version.data());
  return version.size();
}

int64_t get_header_names(Word kind, Word buffer, Word buffer_length) {
  auto* context = contextOrEffectiveContext();
  std::vector<std::string_view> names;

  auto result = context->getHeaderNames(static_cast<WasmHeaderMapType>(kind.u64_), names);
  if (result != WasmResult::Ok) {
    return 0;
  }
  // iterate over names and copy them into a buffer separated by a byte which is written as a 0
  // byte to the end of each name.
  size_t totalCopied = 0;
  for (const auto& name : names) {
    if (name.size() + 1 > buffer_length - totalCopied) {
      // Not enough space left in buffer
      return 0;
    }
    auto separator = std::uint8_t(0); // Separator byte
    context->runtime()->setMemory(buffer + totalCopied, name.size(), (void*)name.data());
    context->runtime()->setMemory(buffer + totalCopied + name.size(), 1, (void*)(&separator));
    totalCopied += name.size() + 1;
  }

  uint64_t count = names.size();
  return count << 32 | totalCopied;
}

int64_t get_header_values(Word kind, Word name, Word name_len, Word buffer, Word buffer_length) {
  auto* context = contextOrEffectiveContext();
  std::vector<std::string_view> nameValues;
  auto key = context->runtime()->getMemory(name, name_len);
  auto result = context->getHeaderMapValue(static_cast<WasmHeaderMapType>(kind.u64_), key.value(),
                                           nameValues);
  if (result != WasmResult::Ok) {
    return 0;
  }
  // iterate over names and copy them into a buffer separated by a byte which is written as a 0
  // byte to the end of each name.
  size_t totalCopied = 0;
  for (const auto& nameValue : nameValues) {
    if (nameValue.size() + 1 > buffer_length - totalCopied) {
      // Not enough space left in buffer
      return 0;
    }
    auto separator = std::uint8_t(0); // Separator byte
    context->runtime()->setMemory(buffer + totalCopied, nameValue.size(), (void*)nameValue.data());
    context->runtime()->setMemory(buffer + totalCopied + nameValue.size(), 1, (void*)(&separator));
    totalCopied += nameValue.size() + 1;
  }

  uint64_t count = nameValues.size();
  return count << 32 | totalCopied;
}

void set_header_value(Word kind, Word name, Word name_len, Word val, Word value_len) {
  auto* context = contextOrEffectiveContext();
  auto key = context->runtime()->getMemory(name, name_len);
  auto value = context->runtime()->getMemory(val, value_len);
  if (key && value) {
    context->replaceHeaderMapValue(static_cast<WasmHeaderMapType>(kind.u64_), key.value(),
                                   value.value());
  }
}

void remove_header(Word kind, Word name, Word name_len) {
  auto* context = contextOrEffectiveContext();
  auto key = context->runtime()->getMemory(name, name_len);
  if (key) {
    context->removeHeaderMapValue(static_cast<WasmHeaderMapType>(kind.u64_), key.value());
  }
}

void add_header_value(Word kind, Word name, Word name_len, Word val, Word value_len) {
  auto* context = contextOrEffectiveContext();
  auto key = context->runtime()->getMemory(name, name_len);
  auto value = context->runtime()->getMemory(val, value_len);
  if (key && value) {
    context->addHeaderMapValue(WasmHeaderMapType::RequestHeaders, key.value(), value.value());
  }
}

// Body ABIs...
int64_t read_body(Word kind, Word val, Word size) {
  if (kind > static_cast<uint64_t>(WasmBufferType::MAX)) {
    return 0;
  }
  auto* context = contextOrEffectiveContext();
  auto* buffer = context->getBuffer(static_cast<WasmBufferType>(kind.u64_));
  if (buffer == nullptr) {
    uint64_t eof = 1;
    eof = (eof << 32);
    return eof;
  }
  auto targetMemory = context->runtime()->getMemory(val.u64_, size);
  if (!targetMemory) {
    return 0;
  }
  return buffer->copyTo(
      const_cast<void*>(reinterpret_cast<const void*>(targetMemory.value().data())), size);
}

void write_body(Word kind, Word val, Word size) {
  if (kind > static_cast<uint64_t>(WasmBufferType::MAX)) {
    // TODO: trap
    return;
  }
  auto* context = contextOrEffectiveContext();
  auto srcMemory = context->runtime()->getMemory(val.u64_, size);
  if (!srcMemory) {
    // TODO: trap
    return;
  }
  auto* buffer = context->getBuffer(static_cast<WasmBufferType>(kind.u64_));
  if (buffer == nullptr && kind == static_cast<uint64_t>(WasmBufferType::HttpResponseBody)) {
    context->setLocalResponseBody(srcMemory.value());
    return;
  }
  buffer->copyFrom(0, srcMemory.value(), size);
  context->maybeAddContentLength(size);
}

Word get_status_code() {
  auto* context = contextOrEffectiveContext();
  std::vector<std::string_view> values;
  auto result = context->getHeaderMapValue(WasmHeaderMapType::ResponseHeaders, ":status", values);
  if (result != WasmResult::Ok) {
    return 0;
  }
  if ((values.size() == 0) || (values.size() > 1)) {
    return 0;
  }
  if (values[0].size() > 3) {
    return 0;
  }
  uint32_t status_code;
  if (!absl::SimpleAtoi(values[0], &status_code)) {
    // ENVOY_LOG(debug, "status code must be a number, got: {}", value);
    return 0; // TODO: trap
  }
  return status_code;
}

void set_status_code(Word response_code) {
  auto* context = contextOrEffectiveContext();
  context->setLocalResponseCode(response_code);
  return;
}

// WASI ABIs...
Word wasi_unstable_path_open(Word /*fd*/, Word /*dir_flags*/, Word /*path*/, Word /*path_len*/,
                             Word /*oflags*/, int64_t /*fs_rights_base*/,
                             int64_t /*fg_rights_inheriting*/, Word /*fd_flags*/,
                             Word /*nwritten_ptr*/) {
  return 44; // __WASI_ERRNO_NOENT
}

// __wasi_errno_t __wasi_fd_prestat_get(__wasi_fd_t fd, __wasi_prestat_t *retptr0)
Word wasi_unstable_fd_prestat_get(Word /*fd*/, Word /*buf_ptr*/) {
  return 8; // __WASI_ERRNO_BADF
}

// __wasi_errno_t __wasi_fd_prestat_dir_name(__wasi_fd_t fd, uint8_t * path, __wasi_size_t
// path_len)
Word wasi_unstable_fd_prestat_dir_name(Word /*fd*/, Word /*path_ptr*/, Word /*path_len*/) {
  return 52; // __WASI_ERRNO_ENOSYS
}

// Implementation of writev-like() syscall that redirects stdout/stderr to Envoy
// logs.
Word writevImpl(Word fd, Word iovs, Word iovs_len, Word* nwritten_ptr) {
  auto* context = contextOrEffectiveContext();

  // Read syscall args.
  uint64_t log_level;
  switch (fd) {
  case 1 /* stdout */:
    log_level = 1; // LogLevel::info
    break;
  case 2 /* stderr */:
    log_level = 2; // LogLevel::error
    break;
  default:
    return 8; // __WASI_EBADF
  }

  std::string s;
  for (size_t i = 0; i < iovs_len; i++) {
    auto memslice =
        context->runtime()->getMemory(iovs + i * 2 * sizeof(uint32_t), 2 * sizeof(uint32_t));
    if (!memslice) {
      return 21; // __WASI_EFAULT
    }
    const auto* iovec = reinterpret_cast<const uint32_t*>(memslice.value().data());
    if (iovec[1] != 0U /* buf_len */) {
      const auto buf = wasmtoh(iovec[0], context->runtime()->usesWasmByteOrder());
      const auto buf_len = wasmtoh(iovec[1], context->runtime()->usesWasmByteOrder());
      memslice = context->runtime()->getMemory(buf, buf_len);
      if (!memslice) {
        return 21; // __WASI_EFAULT
      }
      s.append(memslice.value().data(), memslice.value().size());
    }
  }

  size_t written = s.size();
  if (written != 0U) {
    // Remove trailing newline from the logs, if any.
    if (s[written - 1] == '\n') {
      s.erase(written - 1);
    }
    if (context->log(log_level, s) != WasmResult::Ok) {
      return 8; // __WASI_EBADF
    }
  }
  *nwritten_ptr = Word(written);
  return 0; // __WASI_ESUCCESS
}

// __wasi_errno_t __wasi_fd_write(_wasi_fd_t fd, const _wasi_ciovec_t *iov,
// size_t iovs_len, size_t* nwritten);
Word wasi_unstable_fd_write(Word fd, Word iovs, Word iovs_len, Word nwritten_ptr) {
  auto* context = contextOrEffectiveContext();

  Word nwritten(0);
  auto result = writevImpl(fd, iovs, iovs_len, &nwritten);
  if (result != 0) { // __WASI_ESUCCESS
    return result;
  }
  if (!context->runtime()->setWord(nwritten_ptr, Word(nwritten))) {
    return 21; // __WASI_EFAULT
  }
  return 0; // __WASI_ESUCCESS
}

// void __wasi_proc_exit(__wasi_exitcode_t rval);
void wasi_unstable_proc_exit(Word /*exit_code*/) {
  auto* context = contextOrEffectiveContext();
  context->error("wasi_unstable proc_exit");
}

// __wasi_errno_t __wasi_fd_read(_wasi_fd_t fd, const __wasi_iovec_t *iovs,
//    size_t iovs_len, __wasi_size_t *nread);
Word wasi_unstable_fd_read(Word /*fd*/, Word /*iovs_ptr*/, Word /*iovs_len*/, Word /*nread_ptr*/) {
  // Don't support reading of any files.
  return 52; // __WASI_ERRNO_ENOSYS
}

// __wasi_errno_t __wasi_fd_seek(__wasi_fd_t fd, __wasi_filedelta_t offset,
// __wasi_whence_t whence,__wasi_filesize_t *newoffset);
Word wasi_unstable_fd_seek(Word /*fd*/, int64_t /*offset*/, Word /*whence*/,
                           Word /*newoffset_ptr*/) {
  auto* context = contextOrEffectiveContext();
  context->error("wasi_unstable fd_seek");
  return 0;
}

// __wasi_errno_t __wasi_fd_close(__wasi_fd_t fd);
Word wasi_unstable_fd_close(Word /*fd*/) {
  auto* context = contextOrEffectiveContext();
  context->error("wasi_unstable fd_close");
  return 0;
}

// __wasi_errno_t __wasi_fd_fdstat_get(__wasi_fd_t fd, __wasi_fdstat_t *stat)
Word wasi_unstable_fd_fdstat_get(Word fd, Word statOut) {
  // We will only support this interface on stdout and stderr
  if (fd != 1 && fd != 2) {
    return 8; // __WASI_EBADF;
  }

  // The last word points to a 24-byte structure, which we
  // are mostly going to zero out.
  uint64_t wasi_fdstat[3];
  wasi_fdstat[0] = 0;
  wasi_fdstat[1] = 64; // This sets "fs_rights_base" to __WASI_RIGHTS_FD_WRITE
  wasi_fdstat[2] = 0;

  auto* context = contextOrEffectiveContext();
  context->runtime()->setMemory(statOut, 3 * sizeof(uint64_t), &wasi_fdstat);

  return 0; // __WASI_ESUCCESS
}

// __wasi_errno_t __wasi_environ_get(char **environ, char *environ_buf);
Word wasi_unstable_environ_get(Word environ_array_ptr, Word environ_buf) {
  auto* context = contextOrEffectiveContext();
  auto word_size = context->runtime()->getWordSize();
  const auto& envs = context->guest()->envs();
  for (const auto& e : envs) {
    if (!context->runtime()->setWord(environ_array_ptr, environ_buf)) {
      return 21; // __WASI_EFAULT
    }

    std::string data;
    data.reserve(e.first.size() + e.second.size() + 2);
    data.append(e.first);
    data.append("=");
    data.append(e.second);
    data.append({0x0});
    if (!context->runtime()->setMemory(environ_buf, data.size(), data.c_str())) {
      return 21; // __WASI_EFAULT
    }
    environ_buf = environ_buf.u64_ + data.size();
    environ_array_ptr = environ_array_ptr.u64_ + word_size;
  }

  return 0; // __WASI_ESUCCESS
}

// __wasi_errno_t __wasi_environ_sizes_get(size_t *environ_count, size_t
// *environ_buf_size);
Word wasi_unstable_environ_sizes_get(Word count_ptr, Word buf_size_ptr) {
  auto* context = contextOrEffectiveContext();
  const auto& envs = context->guest()->envs();
  if (!context->runtime()->setWord(count_ptr, Word(envs.size()))) {
    return 21; // __WASI_EFAULT
  }

  size_t size = 0;
  for (const auto& e : envs) {
    // len(key) + len(value) + 1('=') + 1(null terminator)
    size += e.first.size() + e.second.size() + 2;
  }
  if (!context->runtime()->setWord(buf_size_ptr, Word(size))) {
    return 21; // __WASI_EFAULT
  }
  return 0; // __WASI_ESUCCESS
}

// __wasi_errno_t __wasi_args_get(uint8_t **argv, uint8_t *argv_buf);
Word wasi_unstable_args_get(Word /*argv_array_ptr*/, Word /*argv_buf_ptr*/) {
  return 0; // __WASI_ESUCCESS
}

// __wasi_errno_t __wasi_args_sizes_get(size_t *argc, size_t *argv_buf_size);
Word wasi_unstable_args_sizes_get(Word argc_ptr, Word argv_buf_size_ptr) {
  auto* context = contextOrEffectiveContext();
  if (!context->runtime()->setWord(argc_ptr, Word(0))) {
    return 21; // __WASI_EFAULT
  }
  if (!context->runtime()->setWord(argv_buf_size_ptr, Word(0))) {
    return 21; // __WASI_EFAULT
  }
  return 0; // __WASI_ESUCCESS
}

// __wasi_errno_t __wasi_clock_time_get(uint32_t id, uint64_t precision, uint64_t* time);
Word wasi_unstable_clock_time_get(Word clock_id, uint64_t /*precision*/,
                                  Word result_time_uint64_ptr) {

  uint64_t result = 0;
  auto* context = contextOrEffectiveContext();
  switch (clock_id) {
  case 0 /* realtime */:
    result = context->getCurrentTimeNanoseconds();
    break;
  case 1 /* monotonic */:
    result = context->getMonotonicTimeNanoseconds();
    break;
  default:
    // process_cputime_id and thread_cputime_id are not supported yet.
    return 58; // __WASI_ENOTSUP
  }
  if (!context->guest()->setDatatype(result_time_uint64_ptr, result)) {
    return 21; // __WASI_EFAULT
  }
  return 0; // __WASI_ESUCCESS
}

Word wasi_unstable_fd_filestat_get(Word fd, Word statOut) {
  auto* context = contextOrEffectiveContext();
  context->error("wasi_unstable fd_filestat_get");
  return 0;
}
Word wasi_unstable_fd_pread(Word fd, Word iovs, Word iovs_len, int64_t offset, Word nread_ptr) {
  auto* context = contextOrEffectiveContext();
  context->error("wasi_unstable fd_pread");
  return 0;
}
Word wasi_unstable_fd_readdir(Word fd, Word buf, Word buf_len, int64_t cookie, Word bufused_ptr) {
  auto* context = contextOrEffectiveContext();
  context->error("wasi_unstable fd_readdir");
  return 0;
}
Word wasi_unstable_path_filestat_get(Word fd, Word flags, Word path, Word path_len, Word buf) {
  auto* context = contextOrEffectiveContext();
  context->error("wasi_unstable path_filestat_get");
  return 0;
}
Word wasi_unstable_path_remove_directory(Word fd, Word path, Word path_len) {
  auto* context = contextOrEffectiveContext();
  context->error("wasi_unstable path_remove_directory");
  return 0;
}
Word wasi_unstable_path_unlink_file(Word fd, Word path, Word path_len) {
  auto* context = contextOrEffectiveContext();
  context->error("wasi_unstable path_unlink_file");
  return 0;
}

} // namespace exports
} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
