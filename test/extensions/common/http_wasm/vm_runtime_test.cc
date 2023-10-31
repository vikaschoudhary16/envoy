
#include "source/extensions/common/http_wasm/vm_runtime.h"

#include "test/test_common/environment.h"
#include "test/test_common/utility.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "source/extensions/common/http_wasm/bytecode_util.h"

using testing::HasSubstr; // NOLINT
using testing::IsEmpty;   // NOLINT
using testing::Return;    // NOLINT

#define CONVERT_FUNCTION_WORD_TO_UINT32(_f)                                                        \
  &ConvertFunctionWordToUint32<decltype(_f), _f>::convertFunctionWordToUint32

namespace Envoy {
namespace Extensions {
namespace HttpFilters {
namespace HttpWasm {
class MockHostFunctions {
public:
  MOCK_METHOD(void, pong, (uint32_t), (const));
  MOCK_METHOD(uint32_t, random, (), (const));
};

MockHostFunctions* g_host_functions;

void pong(Word value) { g_host_functions->pong(convertWordToUint32(value)); }

Word random() { return {g_host_functions->random()}; }

// pong() with wrong number of arguments.
void badPong1() {}

// pong() with wrong return type.
Word badPong2(Word) { return 2; }

// pong() with wrong argument type.
double badPong3(double) { return 3; }

class RuntimeTest : public testing::TestWithParam<bool> {
public:
  void SetUp() override { // NOLINT(readability-identifier-naming)
    g_host_functions = new MockHostFunctions();
  }
  void TearDown() override { delete g_host_functions; }

  bool init(std::string code = {}) {
    runtime_ = createV8Runtime();
    if (runtime_.get() == nullptr) {
      return false;
    }

    if (code.empty()) {
      code = TestEnvironment::readFileToStringForTest(TestEnvironment::substitute(
          "{{ test_rundir }}/test/extensions/common/http_wasm/test_data/test_rust.wasm"));
    }

    // clang-format off
    std::string_view precompiled = {};
    // clang-format on

    std::string stripped;
    if (!BytecodeUtil::getStrippedSource(code, stripped)) {
      return false;
    }

    return runtime_->load(stripped, precompiled, {});
  }

protected:
  RuntimePtr runtime_;
};

TEST_F(RuntimeTest, V8BadCode) { ASSERT_FALSE(init("bad code")); }

TEST_F(RuntimeTest, V8Load) {
  ASSERT_TRUE(init());
  EXPECT_TRUE(runtime_->getEngineName() == "v8");
  EXPECT_TRUE(runtime_->cloneable() == Cloneable::CompiledBytecode);
  EXPECT_TRUE(runtime_->clone() != nullptr);
}

TEST_F(RuntimeTest, V8BadHostFunctions) {
  ASSERT_TRUE(init());

  runtime_->registerCallback("env", "random", &random, CONVERT_FUNCTION_WORD_TO_UINT32(random));
  EXPECT_FALSE(runtime_->link("test"));

  runtime_->registerCallback("env", "pong", &badPong1, CONVERT_FUNCTION_WORD_TO_UINT32(badPong1));
  EXPECT_FALSE(runtime_->link("test"));

  runtime_->registerCallback("env", "pong", &badPong2, CONVERT_FUNCTION_WORD_TO_UINT32(badPong2));
  EXPECT_FALSE(runtime_->link("test"));

  runtime_->registerCallback("env", "pong", &badPong3, CONVERT_FUNCTION_WORD_TO_UINT32(badPong3));
  EXPECT_FALSE(runtime_->link("test"));
}

TEST_F(RuntimeTest, V8BadModuleFunctions) {
  ASSERT_TRUE(init());

  runtime_->registerCallback("env", "pong", &pong, CONVERT_FUNCTION_WORD_TO_UINT32(pong));
  runtime_->registerCallback("env", "random", &random, CONVERT_FUNCTION_WORD_TO_UINT32(random));
  runtime_->link("test");

  WasmCallVoid<1> ping;
  WasmCallWord<3> sum;

  runtime_->getFunction("nonexistent", &ping);
  EXPECT_TRUE(ping == nullptr);

  runtime_->getFunction("nonexistent", &sum);
  EXPECT_TRUE(sum == nullptr);

  runtime_->getFunction("ping", &sum);
  EXPECT_TRUE(runtime_->isFailed());

  runtime_->getFunction("sum", &ping);
  EXPECT_TRUE(runtime_->isFailed());
}

TEST_F(RuntimeTest, V8FunctionCalls) {
  ASSERT_TRUE(init());

  runtime_->registerCallback("env", "pong", &pong, CONVERT_FUNCTION_WORD_TO_UINT32(pong));
  runtime_->registerCallback("env", "random", &random, CONVERT_FUNCTION_WORD_TO_UINT32(random));
  runtime_->link("test");

  WasmCallVoid<1> ping;
  runtime_->getFunction("ping", &ping);
  EXPECT_CALL(*g_host_functions, pong(42));
  ping(nullptr /* no context */, 42);

  WasmCallWord<1> lucky;
  runtime_->getFunction("lucky", &lucky);
  EXPECT_CALL(*g_host_functions, random()).WillRepeatedly(Return(42));
  EXPECT_EQ(0, lucky(nullptr /* no context */, 1).u64_);
  EXPECT_EQ(1, lucky(nullptr /* no context */, 42).u64_);

  WasmCallWord<3> sum;
  runtime_->getFunction("sum", &sum);
  EXPECT_EQ(42, sum(nullptr /* no context */, 13, 14, 15).u64_);

  WasmCallWord<2> div;
  runtime_->getFunction("div", &div);
  div(nullptr /* no context */, 42, 0);
  EXPECT_TRUE(runtime_->isFailed());

  WasmCallVoid<0> abort;
  runtime_->getFunction("abort", &abort);
  abort(nullptr /* no context */);
  EXPECT_TRUE(runtime_->isFailed());
}

TEST_F(RuntimeTest, V8Memory) {
  ASSERT_TRUE(init());

  runtime_->registerCallback("env", "pong", &pong, CONVERT_FUNCTION_WORD_TO_UINT32(pong));
  runtime_->registerCallback("env", "random", &random, CONVERT_FUNCTION_WORD_TO_UINT32(random));
  runtime_->link("test");

  EXPECT_EQ(runtime_->getMemorySize(), 65536 /* stack size requested at the build-time */);

  const uint64_t test_addr = 128;

  std::string set = "test";
  EXPECT_TRUE(runtime_->setMemory(test_addr, set.size(), set.data()));
  auto got = runtime_->getMemory(test_addr, set.size()).value();
  EXPECT_EQ(sizeof("test") - 1, got.size());
  EXPECT_STREQ("test", got.data());

  EXPECT_FALSE(runtime_->setMemory(1024 * 1024 /* out of bound */, 1 /* size */, nullptr));
  EXPECT_FALSE(runtime_->getMemory(1024 * 1024 /* out of bound */, 1 /* size */).has_value());

  Word word(0);
  EXPECT_TRUE(runtime_->setWord(test_addr, std::numeric_limits<uint32_t>::max()));
  EXPECT_TRUE(runtime_->getWord(test_addr, &word));
  EXPECT_EQ(std::numeric_limits<uint32_t>::max(), word.u64_);

  EXPECT_FALSE(runtime_->setWord(1024 * 1024 /* out of bound */, 1));
  EXPECT_FALSE(runtime_->getWord(1024 * 1024 /* out of bound */, &word));
}

} // namespace HttpWasm
} // namespace HttpFilters
} // namespace Extensions
} // namespace Envoy
