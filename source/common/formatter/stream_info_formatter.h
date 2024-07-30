#pragma once

#include <bitset>
#include <functional>
#include <list>
#include <regex>
#include <string>
#include <vector>

#include "envoy/formatter/substitution_formatter.h"
#include "envoy/stream_info/stream_info.h"

#include "source/common/common/utility.h"
#include "source/common/formatter/substitution_format_utility.h"

#include "absl/container/flat_hash_map.h"
#include "absl/types/optional.h"

namespace Envoy {
namespace Formatter {

using StreamInfoFormatterProviderCreateFunc =
    std::function<StreamInfoFormatterProviderPtr(const std::string&, absl::optional<size_t>)>;

enum class DurationPrecision { Milliseconds, Microseconds, Nanoseconds };

enum class StreamInfoAddressFieldExtractionType { WithPort, WithoutPort, JustPort };

/**
 * Base formatter for formatting Metadata objects
 */
class MetadataFormatter : public StreamInfoFormatterProvider {
public:
  using GetMetadataFunction =
      std::function<const envoy::config::core::v3::Metadata*(const StreamInfo::StreamInfo&)>;
  MetadataFormatter(const std::string& filter_namespace, const std::vector<std::string>& path,
                    absl::optional<size_t> max_length, GetMetadataFunction get);

  // StreamInfoFormatterProvider
  absl::optional<std::string> format(const StreamInfo::StreamInfo& stream_info) const override;
  ProtobufWkt::Value formatValue(const StreamInfo::StreamInfo& stream_info) const override;

protected:
  absl::optional<std::string>
  formatMetadata(const envoy::config::core::v3::Metadata& metadata) const;
  ProtobufWkt::Value formatMetadataValue(const envoy::config::core::v3::Metadata& metadata) const;

private:
  std::string filter_namespace_;
  std::vector<std::string> path_;
  absl::optional<size_t> max_length_;
  GetMetadataFunction get_func_;
};

/**
 * FormatterProvider for DynamicMetadata from StreamInfo.
 */
class DynamicMetadataFormatter : public MetadataFormatter {
public:
  DynamicMetadataFormatter(const std::string& filter_namespace,
                           const std::vector<std::string>& path, absl::optional<size_t> max_length);
};

/**
 * FormatterProvider for ClusterMetadata from StreamInfo.
 */
class ClusterMetadataFormatter : public MetadataFormatter {
public:
  ClusterMetadataFormatter(const std::string& filter_namespace,
                           const std::vector<std::string>& path, absl::optional<size_t> max_length);
};

/**
 * FormatterProvider for UpstreamHostMetadata from StreamInfo.
 */
class UpstreamHostMetadataFormatter : public MetadataFormatter {
public:
  UpstreamHostMetadataFormatter(const std::string& filter_namespace,
                                const std::vector<std::string>& path,
                                absl::optional<size_t> max_length);
};

enum class FilterStateFormat { String, Proto, Field };

/**
 * StreamInfoFormatterProvider for FilterState from StreamInfo.
 */
class FilterStateFormatter : public StreamInfoFormatterProvider {
public:
  static std::unique_ptr<FilterStateFormatter>
  create(const std::string& format, const absl::optional<size_t>& max_length, bool is_upstream);

  FilterStateFormatter(const std::string& key, absl::optional<size_t> max_length,
                       bool serialize_as_string, bool is_upstream = false,
                       const std::string& field_name = "");

  // StreamInfoFormatterProvider
  absl::optional<std::string> format(const StreamInfo::StreamInfo&) const override;
  ProtobufWkt::Value formatValue(const StreamInfo::StreamInfo&) const override;

private:
  const Envoy::StreamInfo::FilterState::Object*
  filterState(const StreamInfo::StreamInfo& stream_info) const;

  std::string key_;
  absl::optional<size_t> max_length_;

  const bool is_upstream_;
  FilterStateFormat format_;
  std::string field_name_;
  StreamInfo::FilterState::ObjectFactory* factory_;
};

class CommonDurationFormatter : public StreamInfoFormatterProvider {
public:
  using TimePointGetter =
      std::function<absl::optional<MonotonicTime>(const StreamInfo::StreamInfo&)>;

  static std::unique_ptr<CommonDurationFormatter> create(absl::string_view sub_command);

  CommonDurationFormatter(TimePointGetter beg, TimePointGetter end,
                          DurationPrecision duration_precision)
      : time_point_beg_(std::move(beg)), time_point_end_(std::move(end)),
        duration_precision_(duration_precision) {}

  // StreamInfoFormatterProvider
  absl::optional<std::string> format(const StreamInfo::StreamInfo&) const override;
  ProtobufWkt::Value formatValue(const StreamInfo::StreamInfo&) const override;

  static const absl::flat_hash_map<absl::string_view, TimePointGetter> KnownTimePointGetters;

private:
  absl::optional<uint64_t> getDurationCount(const StreamInfo::StreamInfo& info) const;

  static TimePointGetter getTimePointGetterByName(absl::string_view name);

  static constexpr absl::string_view MillisecondsPrecision = "ms";
  static constexpr absl::string_view MicrosecondsPrecision = "us";
  static constexpr absl::string_view NanosecondsPrecision = "ns";

  static constexpr absl::string_view FirstDownstreamRxByteReceived =
      "DS_RX_BEG"; // Downstream request receiving begin.
  static constexpr absl::string_view LastDownstreamRxByteReceived =
      "DS_RX_END"; // Downstream request receiving end.
  static constexpr absl::string_view FirstUpstreamTxByteSent =
      "US_TX_BEG"; // Upstream request sending begin.
  static constexpr absl::string_view LastUpstreamTxByteSent =
      "US_TX_END"; // Upstream request sending end.
  static constexpr absl::string_view FirstUpstreamRxByteReceived =
      "US_RX_BEG"; // Upstream response receiving begin.
  static constexpr absl::string_view LastUpstreamRxByteReceived =
      "US_RX_END"; // Upstream response receiving end.
  static constexpr absl::string_view FirstDownstreamTxByteSent =
      "DS_TX_BEG"; // Downstream response sending begin.
  static constexpr absl::string_view LastDownstreamTxByteSent =
      "DS_TX_END"; // Downstream response sending end.

  TimePointGetter time_point_beg_;
  TimePointGetter time_point_end_;
  DurationPrecision duration_precision_;
};

/**
 * Base StreamInfoFormatterProvider for system times from StreamInfo.
 */
class SystemTimeFormatter : public StreamInfoFormatterProvider {
public:
  using TimeFieldExtractor =
      std::function<absl::optional<SystemTime>(const StreamInfo::StreamInfo& stream_info)>;
  using TimeFieldExtractorPtr = std::unique_ptr<TimeFieldExtractor>;

  SystemTimeFormatter(const std::string& format, TimeFieldExtractorPtr f);

  // StreamInfoFormatterProvider
  absl::optional<std::string> format(const StreamInfo::StreamInfo&) const override;
  ProtobufWkt::Value formatValue(const StreamInfo::StreamInfo&) const override;

private:
  const Envoy::DateFormatter date_formatter_;
  const TimeFieldExtractorPtr time_field_extractor_;
};

/**
 * SystemTimeFormatter (FormatterProvider) for request start time from StreamInfo.
 */
class StartTimeFormatter : public SystemTimeFormatter {
public:
  StartTimeFormatter(const std::string& format);
};

/**
 * SystemTimeFormatter (FormatterProvider) for downstream cert start time from the StreamInfo's
 * ConnectionInfo.
 */
class DownstreamPeerCertVStartFormatter : public SystemTimeFormatter {
public:
  DownstreamPeerCertVStartFormatter(const std::string& format);
};

/**
 * SystemTimeFormatter (FormatterProvider) for downstream cert end time from the StreamInfo's
 * ConnectionInfo.
 */
class DownstreamPeerCertVEndFormatter : public SystemTimeFormatter {
public:
  DownstreamPeerCertVEndFormatter(const std::string& format);
};

/**
 * SystemTimeFormatter (FormatterProvider) for upstream cert start time from the StreamInfo's
 * upstreamInfo.
 */
class UpstreamPeerCertVStartFormatter : public SystemTimeFormatter {
public:
  UpstreamPeerCertVStartFormatter(const std::string& format);
};

/**
 * SystemTimeFormatter (FormatterProvider) for upstream cert end time from the StreamInfo's
 * upstreamInfo.
 */
class UpstreamPeerCertVEndFormatter : public SystemTimeFormatter {
public:
  UpstreamPeerCertVEndFormatter(const std::string& format);
};

/**
 * FormatterProvider for environment. If no valid environment value then
 */
class EnvironmentFormatter : public StreamInfoFormatterProvider {
public:
  EnvironmentFormatter(const std::string& key, absl::optional<size_t> max_length);

  // StreamInfoFormatterProvider
  absl::optional<std::string> format(const StreamInfo::StreamInfo&) const override;
  ProtobufWkt::Value formatValue(const StreamInfo::StreamInfo&) const override;

private:
  ProtobufWkt::Value str_;
};

class DefaultBuiltInStreamInfoCommandParserFactory : public BuiltInStreamInfoCommandParserFactory {
public:
  std::string name() const override;
  StreamInfoCommandParserPtr createCommandParser() const override;
};

DECLARE_FACTORY(DefaultBuiltInStreamInfoCommandParserFactory);

} // namespace Formatter
} // namespace Envoy
