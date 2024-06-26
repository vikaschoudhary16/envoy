#include "source/extensions/matching/input_matchers/metadata/matcher.h"

namespace Envoy {
namespace Extensions {
namespace Matching {
namespace InputMatchers {
namespace Metadata {

Matcher::Matcher(Envoy::Matchers::ValueMatcherConstSharedPtr value_matcher, bool invert)
    : value_matcher_(value_matcher), invert_(invert) {}

bool Matcher::match(const Envoy::Matcher::MatchingDataType& input) {
  if (absl::holds_alternative<absl::monostate>(input)) {
    return false;
  }

  if (auto* ptr = absl::get_if<std::shared_ptr<::Envoy::Matcher::CustomMatchData>>(&input);
      ptr != nullptr) {
    Matching::Http::MetadataInput::MetadataMatchData* match_data =
        dynamic_cast<Matching::Http::MetadataInput::MetadataMatchData*>((*ptr).get());
    if (match_data != nullptr) {
      return value_matcher_->match(match_data->value_) ^ invert_;
    }
  }
  return false;
}

} // namespace Metadata
} // namespace InputMatchers
} // namespace Matching
} // namespace Extensions
} // namespace Envoy
