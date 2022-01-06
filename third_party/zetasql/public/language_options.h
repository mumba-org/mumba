//
// Copyright 2019 ZetaSQL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#ifndef ZETASQL_PUBLIC_LANGUAGE_OPTIONS_H_
#define ZETASQL_PUBLIC_LANGUAGE_OPTIONS_H_

#include <set>
#include <string>

#include "zetasql/proto/options.pb.h"
#include "zetasql/proto/public_options.pb.h"
#include "zetasql/proto/resolved_node_kind.pb.h"
#include "absl/base/attributes.h"
#include "zetasql/base/map_util.h"

namespace zetasql {

// This class contains options controlling the language that should be
// accepted, and the desired semantics.  This is used for libraries where
// behavior differs by language version, flags, or other options.
class LanguageOptions {
 public:
  LanguageOptions() = default;
  ~LanguageOptions() = default;
  LanguageOptions(const LanguageOptions&) = default;
  LanguageOptions(LanguageOptions&&) = default;
  LanguageOptions& operator=(const LanguageOptions&) = default;
  LanguageOptions& operator=(LanguageOptions&&) = default;

  // Deserialize LanguageOptions from proto.
  explicit LanguageOptions(const LanguageOptionsProto& proto);

  void Serialize(LanguageOptionsProto* proto) const;

  // Returns true if 'kind' is supported.
  ABSL_MUST_USE_RESULT bool SupportsStatementKind(
      const ResolvedNodeKind kind) const {
    return supported_statement_kinds_.empty() ||
           zetasql_base::ContainsKey(supported_statement_kinds_, kind);
  }

  // The provided set of ResolvedNodeKind enums indicates the statements
  // supported by the caller. The potentially supported statements are the
  // subclasses of ResolvedStatement. An empty set indicates no restrictions. If
  // ZetaSQL encounters a statement kind that is not supported during
  // analysis, it immediately returns an error.
  //
  // By default, the set includes only RESOLVED_QUERY_STMT, so callers must
  // explicitly opt in to support other statements.
  void SetSupportedStatementKinds(
      const std::set<ResolvedNodeKind>& supported_statement_kinds) {
    supported_statement_kinds_ = supported_statement_kinds;
  }

  // Equivalent to SetSupportedStatementKinds({}).
  void SetSupportsAllStatementKinds() {
    supported_statement_kinds_.clear();
  }

  // Adds <kind> to the set of supported statement kinds.
  void AddSupportedStatementKind(ResolvedNodeKind kind) {
    zetasql_base::InsertIfNotPresent(&supported_statement_kinds_, kind);
  }

  // Returns whether or not <feature> is enabled.
  ABSL_MUST_USE_RESULT bool LanguageFeatureEnabled(
      LanguageFeature feature) const {
    return zetasql_base::ContainsKey(enabled_language_features_, feature);
  }

  // Set the ZetaSQL LanguageVersion.  This is equivalent to enabling the
  // set of LanguageFeatures defined as part of that version, and disabling
  // all other LanguageFeatures.  The LanguageVersion itself is not stored.
  //
  // Calling this cancels out any previous calls to EnableLanguageFeature, so
  // EnableLanguageFeature would normally be called after SetLanguageVersion.
  void SetLanguageVersion(LanguageVersion version);

  // Get the set of features enabled as of a particular version.
  static std::set<LanguageFeature> GetLanguageFeaturesForVersion(
      LanguageVersion version);

  // Enables support for the specified <feature>.
  void EnableLanguageFeature(LanguageFeature feature) {
    zetasql_base::InsertIfNotPresent(&enabled_language_features_, feature);
  }
  // DEPRECATED.  This is the old name for EnableLanguageFeature.
  void EnableOptionalFeature(LanguageFeature feature) {
    EnableLanguageFeature(feature);
  }

  void SetEnabledLanguageFeatures(const std::set<LanguageFeature>& features) {
    enabled_language_features_ = features;
  }

  const std::set<LanguageFeature>& GetEnabledLanguageFeatures() const {
    return enabled_language_features_;
  }

  // Returns a comma-separated std::string listing enabled LanguageFeatures.
  std::string GetEnabledLanguageFeaturesAsString() const;
  static std::string ToString(const std::set<LanguageFeature>& features);

  void DisableAllLanguageFeatures() {
    enabled_language_features_.clear();
  }

  // Enable all optional features that are enabled in the idealized ZetaSQL
  // and are released to users.
  void EnableMaximumLanguageFeatures() {
    EnableMaximumLanguageFeatures(/*for_development=*/false);
  }

  // Enable all optional features that are enabled in the idealized ZetaSQL,
  // including features that are still under development. For internal ZetaSQL
  // use only.
  void EnableMaximumLanguageFeaturesForDevelopment() {
    EnableMaximumLanguageFeatures(/*for_development=*/true);
  }

  // Helper that returns a LanguageOptions object that is equivalent to what
  // results from calling EnableMaximumLanguageFeatures().
  static LanguageOptions MaximumFeatures();

  void set_name_resolution_mode(NameResolutionMode mode) {
    name_resolution_mode_ = mode;
  }
  NameResolutionMode name_resolution_mode() const {
    return name_resolution_mode_;
  }

  void set_product_mode(ProductMode mode) {
    product_mode_ = mode;
  }
  ProductMode product_mode() const {
    return product_mode_;
  }

  bool SupportsProtoTypes() const {
    // Protos are unsupported in EXTERNAL mode.
    return product_mode_ != ProductMode::PRODUCT_EXTERNAL;
  }

  void set_error_on_deprecated_syntax(bool value) {
    error_on_deprecated_syntax_ = value;
  }
  ABSL_MUST_USE_RESULT bool error_on_deprecated_syntax() const {
    return error_on_deprecated_syntax_;
  }

 private:
  // Enable all optional features that are enabled in the idealized ZetaSQL.
  // If 'for_development' is false, features that are still under development
  // are excluded.
  void EnableMaximumLanguageFeatures(bool for_development);

  // ======================================================================
  // NOTE: Please update options.proto and LanguageOptions.java accordingly
  // when adding new fields here.
  // ======================================================================

  // The ResolvedNodeKinds supported by the backend, e.g.,
  // zetasql::RESOLVED_QUERY_STMT. An empty set, the default, indicates no
  // restrictions.
  std::set<ResolvedNodeKind> supported_statement_kinds_ = {RESOLVED_QUERY_STMT};

  // This can be used to select strict name resolution mode.
  // In strict mode, implicit column names cannot be used unqualified.
  // This ensures that existing queries will not be broken if additional
  // elements are added to the schema in the future.
  // See (broken link) for full details.
  NameResolutionMode name_resolution_mode_ = NAME_RESOLUTION_DEFAULT;

  // This identifies whether ZetaSQL works in INTERNAL (inside Google) mode,
  // or in EXTERNAL (exposed to non-Goolers in the products such as Cloud).
  // See (broken link) for details.
  ProductMode product_mode_ = PRODUCT_INTERNAL;

  // This set of LanguageFeatures indicates which features are supported and
  // opted into by the caller.  An empty set indicates no optional features
  // are supported.  If a query includes unsupported features an error is
  // returned.
  std::set<LanguageFeature> enabled_language_features_;

  // If true, return an error on deprecated syntax rather than returning
  // deprecation_warnings.
  bool error_on_deprecated_syntax_ = false;

  // Copyable
};

}  // namespace zetasql

#endif  // ZETASQL_PUBLIC_LANGUAGE_OPTIONS_H_
