// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "gen/visibility.h"

#include <memory>

#include "base/strings/string_piece.h"
#include "base/strings/string_util.h"
#include "base/values.h"
#include "gen/err.h"
#include "gen/filesystem_utils.h"
#include "gen/item.h"
#include "gen/label.h"
#include "gen/scope.h"
#include "gen/value.h"
#include "gen/variables.h"

Visibility::Visibility() = default;

Visibility::~Visibility() = default;

bool Visibility::Set(const SourceDir& current_dir,
                     const Value& value,
                     Err* err) {
  patterns_.clear();

  if (!value.VerifyTypeIs(Value::LIST, err)) {
    CHECK(err->has_error());
    return false;
  }

  for (const auto& item : value.list_value()) {
    patterns_.push_back(LabelPattern::GetPattern(current_dir, item, err));
    if (err->has_error())
      return false;
  }
  return true;
}

void Visibility::SetPublic() {
  patterns_.clear();
  patterns_.push_back(
      LabelPattern(LabelPattern::RECURSIVE_DIRECTORY, SourceDir(),
      std::string(), Label()));
}

void Visibility::SetPrivate(const SourceDir& current_dir) {
  patterns_.clear();
  patterns_.push_back(
      LabelPattern(LabelPattern::DIRECTORY, current_dir, std::string(),
      Label()));
}

bool Visibility::CanSeeMe(const Label& label) const {
  return LabelPattern::VectorMatches(patterns_, label);
}

std::string Visibility::Describe(int indent, bool include_brackets) const {
  std::string outer_indent_string(indent, ' ');

  if (patterns_.empty())
    return outer_indent_string + "[] (no visibility)\n";

  std::string result;

  std::string inner_indent_string = outer_indent_string;
  if (include_brackets) {
    result += outer_indent_string + "[\n";
    // Indent the insides more if brackets are requested.
    inner_indent_string += "  ";
  }

  for (const auto& pattern : patterns_)
    result += inner_indent_string + pattern.Describe() + "\n";

  if (include_brackets)
    result += outer_indent_string + "]\n";
  return result;
}

std::unique_ptr<base::Value> Visibility::AsValue() const {
  auto res = std::make_unique<base::ListValue>();
  for (const auto& pattern : patterns_)
    res->AppendString(pattern.Describe());
  return std::move(res);
}

// static
bool Visibility::CheckItemVisibility(scoped_refptr<Item> from,
                                     scoped_refptr<Item> to,
                                     Err* err) {
  if (!to->visibility().CanSeeMe(from->label())) {
    std::string to_label = to->label().GetUserVisibleName(false);
    *err = Err(from->defined_from(), "Dependency not allowed.",
        "The item " + from->label().GetUserVisibleName(false) + "\n"
        "can not depend on " + to_label + "\n"
        "because it is not in " + to_label + "'s visibility list: " +
                   to->visibility().Describe(0, true));
    return false;
  }
  return true;
}

// static
bool Visibility::FillItemVisibility(scoped_refptr<Item> item, Scope* scope, Err* err) {
  const Value* vis_value = scope->GetValue(variables::kVisibility, true);
  if (vis_value)
    item->visibility().Set(scope->GetSourceDir(), *vis_value, err);
  else  // Default to public.
    item->visibility().SetPublic();
  return !err->has_error();
}
