// Copyright (c) 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_BROWSER_ACCESSIBILITY_ACCESSIBILITY_TREE_FORMATTER_BLINK_H_
#define CONTENT_BROWSER_ACCESSIBILITY_ACCESSIBILITY_TREE_FORMATTER_BLINK_H_

#include <stdint.h>

#include "core/host/accessibility/accessibility_tree_formatter_browser.h"

namespace host {

class CONTENT_EXPORT AccessibilityTreeFormatterBlink
    : public AccessibilityTreeFormatterBrowser {
 public:
  explicit AccessibilityTreeFormatterBlink();
  ~AccessibilityTreeFormatterBlink() override;

 private:
  const base::FilePath::StringType GetExpectedFileSuffix() override;
  const std::string GetAllowEmptyString() override;
  const std::string GetAllowString() override;
  const std::string GetDenyString() override;
  uint32_t ChildCount(const BrowserAccessibility& node) const override;
  BrowserAccessibility* GetChild(const BrowserAccessibility& node,
                                 uint32_t i) const override;
  void AddProperties(const BrowserAccessibility& node,
                     base::DictionaryValue* dict) override;
  std::string IntAttrToString(const BrowserAccessibility& node,
                              ax::mojom::IntAttribute attr,
                              int value) const;
  base::string16 ProcessTreeForOutput(
      const base::DictionaryValue& node,
      base::DictionaryValue* filtered_dict_result = nullptr) override;
};

}  // namespace host

#endif  // CONTENT_BROWSER_ACCESSIBILITY_ACCESSIBILITY_TREE_FORMATTER_BLINK_H_
