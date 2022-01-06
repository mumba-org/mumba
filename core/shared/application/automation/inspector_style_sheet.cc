/*
 * Copyright (C) 2010, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "core/shared/application/automation/inspector_style_sheet.h"

#include "core/shared/application/automation/network_dispatcher.h"
#include "core/shared/application/automation/css_dispatcher.h"

#include <algorithm>
#include "third_party/blink/renderer/bindings/core/v8/exception_state.h"
#include "third_party/blink/renderer/bindings/core/v8/script_regexp.h"
#include "third_party/blink/renderer/core/css/css_import_rule.h"
#include "third_party/blink/renderer/core/css/css_keyframe_rule.h"
#include "third_party/blink/renderer/core/css/css_keyframes_rule.h"
#include "third_party/blink/renderer/core/css/css_media_rule.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_supports_rule.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_observer.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/css_property_names.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_container.h"
#include "third_party/blink/renderer/core/svg/svg_style_element.h"
#include "third_party/blink/renderer/platform/wtf/allocator.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/text_position.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"


namespace application {

namespace {

static const blink::CSSParserContext* ParserContextForDocument(blink::Document* document) {
  // Fallback to an insecure context parser if no document is present.
  return document ? blink::CSSParserContext::Create(*document)
                  : blink::StrictCSSParserContext(blink::SecureContextMode::kInsecureContext);
}

// automation::StyleSheetOrigin ToStyleSheetOrigin(String source) {
//   if (source == "injected") {
//     return automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_INJECTED;
//   }
//   if (source == "user-agent") {
//     return automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_USER_AGENT;
//   }
//   if (source == "inspector") {
//     return automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_INSPECTOR;
//   }
//   if (source == "regular") {
//     return automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_REGULAR;
//   }
//   return automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_REGULAR;
// }

String FindMagicComment(const String& content, const String& name) {
  DCHECK(name.Find("=") == kNotFound);

  unsigned length = content.length();
  unsigned name_length = name.length();
  const bool kMultiline = true;

  size_t pos = length;
  size_t equal_sign_pos = 0;
  size_t closing_comment_pos = 0;
  while (true) {
    pos = content.ReverseFind(name, pos);
    if (pos == kNotFound)
      return g_empty_string;

    // Check for a /\/[\/*][@#][ \t]/ regexp (length of 4) before found name.
    if (pos < 4)
      return g_empty_string;
    pos -= 4;
    if (content[pos] != '/')
      continue;
    if ((content[pos + 1] != '/' || kMultiline) &&
        (content[pos + 1] != '*' || !kMultiline))
      continue;
    if (content[pos + 2] != '#' && content[pos + 2] != '@')
      continue;
    if (content[pos + 3] != ' ' && content[pos + 3] != '\t')
      continue;
    equal_sign_pos = pos + 4 + name_length;
    if (equal_sign_pos < length && content[equal_sign_pos] != '=')
      continue;
    if (kMultiline) {
      closing_comment_pos = content.Find("*/", equal_sign_pos + 1);
      if (closing_comment_pos == kNotFound)
        return g_empty_string;
    }

    break;
  }

  DCHECK(equal_sign_pos);
  DCHECK(!kMultiline || closing_comment_pos);
  size_t url_pos = equal_sign_pos + 1;
  String match = kMultiline
                     ? content.Substring(url_pos, closing_comment_pos - url_pos)
                     : content.Substring(url_pos);

  size_t new_line = match.Find("\n");
  if (new_line != kNotFound)
    match = match.Substring(0, new_line);
  match = match.StripWhiteSpace();

  String disallowed_chars("\"' \t");
  for (unsigned i = 0; i < match.length(); ++i) {
    if (disallowed_chars.find(match[i]) != kNotFound)
      return g_empty_string;
  }

  return match;
}

void GetClassNamesFromRule(blink::CSSStyleRule* rule, HashSet<String>& unique_names) {
  const blink::CSSSelectorList& selector_list = rule->GetStyleRule()->SelectorList();
  if (!selector_list.IsValid())
    return;

  for (const blink::CSSSelector* sub_selector = selector_list.First(); sub_selector;
       sub_selector = blink::CSSSelectorList::Next(*sub_selector)) {
    const blink::CSSSelector* simple_selector = sub_selector;
    while (simple_selector) {
      if (simple_selector->Match() == blink::CSSSelector::kClass)
        unique_names.insert(simple_selector->Value());
      simple_selector = simple_selector->TagHistory();
    }
  }
}

class StyleSheetHandler final : public blink::CSSParserObserver {
  STACK_ALLOCATED();

 public:
  StyleSheetHandler(const String& parsed_text,
                    blink::Document* document,
                    blink::CSSRuleSourceDataList* result)
      : parsed_text_(parsed_text), document_(document), result_(result) {
    DCHECK(result_);
  }

 private:
  void StartRuleHeader(blink::StyleRule::RuleType, unsigned) override;
  void EndRuleHeader(unsigned) override;
  void ObserveSelector(unsigned start_offset, unsigned end_offset) override;
  void StartRuleBody(unsigned) override;
  void EndRuleBody(unsigned) override;
  void ObserveProperty(unsigned start_offset,
                       unsigned end_offset,
                       bool is_important,
                       bool is_parsed) override;
  void ObserveComment(unsigned start_offset, unsigned end_offset) override;

  void AddNewRuleToSourceTree(blink::CSSRuleSourceData*);
  blink::CSSRuleSourceData* PopRuleData();
  template <typename CharacterType>
  inline void SetRuleHeaderEnd(const CharacterType*, unsigned);

  const String& parsed_text_;
  blink::Member<blink::Document> document_;
  blink::Member<blink::CSSRuleSourceDataList> result_;
  blink::CSSRuleSourceDataList current_rule_data_stack_;
  blink::Member<blink::CSSRuleSourceData> current_rule_data_;
};

void StyleSheetHandler::StartRuleHeader(blink::StyleRule::RuleType type,
                                        unsigned offset) {
  // Pop off data for a previous invalid rule.
  if (current_rule_data_)
    current_rule_data_stack_.pop_back();

  blink::CSSRuleSourceData* data = new blink::CSSRuleSourceData(type);
  data->rule_header_range.start = offset;
  current_rule_data_ = data;
  current_rule_data_stack_.push_back(data);
}

template <typename CharacterType>
inline void StyleSheetHandler::SetRuleHeaderEnd(const CharacterType* data_start,
                                                unsigned list_end_offset) {
  while (list_end_offset > 1) {
    if (blink::IsHTMLSpace<CharacterType>(*(data_start + list_end_offset - 1)))
      --list_end_offset;
    else
      break;
  }

  current_rule_data_stack_.back()->rule_header_range.end = list_end_offset;
  if (!current_rule_data_stack_.back()->selector_ranges.IsEmpty())
    current_rule_data_stack_.back()->selector_ranges.back().end =
        list_end_offset;
}

void StyleSheetHandler::EndRuleHeader(unsigned offset) {
  DCHECK(!current_rule_data_stack_.IsEmpty());

  if (parsed_text_.Is8Bit())
    SetRuleHeaderEnd<LChar>(parsed_text_.Characters8(), offset);
  else
    SetRuleHeaderEnd<UChar>(parsed_text_.Characters16(), offset);
}

void StyleSheetHandler::ObserveSelector(unsigned start_offset,
                                        unsigned end_offset) {
  DCHECK(current_rule_data_stack_.size());
  current_rule_data_stack_.back()->selector_ranges.push_back(
      blink::SourceRange(start_offset, end_offset));
}

void StyleSheetHandler::StartRuleBody(unsigned offset) {
  current_rule_data_ = nullptr;
  DCHECK(!current_rule_data_stack_.IsEmpty());
  if (parsed_text_[offset] == '{')
    ++offset;  // Skip the rule body opening brace.
  current_rule_data_stack_.back()->rule_body_range.start = offset;
}

void StyleSheetHandler::EndRuleBody(unsigned offset) {
  // Pop off data for a previous invalid rule.
  if (current_rule_data_) {
    current_rule_data_ = nullptr;
    current_rule_data_stack_.pop_back();
  }
  DCHECK(!current_rule_data_stack_.IsEmpty());
  current_rule_data_stack_.back()->rule_body_range.end = offset;
  AddNewRuleToSourceTree(PopRuleData());
}

void StyleSheetHandler::AddNewRuleToSourceTree(blink::CSSRuleSourceData* rule) {
  if (current_rule_data_stack_.IsEmpty())
    result_->push_back(rule);
  else
    current_rule_data_stack_.back()->child_rules.push_back(rule);
}

blink::CSSRuleSourceData* StyleSheetHandler::PopRuleData() {
  DCHECK(!current_rule_data_stack_.IsEmpty());
  current_rule_data_ = nullptr;
  blink::CSSRuleSourceData* data = current_rule_data_stack_.back().Get();
  current_rule_data_stack_.pop_back();
  return data;
}

void StyleSheetHandler::ObserveProperty(unsigned start_offset,
                                        unsigned end_offset,
                                        bool is_important,
                                        bool is_parsed) {
  if (current_rule_data_stack_.IsEmpty() ||
      !current_rule_data_stack_.back()->HasProperties())
    return;

  DCHECK_LE(end_offset, parsed_text_.length());
  if (end_offset < parsed_text_.length() &&
      parsed_text_[end_offset] ==
          ';')  // Include semicolon into the property text.
    ++end_offset;

  DCHECK_LT(start_offset, end_offset);
  String property_string =
      parsed_text_.Substring(start_offset, end_offset - start_offset)
          .StripWhiteSpace();
  if (property_string.EndsWith(';'))
    property_string = property_string.Left(property_string.length() - 1);
  size_t colon_index = property_string.find(':');
  DCHECK_NE(colon_index, kNotFound);

  String name = property_string.Left(colon_index).StripWhiteSpace();
  String value =
      property_string.Substring(colon_index + 1, property_string.length())
          .StripWhiteSpace();
  current_rule_data_stack_.back()->property_data.push_back(
      blink::CSSPropertySourceData(name, value, is_important, false, is_parsed,
                            blink::SourceRange(start_offset, end_offset)));
}

void StyleSheetHandler::ObserveComment(unsigned start_offset,
                                       unsigned end_offset) {
  DCHECK_LE(end_offset, parsed_text_.length());

  if (current_rule_data_stack_.IsEmpty() ||
      !current_rule_data_stack_.back()->rule_header_range.end ||
      !current_rule_data_stack_.back()->HasProperties())
    return;

  // The lexer is not inside a property AND it is scanning a declaration-aware
  // rule body.
  String comment_text =
      parsed_text_.Substring(start_offset, end_offset - start_offset);

  DCHECK(comment_text.StartsWith("/*"));
  comment_text = comment_text.Substring(2);

  // Require well-formed comments.
  if (!comment_text.EndsWith("*/"))
    return;
  comment_text =
      comment_text.Substring(0, comment_text.length() - 2).StripWhiteSpace();
  if (comment_text.IsEmpty())
    return;

  // FIXME: Use the actual rule type rather than STYLE_RULE?
  blink::CSSRuleSourceDataList* source_data = new blink::CSSRuleSourceDataList();

  StyleSheetHandler handler(comment_text, document_, source_data);
  blink::CSSParser::ParseDeclarationListForInspector(
      ParserContextForDocument(document_), comment_text, handler);
  Vector<blink::CSSPropertySourceData>& comment_property_data = source_data->front()->property_data;
  if (comment_property_data.size() != 1)
    return;
  blink::CSSPropertySourceData& property_data = comment_property_data.at(0);
  bool parsed_ok = property_data.parsed_ok ||
                   property_data.name.StartsWith("-moz-") ||
                   property_data.name.StartsWith("-o-") ||
                   property_data.name.StartsWith("-webkit-") ||
                   property_data.name.StartsWith("-ms-");
  if (!parsed_ok || property_data.range.length() != comment_text.length())
    return;

  current_rule_data_stack_.back()->property_data.push_back(
      blink::CSSPropertySourceData(property_data.name, property_data.value, false,
                            true, true, blink::SourceRange(start_offset, end_offset)));
}

bool VerifyRuleText(blink::Document* document, const String& rule_text) {
  DEFINE_STATIC_LOCAL(String, bogus_property_name, ("-webkit-boguz-propertee"));
  blink::StyleSheetContents* style_sheet =
      blink::StyleSheetContents::Create(ParserContextForDocument(document));
  blink::CSSRuleSourceDataList* source_data = new blink::CSSRuleSourceDataList();
  String text = rule_text + " div { " + bogus_property_name + ": none; }";
  StyleSheetHandler handler(text, document, source_data);
  blink::CSSParser::ParseSheetForInspector(ParserContextForDocument(document),
                                    style_sheet, text, handler);
  unsigned rule_count = source_data->size();

  // Exactly two rules should be parsed.
  if (rule_count != 2)
    return false;

  // Added rule must be style rule.
  if (!source_data->at(0)->HasProperties())
    return false;

  Vector<blink::CSSPropertySourceData>& property_data =
      source_data->at(1)->property_data;
  unsigned property_count = property_data.size();

  // Exactly one property should be in rule.
  if (property_count != 1)
    return false;

  // Check for the property name.
  if (property_data.at(0).name != bogus_property_name)
    return false;

  return true;
}

bool VerifyStyleText(blink::Document* document, const String& text) {
  return VerifyRuleText(document, "div {" + text + "}");
}

bool VerifyKeyframeKeyText(blink::Document* document, const String& key_text) {
  blink::StyleSheetContents* style_sheet =
      blink::StyleSheetContents::Create(ParserContextForDocument(document));
  blink::CSSRuleSourceDataList* source_data = new blink::CSSRuleSourceDataList();
  String text = "@keyframes boguzAnim { " + key_text +
                " { -webkit-boguz-propertee : none; } }";
  StyleSheetHandler handler(text, document, source_data);
  blink::CSSParser::ParseSheetForInspector(ParserContextForDocument(document),
                                    style_sheet, text, handler);

  // Exactly one should be parsed.
  unsigned rule_count = source_data->size();
  if (rule_count != 1 || source_data->at(0)->type != blink::StyleRule::kKeyframes)
    return false;

  const blink::CSSRuleSourceData& keyframe_data = *source_data->at(0);
  if (keyframe_data.child_rules.size() != 1 ||
      keyframe_data.child_rules.at(0)->type != blink::StyleRule::kKeyframe)
    return false;

  // Exactly one property should be in keyframe rule.
  const unsigned property_count =
      keyframe_data.child_rules.at(0)->property_data.size();
  if (property_count != 1)
    return false;

  return true;
}

bool VerifySelectorText(blink::Document* document, const String& selector_text) {
  DEFINE_STATIC_LOCAL(String, bogus_property_name, ("-webkit-boguz-propertee"));
  blink::StyleSheetContents* style_sheet =
      blink::StyleSheetContents::Create(ParserContextForDocument(document));
  blink::CSSRuleSourceDataList* source_data = new blink::CSSRuleSourceDataList();
  String text = selector_text + " { " + bogus_property_name + ": none; }";
  StyleSheetHandler handler(text, document, source_data);
  blink::CSSParser::ParseSheetForInspector(ParserContextForDocument(document),
                                    style_sheet, text, handler);

  // Exactly one rule should be parsed.
  unsigned rule_count = source_data->size();
  if (rule_count != 1 || source_data->at(0)->type != blink::StyleRule::kStyle)
    return false;

  // Exactly one property should be in style rule.
  Vector<blink::CSSPropertySourceData>& property_data =
      source_data->at(0)->property_data;
  unsigned property_count = property_data.size();
  if (property_count != 1)
    return false;

  // Check for the property name.
  if (property_data.at(0).name != bogus_property_name)
    return false;

  return true;
}

bool VerifyMediaText(blink::Document* document, const String& media_text) {
  DEFINE_STATIC_LOCAL(String, bogus_property_name, ("-webkit-boguz-propertee"));
  blink::StyleSheetContents* style_sheet =
      blink::StyleSheetContents::Create(ParserContextForDocument(document));
  blink::CSSRuleSourceDataList* source_data = new blink::CSSRuleSourceDataList();
  String text = "@media " + media_text + " { div { " + bogus_property_name +
                ": none; } }";
  StyleSheetHandler handler(text, document, source_data);
  blink::CSSParser::ParseSheetForInspector(ParserContextForDocument(document),
                                    style_sheet, text, handler);

  // Exactly one media rule should be parsed.
  unsigned rule_count = source_data->size();
  if (rule_count != 1 || source_data->at(0)->type != blink::StyleRule::kMedia)
    return false;

  // Media rule should have exactly one style rule child.
  blink::CSSRuleSourceDataList& child_source_data = source_data->at(0)->child_rules;
  rule_count = child_source_data.size();
  if (rule_count != 1 || !child_source_data.at(0)->HasProperties())
    return false;

  // Exactly one property should be in style rule.
  Vector<blink::CSSPropertySourceData>& property_data =
      child_source_data.at(0)->property_data;
  unsigned property_count = property_data.size();
  if (property_count != 1)
    return false;

  // Check for the property name.
  if (property_data.at(0).name != bogus_property_name)
    return false;

  return true;
}

void FlattenSourceData(const blink::CSSRuleSourceDataList& data_list,
                       blink::CSSRuleSourceDataList* result) {
  for (blink::CSSRuleSourceData* data : data_list) {
    // The result->append()'ed types should be exactly the same as in
    // collectFlatRules().
    switch (data->type) {
      case blink::StyleRule::kStyle:
      case blink::StyleRule::kImport:
      case blink::StyleRule::kPage:
      case blink::StyleRule::kFontFace:
      case blink::StyleRule::kViewport:
      case blink::StyleRule::kKeyframe:
        result->push_back(data);
        break;
      case blink::StyleRule::kMedia:
      case blink::StyleRule::kSupports:
      case blink::StyleRule::kKeyframes:
        result->push_back(data);
        FlattenSourceData(data->child_rules, result);
        break;
      default:
        break;
    }
  }
}

blink::CSSRuleList* AsCSSRuleList(blink::CSSRule* rule) {
  if (!rule)
    return nullptr;

  if (rule->type() == blink::CSSRule::kMediaRule)
    return ToCSSMediaRule(rule)->cssRules();

  if (rule->type() == blink::CSSRule::kSupportsRule)
    return ToCSSSupportsRule(rule)->cssRules();

  if (rule->type() == blink::CSSRule::kKeyframesRule)
    return ToCSSKeyframesRule(rule)->cssRules();

  return nullptr;
}

template <typename RuleList>
void CollectFlatRules(RuleList rule_list, CSSRuleVector* result) {
  if (!rule_list)
    return;

  for (unsigned i = 0, size = rule_list->length(); i < size; ++i) {
    blink::CSSRule* rule = rule_list->item(i);

    // The result->append()'ed types should be exactly the same as in
    // flattenSourceData().
    switch (rule->type()) {
      case blink::CSSRule::kStyleRule:
      case blink::CSSRule::kImportRule:
      case blink::CSSRule::kCharsetRule:
      case blink::CSSRule::kPageRule:
      case blink::CSSRule::kFontFaceRule:
      case blink::CSSRule::kViewportRule:
      case blink::CSSRule::kKeyframeRule:
        result->push_back(rule);
        break;
      case blink::CSSRule::kMediaRule:
      case blink::CSSRule::kSupportsRule:
      case blink::CSSRule::kKeyframesRule:
        result->push_back(rule);
        CollectFlatRules(AsCSSRuleList(rule), result);
        break;
      default:
        break;
    }
  }
}

typedef HashMap<unsigned,
                unsigned,
                WTF::IntHash<unsigned>,
                WTF::UnsignedWithZeroKeyHashTraits<unsigned>>
    IndexMap;

void Diff(const Vector<String>& list_a,
          const Vector<String>& list_b,
          IndexMap* a_to_b,
          IndexMap* b_to_a) {
  // Cut of common prefix.
  size_t start_offset = 0;
  while (start_offset < list_a.size() && start_offset < list_b.size()) {
    if (list_a.at(start_offset) != list_b.at(start_offset))
      break;
    a_to_b->Set(start_offset, start_offset);
    b_to_a->Set(start_offset, start_offset);
    ++start_offset;
  }

  // Cut of common suffix.
  size_t end_offset = 0;
  while (end_offset < list_a.size() - start_offset &&
         end_offset < list_b.size() - start_offset) {
    size_t index_a = list_a.size() - end_offset - 1;
    size_t index_b = list_b.size() - end_offset - 1;
    if (list_a.at(index_a) != list_b.at(index_b))
      break;
    a_to_b->Set(index_a, index_b);
    b_to_a->Set(index_b, index_a);
    ++end_offset;
  }

  int n = list_a.size() - start_offset - end_offset;
  int m = list_b.size() - start_offset - end_offset;

  // If we mapped either of arrays, we have no more work to do.
  if (n == 0 || m == 0)
    return;

  int** diff = new int*[n];
  int** backtrack = new int*[n];
  for (int i = 0; i < n; ++i) {
    diff[i] = new int[m];
    backtrack[i] = new int[m];
  }

  // Compute longest common subsequence of two cssom models.
  for (int i = 0; i < n; ++i) {
    for (int j = 0; j < m; ++j) {
      int max = 0;
      int track = 0;

      if (i > 0 && diff[i - 1][j] > max) {
        max = diff[i - 1][j];
        track = 1;
      }

      if (j > 0 && diff[i][j - 1] > max) {
        max = diff[i][j - 1];
        track = 2;
      }

      if (list_a.at(i + start_offset) == list_b.at(j + start_offset)) {
        int value = i > 0 && j > 0 ? diff[i - 1][j - 1] + 1 : 1;
        if (value > max) {
          max = value;
          track = 3;
        }
      }

      diff[i][j] = max;
      backtrack[i][j] = track;
    }
  }

  // Backtrack and add missing mapping.
  int i = n - 1, j = m - 1;
  while (i >= 0 && j >= 0 && backtrack[i][j]) {
    switch (backtrack[i][j]) {
      case 1:
        i -= 1;
        break;
      case 2:
        j -= 1;
        break;
      case 3:
        a_to_b->Set(i + start_offset, j + start_offset);
        b_to_a->Set(j + start_offset, i + start_offset);
        i -= 1;
        j -= 1;
        break;
      default:
        NOTREACHED();
    }
  }

  for (int i = 0; i < n; ++i) {
    delete[] diff[i];
    delete[] backtrack[i];
  }
  delete[] diff;
  delete[] backtrack;
}

String CanonicalCSSText(blink::CSSRule* rule) {
  if (rule->type() != blink::CSSRule::kStyleRule)
    return rule->cssText();
  blink::CSSStyleRule* style_rule = ToCSSStyleRule(rule);

  Vector<String> property_names;
  blink::CSSStyleDeclaration* style = style_rule->style();
  for (unsigned i = 0; i < style->length(); ++i)
    property_names.push_back(style->item(i));

  std::sort(property_names.begin(), property_names.end(),
            WTF::CodePointCompareLessThan);

  StringBuilder builder;
  builder.Append(style_rule->selectorText());
  builder.Append('{');
  for (unsigned i = 0; i < property_names.size(); ++i) {
    String name = property_names.at(i);
    builder.Append(' ');
    builder.Append(name);
    builder.Append(':');
    builder.Append(style->getPropertyValue(name));
    if (!style->getPropertyPriority(name).IsEmpty()) {
      builder.Append(' ');
      builder.Append(style->getPropertyPriority(name));
    }
    builder.Append(';');
  }
  builder.Append('}');

  return builder.ToString();
}

}  // namespace

enum MediaListSource {
  kMediaListSourceLinkedSheet,
  kMediaListSourceInlineSheet,
  kMediaListSourceMediaRule,
  kMediaListSourceImportRule
};

automation::SourceRangePtr InspectorStyleSheetBase::BuildSourceRangeObject(const blink::SourceRange& range) {
  const LineEndings* line_endings = this->GetLineEndings();
  if (!line_endings)
    return nullptr;
  TextPosition start =
      TextPosition::FromOffsetAndLineEndings(range.start, *line_endings);
  TextPosition end =
      TextPosition::FromOffsetAndLineEndings(range.end, *line_endings);

  automation::SourceRangePtr result = automation::SourceRange::New();
  result->start_line = start.line_.ZeroBasedInt();
  result->start_column = start.column_.ZeroBasedInt();
  result->end_line = end.line_.ZeroBasedInt();
  result->end_column = end.column_.ZeroBasedInt();
  return result;
}

InspectorStyle* InspectorStyle::Create(
  blink::CSSStyleDeclaration* style,
  blink::CSSRuleSourceData* source_data,
  InspectorStyleSheetBase* parent_style_sheet) {
  return new InspectorStyle(style, source_data, parent_style_sheet);
}

InspectorStyle::InspectorStyle(blink::CSSStyleDeclaration* style,
                               blink::CSSRuleSourceData* source_data,
                               InspectorStyleSheetBase* parent_style_sheet)
    : style_(style),
      source_data_(source_data),
      parent_style_sheet_(parent_style_sheet) {
  DCHECK(style_);
}

InspectorStyle::~InspectorStyle() = default;

automation::CSSStylePtr InspectorStyle::BuildObjectForStyle() {
  automation::CSSStylePtr result = StyleWithProperties();
  if (source_data_) {
    if (parent_style_sheet_ && !parent_style_sheet_->Id().IsEmpty())
      result->style_sheet_id = std::string(parent_style_sheet_->Id().Utf8().data(), parent_style_sheet_->Id().length());
    result->range = parent_style_sheet_->BuildSourceRangeObject(
        source_data_->rule_body_range);
    String sheet_text;
    bool success = parent_style_sheet_->GetText(&sheet_text);
    if (success) {
      const blink::SourceRange& body_range = source_data_->rule_body_range;
      String sheet_text_substr = sheet_text.Substring(
          body_range.start, body_range.end - body_range.start);
      result->css_text = std::string(sheet_text_substr.Utf8().data(), sheet_text_substr.length());
    }
  }

  return result;
}

bool InspectorStyle::StyleText(String* result) {
  if (!source_data_)
    return false;

  return TextForRange(source_data_->rule_body_range, result);
}

bool InspectorStyle::TextForRange(const blink::SourceRange& range, String* result) {
  String style_sheet_text;
  bool success = parent_style_sheet_->GetText(&style_sheet_text);
  if (!success)
    return false;

  DCHECK(0 <= range.start);
  DCHECK_LE(range.start, range.end);
  DCHECK_LE(range.end, style_sheet_text.length());
  *result = style_sheet_text.Substring(range.start, range.end - range.start);
  return true;
}

void InspectorStyle::PopulateAllProperties(
  Vector<blink::CSSPropertySourceData>& result) {
  HashSet<String> source_property_names;

  if (source_data_ && source_data_->HasProperties()) {
    Vector<blink::CSSPropertySourceData>& source_property_data =
        source_data_->property_data;
    for (const auto& data : source_property_data) {
      result.push_back(data);
      source_property_names.insert(data.name.DeprecatedLower());
    }
  }

  for (int i = 0, size = style_->length(); i < size; ++i) {
    String name = style_->item(i);
    if (!source_property_names.insert(name.DeprecatedLower()).is_new_entry)
      continue;

    String value = style_->getPropertyValue(name);
    if (value.IsEmpty())
      continue;
    bool important = !style_->getPropertyPriority(name).IsEmpty();
    if (important)
      value.append(" !important");
    result.push_back(blink::CSSPropertySourceData(
        name, value, !style_->getPropertyPriority(name).IsEmpty(), false, true,
        blink::SourceRange()));
  }
}

automation::CSSStylePtr InspectorStyle::StyleWithProperties() {
  std::vector<automation::CSSPropertyPtr> properties_object;
  std::vector<automation::ShorthandEntryPtr> shorthand_entries;
  HashSet<String> found_shorthands;

  Vector<blink::CSSPropertySourceData> properties;
  PopulateAllProperties(properties);

  for (auto& style_property : properties) {
    const blink::CSSPropertySourceData& property_entry = style_property;
    const String& name = property_entry.name;

    automation::CSSPropertyPtr property = automation::CSSProperty::New();
    property->name = std::string(name.Utf8().data(), name.length());
    property->value = std::string(property_entry.value.Utf8().data(), name.length());

    // Default "parsedOk" == true.
    if (!property_entry.parsed_ok)
      property->parsed_ok = false;
    String text;
    if (style_property.range.length() &&
        TextForRange(style_property.range, &text))
      property->text = std::string(text.Utf8().data(), text.length());
    if (property_entry.important)
      property->important = true;
    if (style_property.range.length()) {
      property->range = parent_style_sheet_
                             ? parent_style_sheet_->BuildSourceRangeObject(
                                   property_entry.range)
                             : nullptr;
      if (!property_entry.disabled) {
        property->implicit = false;
      }
      property->disabled = property_entry.disabled;
    } else if (!property_entry.disabled) {
      bool implicit = style_->IsPropertyImplicit(name);
      // Default "implicit" == false.
      if (implicit)
        property->implicit = true;

      String shorthand = style_->GetPropertyShorthand(name);
      if (!shorthand.IsEmpty()) {
        if (found_shorthands.insert(shorthand).is_new_entry) {
          automation::ShorthandEntryPtr entry = automation::ShorthandEntry::New();
          entry->name = std::string(shorthand.Utf8().data(), shorthand.length());
          entry->value = std::string(ShorthandValue(shorthand).Utf8().data());
          
          if (!style_->getPropertyPriority(name).IsEmpty())
            entry->important = true;
          shorthand_entries.push_back(std::move(entry));
        }
      }
    }
    properties_object.push_back(std::move(property));
  }

  automation::CSSStylePtr result = automation::CSSStyle::New();
  result->css_properties = std::move(properties_object);
  result->shorthand_entries = std::move(shorthand_entries);
  return result;
}

String InspectorStyle::ShorthandValue(const String& shorthand_property) {
  StringBuilder builder;
  String value = style_->getPropertyValue(shorthand_property);
  if (value.IsEmpty()) {
    for (unsigned i = 0; i < style_->length(); ++i) {
      String individual_property = style_->item(i);
      if (style_->GetPropertyShorthand(individual_property) !=
          shorthand_property)
        continue;
      if (style_->IsPropertyImplicit(individual_property))
        continue;
      String individual_value = style_->getPropertyValue(individual_property);
      if (individual_value == "initial")
        continue;
      if (!builder.IsEmpty())
        builder.Append(' ');
      builder.Append(individual_value);
    }
  } else {
    builder.Append(value);
  }

  if (!style_->getPropertyPriority(shorthand_property).IsEmpty())
    builder.Append(" !important");

  return builder.ToString();
}

void InspectorStyle::Trace(blink::Visitor* visitor) {
  visitor->Trace(style_);
  visitor->Trace(parent_style_sheet_);
  visitor->Trace(source_data_);
}

InspectorStyleSheetBase::InspectorStyleSheetBase(Listener* listener)
    : id_(blink::IdentifiersFactory::CreateIdentifier()),
      listener_(listener),
      line_endings_(std::make_unique<LineEndings>()) {}

void InspectorStyleSheetBase::OnStyleSheetTextChanged() {
  line_endings_ = std::make_unique<LineEndings>();
  if (GetListener())
    GetListener()->StyleSheetChanged(this);
}

automation::CSSStylePtr InspectorStyleSheetBase::BuildObjectForStyle(blink::CSSStyleDeclaration* style) {
  return GetInspectorStyle(style)->BuildObjectForStyle();
}

const LineEndings* InspectorStyleSheetBase::GetLineEndings() {
  if (line_endings_->size() > 0)
    return line_endings_.get();
  String text;
  if (GetText(&text))
    line_endings_ = WTF::GetLineEndings(text);
  return line_endings_.get();
}

bool InspectorStyleSheetBase::LineNumberAndColumnToOffset(
    unsigned line_number,
    unsigned column_number,
    unsigned* offset) {
  const LineEndings* endings = GetLineEndings();
  if (line_number >= endings->size())
    return false;
  unsigned characters_in_line =
      line_number > 0
          ? endings->at(line_number) - endings->at(line_number - 1) - 1
          : endings->at(0);
  if (column_number > characters_in_line)
    return false;
  TextPosition position(OrdinalNumber::FromZeroBasedInt(line_number),
                        OrdinalNumber::FromZeroBasedInt(column_number));
  *offset = position.ToOffset(*endings).ZeroBasedInt();
  return true;
}

InspectorStyleSheet* InspectorStyleSheet::Create(
    NetworkDispatcher* network_dispatcher,
    blink::CSSStyleSheet* page_style_sheet,
    automation::StyleSheetOrigin origin,
    const String& document_url,
    InspectorStyleSheetBase::Listener* listener,
    blink::InspectorResourceContainer* resource_container) {
  return new InspectorStyleSheet(network_dispatcher, page_style_sheet, origin,
                                 document_url, listener, resource_container);
}

InspectorStyleSheet::InspectorStyleSheet(
    NetworkDispatcher* network_dispatcher,
    blink::CSSStyleSheet* page_style_sheet,
    automation::StyleSheetOrigin origin,
    const String& document_url,
    InspectorStyleSheetBase::Listener* listener,
    blink::InspectorResourceContainer* resource_container)
    : InspectorStyleSheetBase(listener),
      resource_container_(resource_container),
      network_dispatcher_(network_dispatcher),
      page_style_sheet_(page_style_sheet),
      origin_(origin),
      document_url_(document_url) {
  String text;
  bool success = InspectorStyleSheetText(&text);
  if (!success)
    success = InlineStyleSheetText(&text);
  if (!success)
    success = ResourceStyleSheetText(&text);
  if (success)
    InnerSetText(text, false);
}

InspectorStyleSheet::~InspectorStyleSheet() = default;

void InspectorStyleSheet::Trace(blink::Visitor* visitor) {
  visitor->Trace(resource_container_);
  //visitor->Trace(network_dispatcher_);
  visitor->Trace(page_style_sheet_);
  visitor->Trace(cssom_flat_rules_);
  visitor->Trace(parsed_flat_rules_);
  visitor->Trace(source_data_);
  InspectorStyleSheetBase::Trace(visitor);
}

static String StyleSheetURL(blink::CSSStyleSheet* page_style_sheet) {
  if (page_style_sheet && !page_style_sheet->Contents()->BaseURL().IsEmpty())
    return page_style_sheet->Contents()->BaseURL().GetString();
  return g_empty_string;
}

String InspectorStyleSheet::FinalURL() {
  String url = StyleSheetURL(page_style_sheet_.Get());
  return url.IsEmpty() ? document_url_ : url;
}

bool InspectorStyleSheet::SetText(const String& text, blink::ExceptionState&) {
  InnerSetText(text, true);
  page_style_sheet_->SetText(text);
  OnStyleSheetTextChanged();
  return true;
}

blink::CSSStyleRule* InspectorStyleSheet::SetRuleSelector(
  const blink::SourceRange& range,
  const String& text,
  blink::SourceRange* new_range,
  String* old_text,
  blink::ExceptionState& exception_state) {
  if (!VerifySelectorText(page_style_sheet_->OwnerDocument(), text)) {
    exception_state.ThrowDOMException(blink::kSyntaxError,
                                      "Selector or media text is not valid.");
    return nullptr;
  }

  blink::CSSRuleSourceData* source_data = FindRuleByHeaderRange(range);
  if (!source_data || !source_data->HasProperties()) {
    exception_state.ThrowDOMException(
        blink::kNotFoundError, "Source range didn't match existing source range");
    return nullptr;
  }

  blink::CSSRule* rule = RuleForSourceData(source_data);
  if (!rule || !rule->parentStyleSheet() ||
      rule->type() != blink::CSSRule::kStyleRule) {
    exception_state.ThrowDOMException(
        blink::kNotFoundError,
        "Source range didn't match existing style source range");
    return nullptr;
  }

  blink::CSSStyleRule* style_rule = CSSDispatcher::AsCSSStyleRule(rule);
  style_rule->setSelectorText(page_style_sheet_->OwnerDocument(), text);

  ReplaceText(source_data->rule_header_range, text, new_range, old_text);
  OnStyleSheetTextChanged();

  return style_rule;
}

blink::CSSKeyframeRule* InspectorStyleSheet::SetKeyframeKey(
    const blink::SourceRange& range,
    const String& text,
    blink::SourceRange* new_range,
    String* old_text,
    blink::ExceptionState& exception_state) {
  if (!VerifyKeyframeKeyText(page_style_sheet_->OwnerDocument(), text)) {
    exception_state.ThrowDOMException(blink::kSyntaxError,
                                      "Keyframe key text is not valid.");
    return nullptr;
  }

  blink::CSSRuleSourceData* source_data = FindRuleByHeaderRange(range);
  if (!source_data || !source_data->HasProperties()) {
    exception_state.ThrowDOMException(
        blink::kNotFoundError, "Source range didn't match existing source range");
    return nullptr;
  }

  blink::CSSRule* rule = RuleForSourceData(source_data);
  if (!rule || !rule->parentStyleSheet() ||
      rule->type() != blink::CSSRule::kKeyframeRule) {
    exception_state.ThrowDOMException(
        blink::kNotFoundError,
        "Source range didn't match existing style source range");
    return nullptr;
  }

  blink::CSSKeyframeRule* keyframe_rule = ToCSSKeyframeRule(rule);
  keyframe_rule->setKeyText(text, exception_state);

  ReplaceText(source_data->rule_header_range, text, new_range, old_text);
  OnStyleSheetTextChanged();

  return keyframe_rule;
}

blink::CSSRule* InspectorStyleSheet::SetStyleText(const blink::SourceRange& range,
                                                  const String& text,
                                                  blink::SourceRange* new_range,
                                                  String* old_text,
                                                  blink::ExceptionState& exception_state) {
  if (!VerifyStyleText(page_style_sheet_->OwnerDocument(), text)) {
    exception_state.ThrowDOMException(blink::kSyntaxError, "Style text is not valid.");
    return nullptr;
  }

  blink::CSSRuleSourceData* source_data = FindRuleByBodyRange(range);
  if (!source_data || !source_data->HasProperties()) {
    exception_state.ThrowDOMException(
        blink::kNotFoundError,
        "Source range didn't match existing style source range");
    return nullptr;
  }

  blink::CSSRule* rule = RuleForSourceData(source_data);
  if (!rule || !rule->parentStyleSheet() ||
      (rule->type() != blink::CSSRule::kStyleRule &&
       rule->type() != blink::CSSRule::kKeyframeRule)) {
    exception_state.ThrowDOMException(
        blink::kNotFoundError,
        "Source range didn't match existing style source range");
    return nullptr;
  }

  blink::CSSStyleDeclaration* style = nullptr;
  if (rule->type() == blink::CSSRule::kStyleRule)
    style = ToCSSStyleRule(rule)->style();
  else if (rule->type() == blink::CSSRule::kKeyframeRule)
    style = ToCSSKeyframeRule(rule)->style();
  style->setCSSText(page_style_sheet_->OwnerDocument(), text, exception_state);

  ReplaceText(source_data->rule_body_range, text, new_range, old_text);
  OnStyleSheetTextChanged();

  return rule;
}

blink::CSSMediaRule* InspectorStyleSheet::SetMediaRuleText(
    const blink::SourceRange& range,
    const String& text,
    blink::SourceRange* new_range,
    String* old_text,
    blink::ExceptionState& exception_state) {
  if (!VerifyMediaText(page_style_sheet_->OwnerDocument(), text)) {
    exception_state.ThrowDOMException(blink::kSyntaxError,
                                      "Selector or media text is not valid.");
    return nullptr;
  }

  blink::CSSRuleSourceData* source_data = FindRuleByHeaderRange(range);
  if (!source_data || !source_data->HasMedia()) {
    exception_state.ThrowDOMException(
        blink::kNotFoundError, "Source range didn't match existing source range");
    return nullptr;
  }

  blink::CSSRule* rule = RuleForSourceData(source_data);
  if (!rule || !rule->parentStyleSheet() ||
      rule->type() != blink::CSSRule::kMediaRule) {
    exception_state.ThrowDOMException(
        blink::kNotFoundError,
        "Source range didn't match existing style source range");
    return nullptr;
  }

  blink::CSSMediaRule* media_rule = CSSDispatcher::AsCSSMediaRule(rule);
  media_rule->media()->setMediaText(text);

  ReplaceText(source_data->rule_header_range, text, new_range, old_text);
  OnStyleSheetTextChanged();

  return media_rule;
}

blink::CSSRuleSourceData* InspectorStyleSheet::RuleSourceDataAfterSourceRange(
    const blink::SourceRange& source_range) {
  DCHECK(source_data_);
  unsigned index = 0;
  for (; index < source_data_->size(); ++index) {
    blink::CSSRuleSourceData* sd = source_data_->at(index).Get();
    if (sd->rule_header_range.start >= source_range.end)
      break;
  }
  return index < source_data_->size() ? source_data_->at(index).Get() : nullptr;
}

blink::CSSStyleRule* InspectorStyleSheet::InsertCSSOMRuleInStyleSheet(
  blink::CSSRule* insert_before,
  const String& rule_text,
  blink::ExceptionState& exception_state) {
  unsigned index = 0;
  for (; index < page_style_sheet_->length(); ++index) {
    blink::CSSRule* rule = page_style_sheet_->item(index);
    if (rule == insert_before)
      break;
  }

  page_style_sheet_->insertRule(rule_text, index, exception_state);
  blink::CSSRule* rule = page_style_sheet_->item(index);
  blink::CSSStyleRule* style_rule = CSSDispatcher::AsCSSStyleRule(rule);
  if (!style_rule) {
    page_style_sheet_->deleteRule(index, ASSERT_NO_EXCEPTION);
    exception_state.ThrowDOMException(
        blink::kSyntaxError,
        "The rule '" + rule_text + "' could not be added in style sheet.");
    return nullptr;
  }
  return style_rule;
}

blink::CSSStyleRule* InspectorStyleSheet::InsertCSSOMRuleInMediaRule(
  blink::CSSMediaRule* media_rule,
  blink::CSSRule* insert_before,
  const String& rule_text,
  blink::ExceptionState& exception_state) {
  unsigned index = 0;
  for (; index < media_rule->length(); ++index) {
    blink::CSSRule* rule = media_rule->Item(index);
    if (rule == insert_before)
      break;
  }

  media_rule->insertRule(page_style_sheet_->OwnerDocument(), rule_text, index,
                         exception_state);
  blink::CSSRule* rule = media_rule->Item(index);
  blink::CSSStyleRule* style_rule = CSSDispatcher::AsCSSStyleRule(rule);
  if (!style_rule) {
    media_rule->deleteRule(index, ASSERT_NO_EXCEPTION);
    exception_state.ThrowDOMException(
        blink::kSyntaxError,
        "The rule '" + rule_text + "' could not be added in media rule.");
    return nullptr;
  }
  return style_rule;
}

blink::CSSStyleRule* InspectorStyleSheet::InsertCSSOMRuleBySourceRange(
  const blink::SourceRange& source_range,
  const String& rule_text,
  blink::ExceptionState& exception_state) {
  DCHECK(source_data_);

  blink::CSSRuleSourceData* containing_rule_source_data = nullptr;
  for (size_t i = 0; i < source_data_->size(); ++i) {
    blink::CSSRuleSourceData* rule_source_data = source_data_->at(i).Get();
    if (rule_source_data->rule_header_range.start < source_range.start &&
        source_range.start < rule_source_data->rule_body_range.start) {
      exception_state.ThrowDOMException(
          blink::kNotFoundError, "Cannot insert rule inside rule selector.");
      return nullptr;
    }
    if (source_range.start < rule_source_data->rule_body_range.start ||
        rule_source_data->rule_body_range.end < source_range.start)
      continue;
    if (!containing_rule_source_data ||
        containing_rule_source_data->rule_body_range.length() >
            rule_source_data->rule_body_range.length())
      containing_rule_source_data = rule_source_data;
  }

  blink::CSSRuleSourceData* insert_before =
      RuleSourceDataAfterSourceRange(source_range);
  blink::CSSRule* insert_before_rule = RuleForSourceData(insert_before);

  if (!containing_rule_source_data)
    return InsertCSSOMRuleInStyleSheet(insert_before_rule, rule_text,
                                       exception_state);

  blink::CSSRule* rule = RuleForSourceData(containing_rule_source_data);
  if (!rule || rule->type() != blink::CSSRule::kMediaRule) {
    exception_state.ThrowDOMException(blink::kNotFoundError,
                                      "Cannot insert rule in non-media rule.");
    return nullptr;
  }

  return InsertCSSOMRuleInMediaRule(ToCSSMediaRule(rule), insert_before_rule,
                                    rule_text, exception_state);
}

blink::CSSStyleRule* InspectorStyleSheet::AddRule(const String& rule_text,
                                                  const blink::SourceRange& location,
                                                  blink::SourceRange* added_range,
                                                  blink::ExceptionState& exception_state) {
  if (location.start != location.end) {
    exception_state.ThrowDOMException(blink::kNotFoundError,
                                      "Source range must be collapsed.");
    return nullptr;
  }

  if (!VerifyRuleText(page_style_sheet_->OwnerDocument(), rule_text)) {
    exception_state.ThrowDOMException(blink::kSyntaxError, "Rule text is not valid.");
    return nullptr;
  }

  if (!source_data_) {
    exception_state.ThrowDOMException(blink::kNotFoundError, "Style is read-only.");
    return nullptr;
  }

  blink::CSSStyleRule* style_rule =
      InsertCSSOMRuleBySourceRange(location, rule_text, exception_state);
  if (exception_state.HadException())
    return nullptr;

  ReplaceText(location, rule_text, added_range, nullptr);
  OnStyleSheetTextChanged();
  return style_rule;
}

bool InspectorStyleSheet::DeleteRule(const blink::SourceRange& range,
                                     blink::ExceptionState& exception_state) {
  if (!source_data_) {
    exception_state.ThrowDOMException(blink::kNotFoundError, "Style is read-only.");
    return false;
  }

  // Find index of CSSRule that entirely belongs to the range.
  blink::CSSRuleSourceData* found_data = nullptr;

  for (size_t i = 0; i < source_data_->size(); ++i) {
    blink::CSSRuleSourceData* rule_source_data = source_data_->at(i).Get();
    unsigned rule_start = rule_source_data->rule_header_range.start;
    unsigned rule_end = rule_source_data->rule_body_range.end + 1;
    bool start_belongs = rule_start >= range.start && rule_start < range.end;
    bool end_belongs = rule_end > range.start && rule_end <= range.end;

    if (start_belongs != end_belongs)
      break;
    if (!start_belongs)
      continue;
    if (!found_data || found_data->rule_body_range.length() >
                           rule_source_data->rule_body_range.length())
      found_data = rule_source_data;
  }
  blink::CSSRule* rule = RuleForSourceData(found_data);
  if (!rule) {
    exception_state.ThrowDOMException(
        blink::kNotFoundError, "No style rule could be found in given range.");
    return false;
  }
  blink::CSSStyleSheet* style_sheet = rule->parentStyleSheet();
  if (!style_sheet) {
    exception_state.ThrowDOMException(blink::kNotFoundError,
                                      "No parent stylesheet could be found.");
    return false;
  }
  blink::CSSRule* parent_rule = rule->parentRule();
  if (parent_rule) {
    if (parent_rule->type() != blink::CSSRule::kMediaRule) {
      exception_state.ThrowDOMException(
          blink::kNotFoundError, "Cannot remove rule from non-media rule.");
      return false;
    }
    blink::CSSMediaRule* parent_media_rule = ToCSSMediaRule(parent_rule);
    size_t index = 0;
    while (index < parent_media_rule->length() &&
           parent_media_rule->Item(index) != rule)
      ++index;
    DCHECK_LT(index, parent_media_rule->length());
    parent_media_rule->deleteRule(index, exception_state);
  } else {
    size_t index = 0;
    while (index < style_sheet->length() && style_sheet->item(index) != rule)
      ++index;
    DCHECK_LT(index, style_sheet->length());
    style_sheet->deleteRule(index, exception_state);
  }
  // |rule| MAY NOT be addressed after this line!

  if (exception_state.HadException())
    return false;

  ReplaceText(range, "", nullptr, nullptr);
  OnStyleSheetTextChanged();
  return true;
}

std::vector<std::string> InspectorStyleSheet::CollectClassNames() {
  HashSet<String> unique_names;
  std::vector<std::string> result;

  for (size_t i = 0; i < parsed_flat_rules_.size(); ++i) {
    if (parsed_flat_rules_.at(i)->type() == blink::CSSRule::kStyleRule)
      GetClassNamesFromRule(ToCSSStyleRule(parsed_flat_rules_.at(i)),
                            unique_names);
  }
  for (const String& class_name : unique_names)
    result.push_back(std::string(class_name.Utf8().data()));
  return result;
}

void InspectorStyleSheet::ReplaceText(const blink::SourceRange& range,
                                      const String& text,
                                      blink::SourceRange* new_range,
                                      String* old_text) {
  String sheet_text = text_;
  if (old_text)
    *old_text = sheet_text.Substring(range.start, range.length());
  sheet_text.replace(range.start, range.length(), text);
  if (new_range)
    *new_range = blink::SourceRange(range.start, range.start + text.length());
  InnerSetText(sheet_text, true);
}

void InspectorStyleSheet::InnerSetText(const String& text,
                                       bool mark_as_locally_modified) {
  blink::CSSRuleSourceDataList* rule_tree = new blink::CSSRuleSourceDataList();
  blink::StyleSheetContents* style_sheet = blink::StyleSheetContents::Create(
      page_style_sheet_->Contents()->ParserContext());
  StyleSheetHandler handler(text, page_style_sheet_->OwnerDocument(),
                            rule_tree);
  blink::CSSParser::ParseSheetForInspector(
      page_style_sheet_->Contents()->ParserContext(), style_sheet, text,
      handler);
  blink::CSSStyleSheet* source_data_sheet = nullptr;
  if (ToCSSImportRule(page_style_sheet_->ownerRule())) {
    source_data_sheet = blink::CSSStyleSheet::Create(
        style_sheet, ToCSSImportRule(page_style_sheet_->ownerRule()));
  } else {
    source_data_sheet =
        blink::CSSStyleSheet::Create(style_sheet, *page_style_sheet_->ownerNode());
  }

  parsed_flat_rules_.clear();
  CollectFlatRules(source_data_sheet, &parsed_flat_rules_);

  source_data_ = new blink::CSSRuleSourceDataList();
  FlattenSourceData(*rule_tree, source_data_.Get());
  text_ = text;

  if (mark_as_locally_modified) {
    blink::Element* element = OwnerStyleElement();
    if (element)
      resource_container_->StoreStyleElementContent(
          blink::DOMNodeIds::IdForNode(element), text);
    else if (origin_ == automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_INSPECTOR)
      resource_container_->StoreStyleElementContent(
          blink::DOMNodeIds::IdForNode(page_style_sheet_->OwnerDocument()), text);
    else
      resource_container_->StoreStyleSheetContent(FinalURL(), text);
  }
}

automation::CSSStyleSheetHeaderPtr InspectorStyleSheet::BuildObjectForStyleSheetInfo() {
  blink::CSSStyleSheet* style_sheet = PageStyleSheet();
  if (!style_sheet)
    return nullptr;

  blink::Document* document = style_sheet->OwnerDocument();
  blink::LocalFrame* frame = document ? document->GetFrame() : nullptr;
  String text;
  GetText(&text);
  automation::CSSStyleSheetHeaderPtr result = automation::CSSStyleSheetHeader::New();
  result->style_sheet_id = std::string(Id().Utf8().data(), Id().length());
  result->origin = origin_;
  result->disabled = style_sheet->disabled();
  result->source_url = std::string(Url().Utf8().data(), Url().length());;
  result->title = std::string(style_sheet->title().Utf8().data(), style_sheet->title().length());
  result->frame_id = frame ? std::string(blink::IdentifiersFactory::FrameId(frame).Utf8().data()) : "";
  result->is_inline = style_sheet->IsInline() && !StartsAtZero();
  result->start_line = style_sheet->StartPositionInSource().line_.ZeroBasedInt();
  result->start_column = style_sheet->StartPositionInSource().column_.ZeroBasedInt();
  result->length = text.length();
          
  if (HasSourceURL())
    result->has_source_url = true;

  if (style_sheet->ownerNode())
    result->owner_node = blink::DOMNodeIds::IdForNode(style_sheet->ownerNode());

  String source_map_url_value = SourceMapURL();
  if (!source_map_url_value.IsEmpty())
    result->source_map_url = std::string(source_map_url_value.Utf8().data(), source_map_url_value.length());

  return result;
}

std::vector<automation::CSSValuePtr> InspectorStyleSheet::SelectorsFromSource(
  blink::CSSRuleSourceData* source_data,
  const String& sheet_text) {
  
  blink::ScriptRegexp comment("/\\*[^]*?\\*/", kTextCaseSensitive, blink::kMultilineEnabled);
  std::vector<automation::CSSValuePtr> result;
  const Vector<blink::SourceRange>& ranges = source_data->selector_ranges;
  for (size_t i = 0, size = ranges.size(); i < size; ++i) {
    const blink::SourceRange& range = ranges.at(i);
    String selector = sheet_text.Substring(range.start, range.length());

    // We don't want to see any comments in the selector components, only the
    // meaningful parts.
    int match_length;
    int offset = 0;
    while ((offset = comment.Match(selector, offset, &match_length)) >= 0)
      selector.replace(offset, match_length, "");

    automation::CSSValuePtr simple_selector = automation::CSSValue::New();
    simple_selector->text = std::string(selector.StripWhiteSpace().Utf8().data());
    simple_selector->range = BuildSourceRangeObject(range);
    result.push_back(std::move(simple_selector));
  }
  return result;
}

automation::SelectorListPtr InspectorStyleSheet::BuildObjectForSelectorList(blink::CSSStyleRule* rule) {
  blink::CSSRuleSourceData* source_data = SourceDataForRule(rule);
  std::vector<automation::CSSValuePtr> selectors;

  // This intentionally does not rely on the source data to avoid catching the
  // trailing comments (before the declaration starting '{').
  String selector_text = rule->selectorText();

  if (source_data) {
    selectors = SelectorsFromSource(source_data, text_);
  } else {
    const blink::CSSSelectorList& selector_list = rule->GetStyleRule()->SelectorList();
    for (const blink::CSSSelector* selector = selector_list.First(); selector;
         selector = blink::CSSSelectorList::Next(*selector)) {
      automation::CSSValuePtr sel = automation::CSSValue::New();
      sel->text = std::string(selector->SelectorText().Utf8().data());
      selectors.push_back(std::move(sel));
    }
  }
  automation::SelectorListPtr selector_list = automation::SelectorList::New();
  selector_list->selectors = std::move(selectors);
  selector_list->text = std::string(selector_text.Utf8().data(), selector_text.length());
  return selector_list;
}

static bool CanBind(automation::StyleSheetOrigin origin) {
  return origin != automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_USER_AGENT &&
         origin != automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_INJECTED;
}

automation::CSSRulePtr InspectorStyleSheet::BuildObjectForRuleWithoutMedia(blink::CSSStyleRule* rule) {
  automation::CSSRulePtr result = automation::CSSRule::New();
  result->selector_list = BuildObjectForSelectorList(rule);
  result->origin = origin_;
  result->style = BuildObjectForStyle(rule->style());
  if (CanBind(origin_)) {
    if (!Id().IsEmpty())
      result->style_sheet_id = std::string(Id().Utf8().data(), Id().length());
  }

  return result;
}

automation::CSSRuleUsagePtr InspectorStyleSheet::BuildObjectForRuleUsage(blink::CSSRule* rule, bool was_used) {
  blink::CSSRuleSourceData* source_data = SourceDataForRule(rule);

  if (!source_data)
    return nullptr;

  blink::SourceRange whole_rule_range(source_data->rule_header_range.start,
                               source_data->rule_body_range.end + 1);
  automation::CSSRuleUsagePtr result = automation::CSSRuleUsage::New();
  result->style_sheet_id = std::string(Id().Utf8().data(), Id().length());
  result->start_offset = whole_rule_range.start;
  result->end_offset = whole_rule_range.end;
  result->used = was_used;
  
  return result;
}

automation::CSSKeyframeRulePtr InspectorStyleSheet::BuildObjectForKeyframeRule(
  blink::CSSKeyframeRule* keyframe_rule) {
  automation::CSSValuePtr key_text = automation::CSSValue::New();
  key_text->text = std::string(keyframe_rule->keyText().Utf8().data(), keyframe_rule->keyText().length());
  blink::CSSRuleSourceData* source_data = SourceDataForRule(keyframe_rule);
  if (source_data) {
    key_text->range = BuildSourceRangeObject(source_data->rule_header_range);
  }
  automation::CSSKeyframeRulePtr result = automation::CSSKeyframeRule::New();        
  result->key_text = std::move(key_text);
  result->origin = origin_;
  result->style = BuildObjectForStyle(keyframe_rule->style());
  if (CanBind(origin_) && !Id().IsEmpty())
    result->style_sheet_id = std::string(Id().Utf8().data(), Id().length());;
  return result;
}

bool InspectorStyleSheet::GetText(String* result) {
  if (source_data_) {
    *result = text_;
    return true;
  }
  return false;
}

automation::SourceRangePtr InspectorStyleSheet::RuleHeaderSourceRange(blink::CSSRule* rule) {
  if (!source_data_)
    return nullptr;
  blink::CSSRuleSourceData* source_data = SourceDataForRule(rule);
  if (!source_data)
    return nullptr;
  return BuildSourceRangeObject(source_data->rule_header_range);
}

automation::SourceRangePtr InspectorStyleSheet::MediaQueryExpValueSourceRange(
  blink::CSSRule* rule,
  size_t media_query_index,
  size_t media_query_exp_index) {
  if (!source_data_)
    return nullptr;
  blink::CSSRuleSourceData* source_data = SourceDataForRule(rule);
  if (!source_data || !source_data->HasMedia() ||
      media_query_index >= source_data->media_query_exp_value_ranges.size())
    return nullptr;
  const Vector<blink::SourceRange>& media_query_exp_data =
      source_data->media_query_exp_value_ranges[media_query_index];
  if (media_query_exp_index >= media_query_exp_data.size())
    return nullptr;
  return BuildSourceRangeObject(media_query_exp_data[media_query_exp_index]);
}

InspectorStyle* InspectorStyleSheet::GetInspectorStyle(blink::CSSStyleDeclaration* style) {
  return style ? InspectorStyle::Create(style, SourceDataForRule(style->parentRule()), this)
               : nullptr;
}

String InspectorStyleSheet::SourceURL() {
  if (!source_url_.IsNull())
    return source_url_;
  if (origin_ != automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_REGULAR) {
    source_url_ = "";
    return source_url_;
  }

  String style_sheet_text;
  bool success = GetText(&style_sheet_text);
  if (success) {
    String comment_value = FindMagicComment(style_sheet_text, "sourceURL");
    if (!comment_value.IsEmpty()) {
      source_url_ = comment_value;
      return comment_value;
    }
  }
  source_url_ = "";
  return source_url_;
}

String InspectorStyleSheet::Url() {
  // "sourceURL" is present only for regular rules, otherwise "origin" should be
  // used in the frontend.
  if (origin_ != automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_REGULAR)
    return String();

  blink::CSSStyleSheet* style_sheet = PageStyleSheet();
  if (!style_sheet)
    return String();

  if (HasSourceURL())
    return SourceURL();

  if (style_sheet->IsInline() && StartsAtZero())
    return String();

  return FinalURL();
}

bool InspectorStyleSheet::HasSourceURL() {
  return !SourceURL().IsEmpty();
}

bool InspectorStyleSheet::StartsAtZero() {
  blink::CSSStyleSheet* style_sheet = PageStyleSheet();
  if (!style_sheet)
    return true;

  return style_sheet->StartPositionInSource() ==
         TextPosition::MinimumPosition();
}

String InspectorStyleSheet::SourceMapURL() {
  if (origin_ != automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_REGULAR)
    return String();

  String style_sheet_text;
  bool success = GetText(&style_sheet_text);
  if (success) {
    String comment_value =
        FindMagicComment(style_sheet_text, "sourceMappingURL");
    if (!comment_value.IsEmpty())
      return comment_value;
  }
  return page_style_sheet_->Contents()->SourceMapURL();
}

blink::CSSRuleSourceData* InspectorStyleSheet::FindRuleByHeaderRange(const blink::SourceRange& source_range) {
  if (!source_data_)
    return nullptr;

  for (size_t i = 0; i < source_data_->size(); ++i) {
    blink::CSSRuleSourceData* rule_source_data = source_data_->at(i).Get();
    if (rule_source_data->rule_header_range.start == source_range.start &&
        rule_source_data->rule_header_range.end == source_range.end) {
      return rule_source_data;
    }
  }
  return nullptr;
}

blink::CSSRuleSourceData* InspectorStyleSheet::FindRuleByBodyRange(const blink::SourceRange& source_range) {
  if (!source_data_)
    return nullptr;

  for (size_t i = 0; i < source_data_->size(); ++i) {
    blink::CSSRuleSourceData* rule_source_data = source_data_->at(i).Get();
    if (rule_source_data->rule_body_range.start == source_range.start &&
        rule_source_data->rule_body_range.end == source_range.end) {
      return rule_source_data;
    }
  }
  return nullptr;
}

blink::CSSRule* InspectorStyleSheet::RuleForSourceData(blink::CSSRuleSourceData* source_data) {
  if (!source_data_ || !source_data)
    return nullptr;

  RemapSourceDataToCSSOMIfNecessary();

  size_t index = source_data_->Find(source_data);
  if (index == kNotFound)
    return nullptr;
  IndexMap::iterator it = source_data_to_rule_.find(index);
  if (it == source_data_to_rule_.end())
    return nullptr;

  DCHECK_LT(it->value, cssom_flat_rules_.size());

  // Check that CSSOM did not mutate this rule.
  blink::CSSRule* result = cssom_flat_rules_.at(it->value);
  if (CanonicalCSSText(parsed_flat_rules_.at(index)) !=
      CanonicalCSSText(result))
    return nullptr;
  return result;
}

blink::CSSRuleSourceData* InspectorStyleSheet::SourceDataForRule(blink::CSSRule* rule) {
  if (!source_data_ || !rule)
    return nullptr;

  RemapSourceDataToCSSOMIfNecessary();

  size_t index = cssom_flat_rules_.Find(rule);
  if (index == kNotFound)
    return nullptr;
  IndexMap::iterator it = rule_to_source_data_.find(index);
  if (it == rule_to_source_data_.end())
    return nullptr;

  DCHECK_LT(it->value, source_data_->size());

  // Check that CSSOM did not mutate this rule.
  blink::CSSRule* parsed_rule = parsed_flat_rules_.at(it->value);
  if (CanonicalCSSText(rule) != CanonicalCSSText(parsed_rule))
    return nullptr;
  return source_data_->at(it->value).Get();
}

void InspectorStyleSheet::RemapSourceDataToCSSOMIfNecessary() {
  CSSRuleVector cssom_rules;
  CollectFlatRules(page_style_sheet_.Get(), &cssom_rules);

  if (cssom_rules.size() != cssom_flat_rules_.size()) {
    MapSourceDataToCSSOM();
    return;
  }

  for (size_t i = 0; i < cssom_flat_rules_.size(); ++i) {
    if (cssom_flat_rules_.at(i) != cssom_rules.at(i)) {
      MapSourceDataToCSSOM();
      return;
    }
  }
}

void InspectorStyleSheet::MapSourceDataToCSSOM() {
  rule_to_source_data_.clear();
  source_data_to_rule_.clear();

  cssom_flat_rules_.clear();
  CSSRuleVector& cssom_rules = cssom_flat_rules_;
  CollectFlatRules(page_style_sheet_.Get(), &cssom_rules);

  if (!source_data_)
    return;

  CSSRuleVector& parsed_rules = parsed_flat_rules_;

  Vector<String> cssom_rules_text = Vector<String>();
  Vector<String> parsed_rules_text = Vector<String>();
  for (size_t i = 0; i < cssom_rules.size(); ++i)
    cssom_rules_text.push_back(CanonicalCSSText(cssom_rules.at(i)));
  for (size_t j = 0; j < parsed_rules.size(); ++j)
    parsed_rules_text.push_back(CanonicalCSSText(parsed_rules.at(j)));

  Diff(cssom_rules_text, parsed_rules_text, &rule_to_source_data_,
       &source_data_to_rule_);
}

const CSSRuleVector& InspectorStyleSheet::FlatRules() {
  RemapSourceDataToCSSOMIfNecessary();
  return cssom_flat_rules_;
}

bool InspectorStyleSheet::ResourceStyleSheetText(String* result) {
  if (origin_ == automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_INJECTED ||
      origin_ == automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_USER_AGENT)
    return false;

  if (!page_style_sheet_->OwnerDocument())
    return false;

  blink::KURL url(page_style_sheet_->href());
  if (resource_container_->LoadStyleSheetContent(url, result))
    return true;

  bool base64_encoded;
  bool success = network_dispatcher_->FetchResourceContent(
      page_style_sheet_->OwnerDocument(), url, result, &base64_encoded);
  return success && !base64_encoded;
}

blink::Element* InspectorStyleSheet::OwnerStyleElement() {
  blink::Node* owner_node = page_style_sheet_->ownerNode();
  if (!owner_node || !owner_node->IsElementNode())
    return nullptr;
  blink::Element* owner_element = ToElement(owner_node);

  if (!IsHTMLStyleElement(owner_element) && !IsSVGStyleElement(owner_element))
    return nullptr;
  return owner_element;
}

bool InspectorStyleSheet::InlineStyleSheetText(String* result) {
  blink::Element* owner_element = OwnerStyleElement();
  if (!owner_element)
    return false;
  if (resource_container_->LoadStyleElementContent(
       blink::DOMNodeIds::IdForNode(owner_element), result))
    return true;
  *result = owner_element->textContent();
  return true;
}

bool InspectorStyleSheet::InspectorStyleSheetText(String* result) {
  if (origin_ != automation::StyleSheetOrigin::kSTYLE_SHEET_ORIGIN_INSPECTOR)
    return false;
  if (!page_style_sheet_->OwnerDocument())
    return false;
  if (resource_container_->LoadStyleElementContent(
      blink::DOMNodeIds::IdForNode(page_style_sheet_->OwnerDocument()), result))
    return true;
  *result = "";
  return true;
}

InspectorStyleSheetForInlineStyle* InspectorStyleSheetForInlineStyle::Create(
  blink::Element* element,
  Listener* listener) {
  return new InspectorStyleSheetForInlineStyle(element, listener);
}

InspectorStyleSheetForInlineStyle::InspectorStyleSheetForInlineStyle(
  blink::Element* element,
  Listener* listener)
    : InspectorStyleSheetBase(listener), element_(element) {
  DCHECK(element_);
}

void InspectorStyleSheetForInlineStyle::DidModifyElementAttribute() {
  inspector_style_.Clear();
  OnStyleSheetTextChanged();
}

bool InspectorStyleSheetForInlineStyle::SetText(
  const String& text,
  blink::ExceptionState& exception_state) {
  if (!VerifyStyleText(&element_->GetDocument(), text)) {
    exception_state.ThrowDOMException(blink::kSyntaxError, "Style text is not valid.");
    return false;
  }

  {
    CSSDispatcher::InlineStyleOverrideScope override_scope(
        element_->ownerDocument());
    element_->setAttribute("style", AtomicString(text), exception_state);
  }
  if (!exception_state.HadException())
    OnStyleSheetTextChanged();
  return !exception_state.HadException();
}

bool InspectorStyleSheetForInlineStyle::GetText(String* result) {
  *result = ElementStyleText();
  return true;
}

InspectorStyle* InspectorStyleSheetForInlineStyle::GetInspectorStyle(
  blink::CSSStyleDeclaration* style) {
  if (!inspector_style_)
    inspector_style_ =
        InspectorStyle::Create(element_->style(), RuleSourceData(), this);

  return inspector_style_;
}

blink::CSSRuleSourceData* InspectorStyleSheetForInlineStyle::RuleSourceData() {
  const String& text = ElementStyleText();
  blink::CSSRuleSourceData* rule_source_data = nullptr;
  if (text.IsEmpty()) {
    rule_source_data = new blink::CSSRuleSourceData(blink::StyleRule::kStyle);
    rule_source_data->rule_body_range.start = 0;
    rule_source_data->rule_body_range.end = 0;
  } else {
    blink::CSSRuleSourceDataList* rule_source_data_result =
        new blink::CSSRuleSourceDataList();
    StyleSheetHandler handler(text, &element_->GetDocument(),
                              rule_source_data_result);
    blink::CSSParser::ParseDeclarationListForInspector(
        ParserContextForDocument(&element_->GetDocument()), text, handler);
    rule_source_data = rule_source_data_result->front();
  }
  return rule_source_data;
}

blink::CSSStyleDeclaration* InspectorStyleSheetForInlineStyle::InlineStyle() {
  return element_->style();
}

const String& InspectorStyleSheetForInlineStyle::ElementStyleText() {
  return element_->getAttribute("style").GetString();
}

void InspectorStyleSheetForInlineStyle::Trace(blink::Visitor* visitor) {
  visitor->Trace(element_);
  visitor->Trace(inspector_style_);
  InspectorStyleSheetBase::Trace(visitor);
}

}  // namespace blink
