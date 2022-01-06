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

#ifndef CORE_APPLICATION_AUTOMATION_INSPECTOR_STYLE_SHEET_H_
#define CORE_APPLICATION_AUTOMATION_INSPECTOR_STYLE_SHEET_H_

#include <memory>
#include "base/memory/scoped_refptr.h"
#include "core/shared/common/mojom/automation.mojom.h"
#include "third_party/blink/renderer/core/css/css_property_source_data.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/inspector/protocol/CSS.h"
#include "third_party/blink/renderer/platform/heap/handle.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {
class CSSKeyframeRule;
class CSSMediaRule;
class CSSStyleDeclaration;
class CSSStyleRule;
class CSSStyleSheet;
class Element;
class ExceptionState;
class InspectorResourceContainer;
}

namespace application {
class NetworkDispatcher;
class InspectorStyleSheetBase;

typedef blink::HeapVector<blink::Member<blink::CSSRule>> CSSRuleVector;
typedef Vector<unsigned> LineEndings;

class InspectorStyle final : public blink::GarbageCollectedFinalized<InspectorStyle> {
 public:
  static InspectorStyle* Create(blink::CSSStyleDeclaration*,
                                blink::CSSRuleSourceData*,
                                InspectorStyleSheetBase* parent_style_sheet);
  ~InspectorStyle();

  blink::CSSStyleDeclaration* CssStyle() { return style_.Get(); }
  automation::CSSStylePtr BuildObjectForStyle();
  bool StyleText(String* result);
  bool TextForRange(const blink::SourceRange&, String* result);

  void Trace(blink::Visitor*);

 private:
  InspectorStyle(blink::CSSStyleDeclaration*,
                 blink::CSSRuleSourceData*,
                 InspectorStyleSheetBase* parent_style_sheet);

  void PopulateAllProperties(Vector<blink::CSSPropertySourceData>& result);
  automation::CSSStylePtr StyleWithProperties();
  String ShorthandValue(const String& shorthand_property);

  blink::Member<blink::CSSStyleDeclaration> style_;
  blink::Member<blink::CSSRuleSourceData> source_data_;
  blink::Member<InspectorStyleSheetBase> parent_style_sheet_;
};

class InspectorStyleSheetBase
    : public blink::GarbageCollectedFinalized<InspectorStyleSheetBase> {
 public:
  class CORE_EXPORT Listener {
   public:
    Listener() = default;
    virtual ~Listener() = default;
    virtual void StyleSheetChanged(InspectorStyleSheetBase*) = 0;
  };
  virtual ~InspectorStyleSheetBase() = default;
  virtual void Trace(blink::Visitor* visitor) {}

  String Id() { return id_; }

  virtual bool SetText(const String&, blink::ExceptionState&) = 0;
  virtual bool GetText(String* result) = 0;
  virtual String SourceMapURL() { return String(); }

  automation::CSSStylePtr BuildObjectForStyle(blink::CSSStyleDeclaration*);
  automation::SourceRangePtr BuildSourceRangeObject(const blink::SourceRange&);
  bool LineNumberAndColumnToOffset(unsigned line_number,
                                   unsigned column_number,
                                   unsigned* offset);
  virtual bool IsInlineStyle() = 0;

 protected:
  explicit InspectorStyleSheetBase(Listener*);

  Listener* GetListener() { return listener_; }
  void OnStyleSheetTextChanged();
  const LineEndings* GetLineEndings();

  virtual InspectorStyle* GetInspectorStyle(blink::CSSStyleDeclaration*) = 0;

 private:
  friend class InspectorStyle;

  String id_;
  Listener* listener_;
  std::unique_ptr<LineEndings> line_endings_;
};

class InspectorStyleSheet : public InspectorStyleSheetBase {
 public:
  static InspectorStyleSheet* Create(NetworkDispatcher*,
                                     blink::CSSStyleSheet* page_style_sheet,
                                     automation::StyleSheetOrigin origin,
                                     const String& document_url,
                                     InspectorStyleSheetBase::Listener*,
                                     blink::InspectorResourceContainer*);

  ~InspectorStyleSheet() override;
  void Trace(blink::Visitor*) override;

  String FinalURL();
  bool SetText(const String&, blink::ExceptionState&) override;
  bool GetText(String* result) override;
  blink::CSSStyleRule* SetRuleSelector(const blink::SourceRange&,
                                       const String& selector,
                                       blink::SourceRange* new_range,
                                       String* old_selector,
                                       blink::ExceptionState&);
  blink::CSSKeyframeRule* SetKeyframeKey(const blink::SourceRange&,
                                         const String& text,
                                         blink::SourceRange* new_range,
                                         String* old_text,
                                         blink::ExceptionState&);
  blink::CSSRule* SetStyleText(const blink::SourceRange&,
                               const String& text,
                               blink::SourceRange* new_range,
                               String* old_selector,
                               blink::ExceptionState&);
  blink::CSSMediaRule* SetMediaRuleText(const blink::SourceRange&,
                                        const String& selector,
                                        blink::SourceRange* new_range,
                                        String* old_selector,
                                        blink::ExceptionState&);
  blink::CSSStyleRule* AddRule(const String& rule_text,
                               const blink::SourceRange& location,
                               blink::SourceRange* added_range,
                               blink::ExceptionState&);
  bool DeleteRule(const blink::SourceRange&, blink::ExceptionState&);
  std::vector<std::string> CollectClassNames();
  blink::CSSStyleSheet* PageStyleSheet() { return page_style_sheet_.Get(); }

  automation::CSSStyleSheetHeaderPtr BuildObjectForStyleSheetInfo();
  automation::CSSRulePtr BuildObjectForRuleWithoutMedia(blink::CSSStyleRule*);
  automation::CSSRuleUsagePtr BuildObjectForRuleUsage(blink::CSSRule*, bool);
  automation::CSSKeyframeRulePtr BuildObjectForKeyframeRule(blink::CSSKeyframeRule*);
  automation::SelectorListPtr BuildObjectForSelectorList(blink::CSSStyleRule*);
  automation::SourceRangePtr RuleHeaderSourceRange(blink::CSSRule*);
  automation::SourceRangePtr MediaQueryExpValueSourceRange(
      blink::CSSRule*,
      size_t media_query_index,
      size_t media_query_exp_index);
  bool IsInlineStyle() override { return false; }
  const CSSRuleVector& FlatRules();
  blink::CSSRuleSourceData* SourceDataForRule(blink::CSSRule*);
  String SourceMapURL() override;

 protected:
  InspectorStyle* GetInspectorStyle(blink::CSSStyleDeclaration*) override;

 private:
  InspectorStyleSheet(NetworkDispatcher*,
                      blink::CSSStyleSheet* page_style_sheet,
                      automation::StyleSheetOrigin origin,
                      const String& document_url,
                      InspectorStyleSheetBase::Listener*,
                      blink::InspectorResourceContainer*);
  blink::CSSRuleSourceData* RuleSourceDataAfterSourceRange(const blink::SourceRange&);
  blink::CSSRuleSourceData* FindRuleByHeaderRange(const blink::SourceRange&);
  blink::CSSRuleSourceData* FindRuleByBodyRange(const blink::SourceRange&);
  blink::CSSRule* RuleForSourceData(blink::CSSRuleSourceData*);
  blink::CSSStyleRule* InsertCSSOMRuleInStyleSheet(blink::CSSRule* insert_before,
                                            const String& rule_text,
                                            blink::ExceptionState&);
  blink::CSSStyleRule* InsertCSSOMRuleInMediaRule(blink::CSSMediaRule*,
                                           blink::CSSRule* insert_before,
                                           const String& rule_text,
                                           blink::ExceptionState&);
  blink::CSSStyleRule* InsertCSSOMRuleBySourceRange(const blink::SourceRange&,
                                             const String& rule_text,
                                             blink::ExceptionState&);
  String SourceURL();
  void RemapSourceDataToCSSOMIfNecessary();
  void MapSourceDataToCSSOM();
  bool ResourceStyleSheetText(String* result);
  bool InlineStyleSheetText(String* result);
  bool InspectorStyleSheetText(String* result);
  std::vector<automation::CSSValuePtr> SelectorsFromSource(blink::CSSRuleSourceData*, const String&);
  String Url();
  bool HasSourceURL();
  bool StartsAtZero();

  void ReplaceText(const blink::SourceRange&,
                   const String& text,
                   blink::SourceRange* new_range,
                   String* old_text);
  void InnerSetText(const String& new_text, bool mark_as_locally_modified);
  blink::Element* OwnerStyleElement();

  blink::Member<blink::InspectorResourceContainer> resource_container_;
  NetworkDispatcher* network_dispatcher_;
  blink::Member<blink::CSSStyleSheet> page_style_sheet_;
  automation::StyleSheetOrigin origin_;
  String document_url_;
  blink::Member<blink::CSSRuleSourceDataList> source_data_;
  String text_;
  CSSRuleVector cssom_flat_rules_;
  CSSRuleVector parsed_flat_rules_;
  typedef HashMap<unsigned,
                  unsigned,
                  WTF::IntHash<unsigned>,
                  WTF::UnsignedWithZeroKeyHashTraits<unsigned>>
      IndexMap;
  IndexMap rule_to_source_data_;
  IndexMap source_data_to_rule_;
  String source_url_;
};

class InspectorStyleSheetForInlineStyle final : public InspectorStyleSheetBase {
 public:
  static InspectorStyleSheetForInlineStyle* Create(blink::Element*, Listener*);

  void DidModifyElementAttribute();
  bool SetText(const String&, blink::ExceptionState&) override;
  bool GetText(String* result) override;
  blink::CSSStyleDeclaration* InlineStyle();
  blink::CSSRuleSourceData* RuleSourceData();

  void Trace(blink::Visitor*) override;

 protected:
  InspectorStyle* GetInspectorStyle(blink::CSSStyleDeclaration*) override;

  // Also accessed by friend class InspectorStyle.
  bool IsInlineStyle() override { return true; }

 private:
  InspectorStyleSheetForInlineStyle(blink::Element*, Listener*);
  const String& ElementStyleText();

  blink::Member<blink::Element> element_;
  blink::Member<InspectorStyle> inspector_style_;
};

}  // namespace blink

#endif  // !defined(InspectorStyleSheet_h)
