// Copyright (c) 2015 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public class FontList {
  
  public var height: Int

  public var baseline: Int

  public var capHeight: Int

  public var fontStyle: FontStyle
  
  public var fontSize: Int

  public var fontWeight: Font.Weight

  public var primaryFont: Font {
    return fonts[0]
  }

  public var fonts: [Font] {

    if _fonts.isEmpty {
      
      guard !fontDescriptionString.isEmpty else {
        // TODO: this should be a temporary hack
        let font = Font(name: "sans", size: 12)
        _fonts.append(font)
        // TODO: fix this (primaryFont getter "fonts[0]" will break).. exception?
        return _fonts
      }

      var fontNames : [String] = []
      var style = FontStyle.None

      let _ = FontList.parseDescription(description: fontDescriptionString, families: &fontNames, style: &style, size: &fontSize)

      if fontStyle == FontStyle.None {
        fontStyle = style
      }
    
      for fontName in fontNames {
        let font = Font(name: fontName, size: fontSize)
        if fontStyle == FontStyle.Normal {
          _fonts.append(font)
        } else {
          _fonts.append(font.derive(sizeDelta: 0, style: fontStyle))
        }
      }
    }
    return _fonts
  }

  public static func parseDescription(description: String,
                                      families: inout [String],
                                      style: inout FontStyle,
                                      size: inout Int) -> Bool {
    // families = base::SplitString(
    //   description, ",", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL)
    
    // if families.isEmpty {
    //   return false;
    // }

    // for family in families {
    //   base::TrimWhitespaceASCII(family, base::TRIM_ALL, &family)
    // }

    // // The last item is "[STYLE1] [STYLE2] [...] SIZE".
    // let styles = base::SplitString(
    //   families_out->back(), base::kWhitespaceASCII,
    //   base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

    // families->pop_back();
  
    // if styles.isEmpty {
    //   return false
    // }

    // // The size takes the form "<INT>px".
    // std::string size_string = styles.back();
    // styles.pop_back();
    
    // if (!base::EndsWith(size_string, "px", base::CompareCase::SENSITIVE))
    //   return false
  
    // size_string.resize(size_string.size() - 2);
    
    // if (!base::StringToInt(size_string, size_pixels_out) ||
    //   *size_pixels_out <= 0)
    // return false

    // // Font supports BOLD and ITALIC; underline is supported via RenderText.
    // *style_out = gfx::Font::NORMAL;
    // for (const auto& style_string : styles) {
    //   if (style_string == "Bold")
    //     *style_out |= gfx::Font::BOLD;
    //   else if (style_string == "Italic")
    //     *style_out |= gfx::Font::ITALIC;
    //   else
    //     return false
    // }

    return true
  }

  internal var _fonts: [Font]

  internal var fontDescriptionString: String
  
  public init() {
    height = 0
    baseline = 0
    capHeight = 0
    fontStyle = FontStyle.None
    fontSize = 0
    fontWeight = Font.Weight.Invalid
    _fonts = []
    fontDescriptionString = String()
  }
  
  public func getExpectedTextWidth(_ length: Int) -> Int {
    return 0
  }
  
}