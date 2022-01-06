// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public struct FontRenderParams {

  public enum SubpixelRendering : Int {
    case None = 0
    case RGB
    case BGR
    case VRGB
    case VBGR
  }

  public enum Hinting : Int {
    case None = 0
    case Slight = 1 
    case Medium = 2
    case Full = 3
  }

  public var antialiasing: Bool

  public var subpixelPositioning: Bool

  public var autohinted: Bool

  public var useBitmaps: Bool

  public var hinting: Hinting

  public var subpixelRendering: SubpixelRendering

  public init() {
    antialiasing = true
    subpixelPositioning = true
    autohinted = false
    useBitmaps = false
    hinting = .Medium
    subpixelRendering = .None
  }
}

public struct FontStyle : OptionSet {
  
  public var position: Int {
    // TODO: we probably have a way to calculate this from the bitmask by using shifts
    switch rawValue {
      case FontStyle.None.rawValue:
        return -1
      case FontStyle.Normal.rawValue:
        return 0
      case FontStyle.Bold.rawValue:
        return 1
      case FontStyle.Italic.rawValue:
        return 2
      case FontStyle.Strike.rawValue:
        return 3
      case FontStyle.DiagonalStrike.rawValue:
        return 4
      case FontStyle.Underline.rawValue:
        return 5
      default:
        return -1
    }
  }

  public let rawValue: Int

  static let None           = FontStyle(rawValue: -1)
  static let Normal         = FontStyle(rawValue: (1 << 0))
  static let Bold           = FontStyle(rawValue: (1 << 1))
  static let Italic         = FontStyle(rawValue: (1 << 2))
  static let Strike         = FontStyle(rawValue: (1 << 3))
  static let DiagonalStrike = FontStyle(rawValue: (1 << 4))
  static let Underline      = FontStyle(rawValue: (1 << 5))

  static let All: [FontStyle] = [.Normal, .Bold, .Italic, .Strike, .DiagonalStrike, .Underline]

  public init(rawValue: Int) {
    self.rawValue = rawValue
  }
  
}

public struct FontRenderParamsQuery {
  public var families: [String]
  public var style: FontStyle
  public var pixelSize: Int

  public init() {
    families = []
    style = FontStyle.Normal
    pixelSize = 0
  }
}

extension FontStyle : Equatable, Hashable {
  
  public var hashValue: Int {
    return rawValue.hashValue
  }

  public static func == (lhs: FontStyle, rhs: FontStyle) -> Bool {
    return lhs.rawValue == rhs.rawValue
  }
}

public class Font {

  public enum Weight: Int {
    case Invalid = -1
    case Thin = 100
    case ExtraLight = 200
    case Light = 300
    case Normal = 400
    case Medium = 500
    case Semibold = 600
    case Bold = 700
    case ExtraBold = 800
    case Black = 900
  }

  public var height: Int {
    didSet {}
  }

  public var baseline: Int {
    didSet {}
  }

  public var capHeight: Int {
    didSet {}
  }

  public var style: FontStyle {
    didSet {}
  }

  public var fontFamily: String {
    didSet {}
  }

  public var fontName: String {
    return fontFamily
  }

  public var fontRenderParams: FontRenderParams {
    didSet {}
  }
  
  public var fontSize: Int {
    didSet {}
  }
 
  var typeface: Typeface

  public init() {
    typeface = Typeface(font: "sans", style: .Normal)
    fontRenderParams = FontRenderParams()
    fontRenderParams.subpixelPositioning = false
    fontRenderParams.antialiasing = true
    height = 1
    baseline = 1
    capHeight = 1
    style = .Normal
    fontFamily = "sans"
    fontSize = 12
  }

  public init(name: String, size: Int) {
    typeface = Typeface(font: name, style: .Normal)
    fontRenderParams = FontRenderParams()
    fontRenderParams.subpixelPositioning = false
    fontRenderParams.antialiasing = true
    height = 1
    baseline = 1
    capHeight = 1
    style = .Normal
    fontFamily = name
    fontSize = size
  }

  internal init(typeface: Typeface) {
    self.typeface = typeface
    fontRenderParams = FontRenderParams()
    fontRenderParams.subpixelPositioning = false
    fontRenderParams.antialiasing = true
    height = 1
    baseline = 1
    capHeight = 1
    style = .Normal
    fontFamily = "sans"
    fontSize = 12
  }

  public func expectedTextWidth(length: Int) -> Int {
    return length
  }

  public func derive(sizeDelta: Int, style: FontStyle) -> Font {
    let derivedFont = Typeface(size: sizeDelta, style: style)
    return Font(typeface: derivedFont)
  }

}

public func getFontRenderParams(query: FontRenderParamsQuery) -> FontRenderParams {
  // FontRenderParamsQuery actual_query(query);
  // if (actual_query.device_scale_factor == 0) {
  // #if defined(OS_HROMEOS)
  //   actual_query.device_scale_factor = device_scale_factor_for_internal_display;
  // #else
  //   // Linux does not support per-display DPI, so we use a slightly simpler
  //   // code path than on Chrome OS to figure out the device scale factor.
  //   gfx::Screen* screen = gfx::Screen::GetScreenByType(gfx::SCREEN_TYPE_NATIVE);
  //   if (screen) {
  //     gfx::Display display = screen->GetPrimaryDisplay();
  //     actual_query.device_scale_factor = display.device_scale_factor();
  //   }
  // #endif
  // }
  // const uint32 hash = HashFontRenderParamsQuery(actual_query);
  // SynchronizedCache* synchronized_cache = g_synchronized_cache.Pointer();

  // {
  //   // Try to find a cached result so Fontconfig doesn't need to be queried.
  //   base::AutoLock lock(synchronized_cache->lock);
  //   Cache::const_iterator it = synchronized_cache->cache.Get(hash);
  //   if (it != synchronized_cache->cache.end()) {
  //     DVLOG(1) << "Returning cached params for " << hash;
  //     const QueryResult& result = it->second;
  //     if (family_out)
  //       *family_out = result.family;
  //     return result.params;
  //   }
  // }

  // DVLOG(1) << "Computing params for " << hash;
  // if (family_out)
  //   family_out->clear();

  // // Start with the delegate's settings, but let Fontconfig have the final say.
  // FontRenderParams params;
  // const LinuxFontDelegate* delegate = LinuxFontDelegate::instance();
  // if (delegate)
  //   params = delegate->GetDefaultFontRenderParams();
  // QueryFontconfig(actual_query, &params, family_out);
  // if (!params.antialiasing) {
  //   // Cairo forces full hinting when antialiasing is disabled, since anything
  //   // less than that looks awful; do the same here. Requesting subpixel
  //   // rendering or positioning doesn't make sense either.
  //   params.hinting = FontRenderParams::HINTING_FULL;
  //   params.subpixel_rendering = FontRenderParams::SUBPIXEL_RENDERING_NONE;
  //   params.subpixel_positioning = false;
  // } else {
  //   params.subpixel_positioning = actual_query.device_scale_factor > 1.0f;

  //   // To enable subpixel positioning, we need to disable hinting.
  //   if (params.subpixel_positioning)
  //     params.hinting = FontRenderParams::HINTING_NONE;
  // }

  // // Use the first family from the list if Fontconfig didn't suggest a family.
  // if (family_out && family_out->empty() && !actual_query.families.empty())
  //   *family_out = actual_query.families[0];

  // {
  //   // Store the result. It's fine if this overwrites a result that was cached
  //   // by a different thread in the meantime; the values should be identical.
  //   base::AutoLock lock(synchronized_cache->lock);
  //   synchronized_cache->cache.Put(hash,
  //       QueryResult(params, family_out ? *family_out : std::string()));
  // }

  // return params;

  var params = FontRenderParams()
  params.subpixelPositioning = true
  params.antialiasing = true
  params.hinting = .Medium
  params.subpixelRendering = .None
  
  return params
}