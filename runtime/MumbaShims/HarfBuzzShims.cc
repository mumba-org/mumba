// Copyright 2015 The Chromium Authors. All rights reserved.
// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <limits>
#include <map>

#include "HarfBuzzShims.h"
#include "CompositorStructsPrivate.h"

#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/numerics/safe_conversions.h"
#include "base/numerics/safe_math.h"
//#include "skia/ext/refptr.h"
#include "third_party/icu/source/common/unicode/uscript.h"
#include "third_party/skia/include/core/SkPaint.h"
#include "third_party/skia/include/core/SkTypeface.h"
#include "third_party/skia/include/private/SkFixed.h"
#include "third_party/harfbuzz-ng/src/src/hb.h"
#include "third_party/harfbuzz-ng/src/src/hb-icu.h"

namespace {

class HarfBuzzFace;

// Maps from code points to glyph indices in a font.
typedef std::map<uint32_t, uint16_t> GlyphCache;

typedef std::pair<HarfBuzzFace, GlyphCache> FaceCache;

// We treat HarfBuzz ints as 16.16 fixed-point.
static const int kHbUnit1 = 1 << 16;

int SkiaScalarToHarfBuzzUnits(SkScalar value) {
  return base::saturated_cast<int>(value * kHbUnit1);
}

// Font data provider for HarfBuzz using Skia. Copied from Blink.
// TODO(ckocagil): Eliminate the duplication. http://crbug.com/368375
struct FontData {
  FontData(GlyphCache* glyph_cache) : glyph_cache_(glyph_cache) {}

  SkPaint paint_;
  GlyphCache* glyph_cache_;
};

// Deletes the object at the given pointer after casting it to the given type.
template<typename Type>
void DeleteByType(void* data) {
  Type* typed_data = reinterpret_cast<Type*>(data);
  delete typed_data;
}

template<typename Type>
void DeleteArrayByType(void* data) {
  Type* typed_data = reinterpret_cast<Type*>(data);
  delete[] typed_data;
}

// Outputs the |width| and |extents| of the glyph with index |codepoint| in
// |paint|'s font.
void GetGlyphWidthAndExtents(SkPaint* paint,
                             hb_codepoint_t codepoint,
                             hb_position_t* width,
                             hb_glyph_extents_t* extents) {
  DCHECK_LE(codepoint, std::numeric_limits<uint16_t>::max());
  paint->setTextEncoding(SkPaint::kGlyphID_TextEncoding);

  SkScalar sk_width;
  SkRect sk_bounds;
  uint16_t glyph = static_cast<uint16_t>(codepoint);

  paint->getTextWidths(&glyph, sizeof(glyph), &sk_width, &sk_bounds);
  if (width)
    *width = SkScalarToFixed(sk_width);
  if (extents) {
    // Invert y-axis because Skia is y-grows-down but we set up HarfBuzz to be
    // y-grows-up.
    extents->x_bearing = SkScalarToFixed(sk_bounds.fLeft);
    extents->y_bearing = SkScalarToFixed(-sk_bounds.fTop);
    extents->width = SkScalarToFixed(sk_bounds.width());
    extents->height = SkScalarToFixed(-sk_bounds.height());
  }
}

// Writes the |glyph| index for the given |unicode| code point. Returns whether
// the glyph exists, i.e. it is not a missing glyph.
hb_bool_t GetGlyph(hb_font_t* font,
                   void* data,
                   hb_codepoint_t unicode,
                   hb_codepoint_t variation_selector,
                   hb_codepoint_t* glyph,
                   void* user_data) {
  FontData* font_data = reinterpret_cast<FontData*>(data);
  GlyphCache* cache = font_data->glyph_cache_;

  bool exists = cache->count(unicode) != 0;
  if (!exists) {
    SkPaint* paint = &font_data->paint_;
    paint->setTextEncoding(SkPaint::kUTF32_TextEncoding);
    paint->textToGlyphs(&unicode, sizeof(hb_codepoint_t), &(*cache)[unicode]);
  }
  *glyph = (*cache)[unicode];
  return !!*glyph;
}

// Returns the horizontal advance value of the |glyph|.
hb_position_t GetGlyphHorizontalAdvance(hb_font_t* font,
                                        void* data,
                                        hb_codepoint_t glyph,
                                        void* user_data) {
  FontData* font_data = reinterpret_cast<FontData*>(data);
  hb_position_t advance = 0;

  GetGlyphWidthAndExtents(&font_data->paint_, glyph, &advance, 0);
  return advance;
}

hb_bool_t GetGlyphHorizontalOrigin(hb_font_t* font,
                                   void* data,
                                   hb_codepoint_t glyph,
                                   hb_position_t* x,
                                   hb_position_t* y,
                                   void* user_data) {
  // Just return true, like the HarfBuzz-FreeType implementation.
  return true;
}

hb_position_t GetGlyphKerning(FontData* font_data,
                              hb_codepoint_t first_glyph,
                              hb_codepoint_t second_glyph) {
  SkTypeface* typeface = font_data->paint_.getTypeface();
  const uint16_t glyphs[2] = { static_cast<uint16_t>(first_glyph),
                               static_cast<uint16_t>(second_glyph) };
  int32_t kerning_adjustments[1] = { 0 };

  if (!typeface->getKerningPairAdjustments(glyphs, 2, kerning_adjustments))
    return 0;

  SkScalar upm = SkIntToScalar(typeface->getUnitsPerEm());
  SkScalar size = font_data->paint_.getTextSize();
  return SkiaScalarToHarfBuzzUnits(SkIntToScalar(kerning_adjustments[0]) *
                                   size / upm);
}

hb_position_t GetGlyphHorizontalKerning(hb_font_t* font,
                                        void* data,
                                        hb_codepoint_t left_glyph,
                                        hb_codepoint_t right_glyph,
                                        void* user_data) {
  FontData* font_data = reinterpret_cast<FontData*>(data);
  if (font_data->paint_.isVerticalText()) {
    // We don't support cross-stream kerning.
    return 0;
  }

  return GetGlyphKerning(font_data, left_glyph, right_glyph);
}

hb_position_t GetGlyphVerticalKerning(hb_font_t* font,
                                      void* data,
                                      hb_codepoint_t top_glyph,
                                      hb_codepoint_t bottom_glyph,
                                      void* user_data) {
  FontData* font_data = reinterpret_cast<FontData*>(data);
  if (!font_data->paint_.isVerticalText()) {
    // We don't support cross-stream kerning.
    return 0;
  }

  return GetGlyphKerning(font_data, top_glyph, bottom_glyph);
}

// Writes the |extents| of |glyph|.
hb_bool_t GetGlyphExtents(hb_font_t* font,
                          void* data,
                          hb_codepoint_t glyph,
                          hb_glyph_extents_t* extents,
                          void* user_data) {
  FontData* font_data = reinterpret_cast<FontData*>(data);

  GetGlyphWidthAndExtents(&font_data->paint_, glyph, 0, extents);
  return true;
}

class FontFuncs {
 public:
  FontFuncs() : font_funcs_(hb_font_funcs_create()) {
    hb_font_funcs_set_glyph_func(font_funcs_, GetGlyph, 0, 0);
    hb_font_funcs_set_glyph_h_advance_func(
        font_funcs_, GetGlyphHorizontalAdvance, 0, 0);
    hb_font_funcs_set_glyph_h_kerning_func(
        font_funcs_, GetGlyphHorizontalKerning, 0, 0);
    hb_font_funcs_set_glyph_h_origin_func(
        font_funcs_, GetGlyphHorizontalOrigin, 0, 0);
    hb_font_funcs_set_glyph_v_kerning_func(
        font_funcs_, GetGlyphVerticalKerning, 0, 0);
    hb_font_funcs_set_glyph_extents_func(
        font_funcs_, GetGlyphExtents, 0, 0);
    hb_font_funcs_make_immutable(font_funcs_);
  }

  ~FontFuncs() {
    hb_font_funcs_destroy(font_funcs_);
  }

  hb_font_funcs_t* get() { return font_funcs_; }

 private:
  hb_font_funcs_t* font_funcs_;

  DISALLOW_COPY_AND_ASSIGN(FontFuncs);
};

base::LazyInstance<FontFuncs>::Leaky g_font_funcs = LAZY_INSTANCE_INITIALIZER;

// Returns the raw data of the font table |tag|.
hb_blob_t* GetFontTable(hb_face_t* face, hb_tag_t tag, void* user_data) {
  SkTypeface* typeface = reinterpret_cast<SkTypeface*>(user_data);

  const size_t table_size = typeface->getTableSize(tag);
  if (!table_size)
    return 0;

  std::unique_ptr<char[]> buffer(new char[table_size]);
  if (!buffer)
    return 0;
  size_t actual_size = typeface->getTableData(tag, 0, table_size, buffer.get());
  if (table_size != actual_size)
    return 0;

  char* buffer_raw = buffer.release();
  return hb_blob_create(buffer_raw, table_size, HB_MEMORY_MODE_WRITABLE,
                        buffer_raw, DeleteArrayByType<char>);
}

void UnrefSkTypeface(void* data) {
  SkTypeface* skia_face = reinterpret_cast<SkTypeface*>(data);
  SkSafeUnref(skia_face);
}

class HarfBuzzFace {
 public:
  HarfBuzzFace() : face_(NULL) {}
  ~HarfBuzzFace() {
    if (face_)
      hb_face_destroy(face_);
  }

  void Init(SkTypeface* skia_face) {
    SkSafeRef(skia_face);
    face_ = hb_face_create_for_tables(GetFontTable, skia_face, UnrefSkTypeface);
    DCHECK(face_);
  }

  hb_face_t* get() {
    return face_;
  }

 private:
  hb_face_t* face_;
};

}


HarfBuzzFontRef _HarfBuzzFontCreate(TypefaceRef typeface,
                                            int text_size,
                                            int antialiasing,
                                            int subpixel_positioning,
                                            int autohinter,
                                            int subpixel_rendering,
                                            int subpixel_rendering_suppressed,
                                            int hinting) {
  
  static std::map<SkFontID, FaceCache> face_caches;

  SkiaTypeface* skia_face = reinterpret_cast<SkiaTypeface *>(typeface);

  FaceCache* face_cache = &face_caches[skia_face->handle()->uniqueID()];
  
  if (face_cache->first.get() == NULL)
    face_cache->first.Init(skia_face->handle());

  hb_font_t* harfbuzz_font = hb_font_create(face_cache->first.get());
  const int scale = SkScalarToFixed(text_size);
  hb_font_set_scale(harfbuzz_font, scale, scale);
  FontData* hb_font_data = new FontData(&face_cache->second);
  
  hb_font_data->paint_.setTypeface(skia_face->own());
  hb_font_data->paint_.setTextSize(SkIntToScalar(text_size));
  hb_font_data->paint_.setAntiAlias(antialiasing == 0 ? false : true);
  hb_font_data->paint_.setLCDRenderText(subpixel_rendering_suppressed == 0 && subpixel_rendering != 0);
  hb_font_data->paint_.setSubpixelText(subpixel_positioning == 0 ? false : true);
  hb_font_data->paint_.setAutohinted(autohinter == 0 ? false : true);
  hb_font_data->paint_.setHinting(static_cast<SkPaint::Hinting>(hinting));

  hb_font_set_funcs(harfbuzz_font, g_font_funcs.Get().get(), hb_font_data, DeleteByType<FontData>);
  hb_font_make_immutable(harfbuzz_font);
  
  return harfbuzz_font;
}

void _HarfBuzzFontDestroy(HarfBuzzFontRef handle) {
  hb_font_destroy(reinterpret_cast<hb_font_t *>(handle));
}

void _HarfBuzzFontShape(HarfBuzzFontRef handle, HarfBuzzBufferRef buffer) {
  hb_shape(reinterpret_cast<hb_font_t *>(handle), reinterpret_cast<hb_buffer_t *>(buffer), nullptr, 0);
}

HarfBuzzBufferRef _HarfBuzzBufferCreate() {
  return hb_buffer_create();
}

void _HarfBuzzBufferDestroy(HarfBuzzBufferRef handle) {
  hb_buffer_destroy(reinterpret_cast<hb_buffer_t *>(handle));
}

void _HarfBuzzBufferAddUTF16(
  HarfBuzzBufferRef handle, 
  const uint16_t* text,
  int textLength,
  unsigned int itemOffset,
  int itemLength) {
  
  hb_buffer_add_utf16(reinterpret_cast<hb_buffer_t *>(handle), text, textLength, itemOffset, itemLength);
}

void _HarfBuzzBufferGetGlyphInfos(
  HarfBuzzBufferRef handle, 
  uint32_t* codepoints, 
  uint32_t* masks, 
  uint32_t* clusters, 
  uint32_t* len) {

  hb_glyph_info_t* glyphs = hb_buffer_get_glyph_infos(reinterpret_cast<hb_buffer_t *>(handle), len);

  for (uint32_t i = 0; i < *len; i++) {
    codepoints[i] = glyphs[i].codepoint;
    masks[i] = glyphs[i].mask;
    clusters[i] = glyphs[i].cluster;
  }

}

void _HarfBuzzBufferGetGlyphPositions(
  HarfBuzzBufferRef handle, 
  int* xadvances, 
  int* yadvances, 
  int* xoffset, 
  int* yoffset, 
  uint32_t* len) {

  hb_glyph_position_t* pos = hb_buffer_get_glyph_positions(reinterpret_cast<hb_buffer_t *>(handle), len);

  for (uint32_t i = 0; i < *len; i++) {
    xadvances[i] = pos[i].x_advance;
    yadvances[i] = pos[i].y_advance;
    xoffset[i] = pos[i].x_offset;
    yoffset[i] = pos[i].y_offset;
  }

}

void _HarfBuzzBufferSetScript(HarfBuzzBufferRef handle, int script) {
  hb_buffer_set_script(reinterpret_cast<hb_buffer_t *>(handle), static_cast<hb_script_t>(script));
}

void _HarfBuzzBufferSetDirection(HarfBuzzBufferRef handle, int dir) {
  hb_buffer_set_direction(reinterpret_cast<hb_buffer_t *>(handle), static_cast<hb_direction_t>(dir));
}

void _HarfBuzzBufferSetLanguage(HarfBuzzBufferRef handle, const char* lang, int len) {
  hb_language_t language = hb_language_from_string(lang, len);
  hb_buffer_set_language(reinterpret_cast<hb_buffer_t *>(handle), language);
}

void _HarfBuzzBufferSetDefaultLanguage(HarfBuzzBufferRef handle) {
  hb_buffer_set_language(reinterpret_cast<hb_buffer_t *>(handle), hb_language_get_default());
}

HarfBuzzScriptEnum _HarfBuzzScriptCreateString(const char* string, int len) {
  return hb_script_from_string(string, len);
}

HarfBuzzScriptEnum _HarfBuzzScriptCreateICU(int script) {
  if (script == USCRIPT_INVALID_CODE) {
    return HB_SCRIPT_INVALID;
  }
  return hb_icu_script_to_script(static_cast<UScriptCode>(script));
  //return hb_script_from_string(uscript_getShortName(static_cast<UScriptCode>(script)), -1);
}