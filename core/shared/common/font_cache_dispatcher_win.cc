// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/shared/common/font_cache_dispatcher_win.h"

#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "base/macros.h"
#include "base/strings/string16.h"
#include "mojo/public/cpp/bindings/strong_binding.h"
#include "services/service_manager/public/cpp/bind_source_info.h"

namespace common {
namespace {
typedef std::vector<base::string16> FontNameVector;
typedef std::map<FontCacheDispatcher*, FontNameVector> DispatcherToFontNames;

class FontCache {
 public:
  static FontCache* GetInstance() { return base::Singleton<FontCache>::get(); }

  void PreCacheFont(const LOGFONT& font, FontCacheDispatcher* dispatcher) {
    base::AutoLock lock(mutex_);

    // Fetch the font into memory.
    // No matter the font is cached or not, we load it to avoid GDI swapping out
    // that font file.
    HDC hdc = GetDC(NULL);
    HFONT font_handle = CreateFontIndirect(&font);
    DCHECK(NULL != font_handle);

    HGDIOBJ old_font = SelectObject(hdc, font_handle);
    DCHECK(NULL != old_font);

    TEXTMETRIC tm;
    BOOL ret = GetTextMetrics(hdc, &tm);
    DCHECK(ret);

    base::string16 font_name = font.lfFaceName;
    int ref_count_inc = 1;
    FontNameVector::iterator it =
        std::find(dispatcher_font_map_[dispatcher].begin(),
                  dispatcher_font_map_[dispatcher].end(),
                  font_name);
    if (it == dispatcher_font_map_[dispatcher].end()) {
      // Requested font is new to cache.
      dispatcher_font_map_[dispatcher].push_back(font_name);
    } else {
      ref_count_inc = 0;
    }

    if (cache_[font_name].ref_count_ == 0) {  // Requested font is new to cache.
      cache_[font_name].ref_count_ = 1;
    } else {  // Requested font is already in cache, release old handles.
      SelectObject(cache_[font_name].dc_, cache_[font_name].old_font_);
      DeleteObject(cache_[font_name].font_);
      ReleaseDC(NULL, cache_[font_name].dc_);
    }
    cache_[font_name].font_ = font_handle;
    cache_[font_name].dc_ = hdc;
    cache_[font_name].old_font_ = old_font;
    cache_[font_name].ref_count_ += ref_count_inc;
  }

  void ReleaseCachedFonts(FontCacheDispatcher* dispatcher) {
    typedef std::map<base::string16, FontCache::CacheElement> FontNameToElement;

    base::AutoLock lock(mutex_);

    DispatcherToFontNames::iterator it;
    it = dispatcher_font_map_.find(dispatcher);
    if (it == dispatcher_font_map_.end()) {
      return;
    }

    for (FontNameVector::iterator i = it->second.begin(), e = it->second.end();
                                  i != e; ++i) {
      FontNameToElement::iterator element;
      element = cache_.find(*i);
      if (element != cache_.end()) {
        --((*element).second.ref_count_);
      }
    }

    dispatcher_font_map_.erase(it);
    for (FontNameToElement::iterator i = cache_.begin(); i != cache_.end(); ) {
      if (i->second.ref_count_ == 0) {
        cache_.erase(i++);
      } else {
        ++i;
      }
    }
  }

 private:
  struct CacheElement {
    CacheElement()
        : font_(NULL), old_font_(NULL), dc_(NULL), ref_count_(0) {
    }

    ~CacheElement() {
      if (font_) {
        if (dc_ && old_font_) {
          SelectObject(dc_, old_font_);
        }
        DeleteObject(font_);
      }
      if (dc_) {
        ReleaseDC(NULL, dc_);
      }
    }

    HFONT font_;
    HGDIOBJ old_font_;
    HDC dc_;
    int ref_count_;
  };
  friend struct base::DefaultSingletonTraits<FontCache>;

  FontCache() {
  }

  std::map<base::string16, CacheElement> cache_;
  DispatcherToFontNames dispatcher_font_map_;
  base::Lock mutex_;

  DISALLOW_COPY_AND_ASSIGN(FontCache);
};

}  // namespace

FontCacheDispatcher::FontCacheDispatcher() {}

FontCacheDispatcher::~FontCacheDispatcher() {
}

// static
void FontCacheDispatcher::Create(
    mojom::FontCacheWinRequest request,
    const service_manager::BindSourceInfo& source_info) {
  mojo::MakeStrongBinding(std::make_unique<FontCacheDispatcher>(),
                          std::move(request));
}

void FontCacheDispatcher::PreCacheFont(const LOGFONT& log_font,
                                       PreCacheFontCallback callback) {
  // If a child process is running in a sandbox, GetTextMetrics()
  // can sometimes fail. If a font has not been loaded
  // previously, GetTextMetrics() will try to load the font
  // from the font file. However, the sandboxed process does
  // not have permissions to access any font files and
  // the call fails. So we make the browser pre-load the
  // font for us by using a dummy call to GetTextMetrics of
  // the same font.
  // This means the browser process just loads the font into memory so that
  // when GDI attempt to query that font info in child process, it does not
  // need to load that file, hence no permission issues there.  Therefore,
  // when a font is asked to be cached, we always recreates the font object
  // to avoid the case that an in-cache font is swapped out by GDI.
  FontCache::GetInstance()->PreCacheFont(log_font, this);

  // Run |callback| to indicate this synchronous handler finished.
  std::move(callback).Run();
}

void FontCacheDispatcher::ReleaseCachedFonts() {
  // Release cached fonts that requested from a pid by decrementing the ref
  // count.  When ref count is zero, the handles are released.
  FontCache::GetInstance()->ReleaseCachedFonts(this);
}

}  // namespace common
