// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CONTENT_PUBLIC_BROWSER_CONTEXT_FACTORY_H_
#define CONTENT_PUBLIC_BROWSER_CONTEXT_FACTORY_H_

namespace ui {
class ContextFactory;
class ContextFactoryPrivate;
}

namespace host {

// Returns the singleton ContextFactory used by content. The return value is
// owned by content.
ui::ContextFactory* GetContextFactory();

// Returns the singleton ContextFactoryPrivate used by content. The return value
// is owned by content.
// TODO(fsamuel): Once Mus is used on all platforms, this private interface
// should not be necessary.
ui::ContextFactoryPrivate* GetContextFactoryPrivate();

}  // namespace host

#endif  // CONTENT_PUBLIC_BROWSER_CONTEXT_FACTORY_H_
