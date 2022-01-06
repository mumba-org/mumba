// Copyright (c) 2011 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef STORAGE_STORAGE_EXPORT_H_
#define STORAGE_STORAGE_EXPORT_H_

// Defines STORAGE_EXPORT so that functionality implemented by the net module can
// be exported to consumers, and STORAGE_EXPORT_PRIVATE that allows unit tests to
// access features not intended to be used directly by real consumers.

#if defined(COMPONENT_BUILD)
#if defined(WIN32)

#define STORAGE_EXPORT __declspec(dllexport)
#define STORAGE_EXPORT_PRIVATE __declspec(dllexport)
#else  // defined(WIN32)
#define STORAGE_EXPORT __attribute__((visibility("default")))
#define STORAGE_EXPORT_PRIVATE __attribute__((visibility("default")))
#endif

#else  /// defined(COMPONENT_BUILD)
#define STORAGE_EXPORT
#define STORAGE_EXPORT_PRIVATE
#endif

#endif  // NET_BASE_NET_EXPORT_H_
