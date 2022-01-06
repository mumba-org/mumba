// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Web

// A Painter associated with a CSS stylesheet
// The idea is to bind to a existant stylesheet
// in a web document or create it programatically
// on code.
// Once the stylesheet is available to DOM elements
// and a element is bound to it, it will be painted
// by a custom painter that implements this interface

public protocol CSSPainter : CanvasPainter {}