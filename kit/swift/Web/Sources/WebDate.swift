// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics
import MumbaShims

public enum WebDateTimeInputType : Int {
    case None = 0
    case Date
    case DateTime
    case DateTimeLocal
    case Month
    case Time
    case Week
}

public struct WebDateTimeSuggestion {
    public var value: Double
    public var localizedValue: String
    public var label: String
}

public struct WebDateTimeChooserParams {
    public var type: WebDateTimeInputType
    public var anchorRectInScreen: IntRect
    // public var currentValue: String
    public var doubleValue: Double
    // public var suggestions: [WebDateTimeSuggestion]
    public var minimum: Double
    public var maximum: Double
    public var step: Double 
    public var stepBase: Double
    public var isRequired: Bool
    public var isAnchorElementRTL: Bool
}

public class WebDateTimeChooserCompletion {
    var reference: WebDateTimeChooserCompletionRef

    init(reference: WebDateTimeChooserCompletionRef) {
        self.reference = reference
    }
}