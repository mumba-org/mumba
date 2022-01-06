// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

public class LabelButtonLabel : Label {

  public override var enabledColor: Color {
    get {
      return super.enabledColor
    }
    set {
      requestedEnabledColor = newValue
      enabledColorSet = true
      if isEnabled {
        super.enabledColor = newValue
      }
    }
  }

  public override var disabledColor: Color {
    get {
      return super.disabledColor
    }
    set {
      super.disabledColor = newValue
      requestedDisabledColor = newValue
      disabledColorSet = true
      if !isEnabled {
        super.enabledColor = newValue
      }
    }
  }
  
  //var requestedDisabledColor: Color = Color.Red
  //var requestedEnabledColor: Color = Color.Red
  //var disabledColorSet: Bool = false
  //var enabledColorSet: Bool = false

  public init(text: String, context: TextContext) {
    super.init(text: text, context: context, style: TextStyle.primary)
  }

  public override func onEnabledChanged() {
    setColorForEnableState()
    super.onEnabledChanged()
  }

  public override func onThemeChanged(theme: Theme) {
    setColorForEnableState()
    super.onThemeChanged(theme: theme)
  }

  func setColorForEnableState() {
    if isEnabled ? enabledColorSet : disabledColorSet {
      super.enabledColor = isEnabled ? requestedEnabledColor : requestedDisabledColor
    } else {
      let style: TextStyle = isEnabled ? .primary : .disabled
      super.enabledColor = TextStyles.getColor(view: self, context: textContext, style: style)
    }
  }

}