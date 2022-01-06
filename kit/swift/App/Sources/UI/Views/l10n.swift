// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct l10n {
  
  public static func getStringUTF16(_ id: Int) -> String {
    var str = ResourceBundle.getLocalizedString(id)
    l10n.adjustParagraphDirectionality(&str)
    return str
  }

  fileprivate static func adjustParagraphDirectionality(_ str: inout String) {

  }

}