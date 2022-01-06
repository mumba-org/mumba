// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public struct TextLine {
 
 var text: Text
 var start: Int
 var end: Int

 init(text: Text, start: Int, end: Int) {
   self.text = text
   self.start = start
   self.end = end
 }

}