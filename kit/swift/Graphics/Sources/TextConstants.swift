// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Specifies the word wrapping behavior when a word would exceed the available
// display width. All words that are too wide will be put on a new line, and
// then:
public enum WordWrapBehavior {
  case IgnoreLongWords   // Overflowing word text is left on that line.
  case TruncateLongWords // Overflowing word text is truncated.
  case ElideLongWords    // Overflowing word text is elided at the ellipsis.
  case WrapLongWords     // Overflowing word text is wrapped over multiple lines.
}

// Horizontal text alignment modes.
public enum HorizontalAlignment {
  case AlignLeft // Align the text's left edge with that of its display area.
  case AlignCenter   // Align the text's center with that of its display area.
  case AlignRight    // Align the text's right edge with that of its display area.
  case AlignToHead  // Align the text to its first strong character's direction.
}

// The directionality modes used to determine the base text direction.
public enum DirectionalityMode {
  case DirectionalityFromText // Use the first strong character's direction.
  case DirectionalityFromUI      // Use the UI locale's text reading direction.
  case DirectionalityForceLTR     // Use LTR regardless of content or UI locale.
  case DirectionalityForceRTL     // Use RTL regardless of content or UI locale.
}

// Text baseline offset types.
// Figure of font metrics:
//   +--------+--------+------------------------+-------------+
//   |        |        | internal leading       | SUPERSCRIPT |
//   |        |        +------------+-----------|             |
//   |        | ascent |            | SUPERIOR  |-------------+
//   | height |        | cap height |-----------|
//   |        |        |            | INFERIOR  |-------------+
//   |        |--------+------------+-----------|             |
//   |        | descent                         | SUBSCRIPT   |
//   +--------+---------------------------------+-------------+
public enum BaselineStyle {
  case NormalBaseline
  case Superscript  // e.g. a mathematical exponent would be superscript.
  case Superior     // e.g. 8th, the "th" would be superior script.
  case Inferior     // e.g. 1/2, the "2" would be inferior ("1" is superior).
  case Subscript    // e.g. H2O, the "2" would be subscript.
}

// Elision behaviors of text that exceeds constrained dimensions.
public enum ElideBehavior {
  case NoElide // Do not modify the text, it may overflow its available bounds.
  case Truncate     // Do not elide or fade, just truncate at the end of the string.
  case ElideHead   // Add an ellipsis at the start of the string.
  case ElideMiddle // Add an ellipsis in the middle of the string.
  case ElideTail   // Add an ellipsis at the end of the string.
  case ElideEmail  // Add ellipses to username and domain substrings.
  case FadeTail    // Fade the string's end opposite of its horizontal alignment.
}

public enum SelectionBehavior {
  // Default behavior for a move-and-select command. The selection start point
  // remains the same. For example, this is the behavior of textfields on Mac
  // for the command moveUpAndModifySelection (Shift + Up).
  case SelectionRetain

  // Use for move-and-select commands that want the existing selection to be
  // extended in the opposite direction, when the selection direction is
  // reversed. For example, this is the behavior for textfields on Mac for the
  // command moveToLeftEndOfLineAndModifySelection (Command + Shift + Left).
  case SelectionExtend

  // Use for move-and-select commands that want the existing selection to reduce
  // to a caret, when the selection direction is reversed. For example, this is
  // the behavior for textfields on Mac for the command
  // moveWordLeftAndModifySelection (Alt + Shift + Left).
  case SelectionCaret

  // No selection. To be used for move commands that don't want to cause a
  // selection, and that want to collapse any pre-existing selection.
  case SelectionNone
}

// the 'official' one is on 'Base'

// public enum TextDirection: Int {
//   case Unknown = 0
//   case RightToLeft = 1
//   case LeftToRight = 2

//   public static var count: Int {
//     return 3
//   }
// }