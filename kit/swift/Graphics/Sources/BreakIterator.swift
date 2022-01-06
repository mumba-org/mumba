// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum BreakType {
  case Word
  case Line
  case Newline
  case Char
  case RuleBased
}

public enum WordBreakStatus {
  // The end of text that the iterator recognizes as word characters.
  // Non-word characters are things like punctuation and spaces.
  case IsWordBreak
  // Characters that the iterator can skip past, such as punctuation,
  // whitespace, and, if using RULE_BASED mode, characters from another
  // character set.
  case IsSkippableWord
  // Only used if not in BREAK_WORD or RULE_BASED mode. This is returned for
  // newlines, line breaks, and character breaks.
  case IsLineOrCharBreak
}

public struct BreakIterator {

  // Under BREAK_WORD mode, returns true if the break we just hit is the
  // end of a word. (Otherwise, the break iterator just skipped over e.g.
  // whitespace or punctuation.)  Under BREAK_LINE and BREAK_NEWLINE modes,
  // this distinction doesn't apply and it always returns false.
  public var isWord: Bool {
    return false
  }

  public var wordBreakStatus: WordBreakStatus {
    return .IsWordBreak
  }

    // Returns the string between prev() and pos().
  // Advance() must have been called successfully at least once for pos() to
  // have advanced to somewhere useful.
  public var string: String {
    return ""
  }

  // Returns the value of pos() returned before Advance() was last called.
  public private(set) var prev: Int

  // Returns the current break position within the string,
  // or BreakIterator::npos when done.
  public private(set) var pos: Int

  public init() {
    prev = 0
    pos = 0
  }

  // Requires |str| to live as long as the BreakIterator does.
  public init(str: String, type: BreakType) {
    prev = 0
    pos = 0
  }
  // Make a rule-based iterator. BreakType == RULE_BASED is implied.
  // TODO(andrewhayden): This signature could easily be misinterpreted as
  // "(const string16& str, const string16& locale)". We should do something
  // better.
  public init(str: String, rules: String) {
    prev = 0
    pos = 0
  }

  // Init() must be called before any of the iterators are valid.
  // Returns false if ICU failed to initialize.
  public func initialize() -> Bool {
    return false
  }

  // Advance to the next break.  Returns false if we've run past the end of
  // the string.  (Note that the very last "break" is after the final
  // character in the string, and when we advance to that position it's the
  // last time Advance() returns true.)
  public func advance() -> Bool {
    return false
  }

  // Updates the text used by the iterator, resetting the iterator as if
  // if Init() had been called again. Any old state is lost. Returns true
  // unless there is an error setting the text.
  public func setText(text: [Character]) -> Bool {
    return false
  }

  // Under BREAK_WORD mode:
  //  - Returns IS_SKIPPABLE_WORD if non-word characters, such as punctuation or
  //    spaces, are found.
  //  - Returns IS_WORD_BREAK if the break we just hit is the end of a sequence
  //    of word characters.
  // Under RULE_BASED mode:
  //  - Returns IS_SKIPPABLE_WORD if characters outside the rules' character set
  //    or non-word characters, such as punctuation or spaces, are found.
  //  - Returns IS_WORD_BREAK if the break we just hit is the end of a sequence
  //    of word characters that are in the rules' character set.
  // Not under BREAK_WORD or RULE_BASED mode:
  //  - Returns IS_LINE_OR_HAR_BREAK.
 
  // Under BREAK_WORD mode, returns true if |position| is at the end of word or
  // at the start of word. It always returns false under BREAK_LINE and
  // BREAK_NEWLINE modes.
  public func isEndOfWord(pos: Int) -> Bool {
    return false
  }

  public func isStartOfWord(pos: Int) -> Bool {
    return false
  }

  // Under BREAK_HARACTER mode, returns whether |position| is a Unicode
  // grapheme boundary.
  public func isGraphemeBoundary(pos: Int) -> Bool {
    return false
  }

}