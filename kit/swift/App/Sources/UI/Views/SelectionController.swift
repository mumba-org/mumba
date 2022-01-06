// Copyright (c) 2018 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

internal func getDoubleClickInterval() -> Int64 {
#if os(Windows)
  return GetDoubleClickTime()
#else
  return 500
#endif
}

public protocol SelectionControllerDelegate : class {

  var renderTextForSelectionController: RenderText? {
    get
  }

  var isReadonly: Bool {
    get
  }

  var supportsDrag: Bool {
    get
  }

  var hasTextBeingDragged: Bool {
    get
    set
  }

  var viewHeight: Int {
    get
  }

  var viewWidth: Int {
    get
  }

  var dragSelectionDelay: Int {
    get
  }

  func onBeforePointerAction()
  func onAfterPointerAction(textChanged: Bool,
                            selectionChanged: Bool)
  func pasteSelectionClipboard() -> Bool
  func updateSelectionClipboard()
}

public class SelectionController {

  public enum InitialFocusStateOnMousePress {
    case Focused
    case Unfocused
  }

  public var lastClickLocation: IntPoint = IntPoint()
  public var handlesSelectionClipboard: Bool = false

  private var maybeRenderText: RenderText? {
    return delegate?.renderTextForSelectionController
  }

  fileprivate weak var delegate: SelectionControllerDelegate!

  // A timer and point used to modify the selection when dragging.
  fileprivate var dragSelectionTimer: RepeatingTimer = RepeatingTimer(tickClock: nil)
  fileprivate var lastDragLocation: IntPoint = IntPoint()

  // State variables used to track the last click time and location.
  fileprivate var lastClickTime: TimeTicks  = TimeTicks()

  // Used to track double and triple clicks. Can take the values 0, 1 and 2
  // which specify a single, double and triple click respectively. Alternates
  // between a double and triple click for continous clicks.
  fileprivate var aggregatedClicks: UInt = 0

  // The range selected on a double click.
  fileprivate var doubleClickWord: TextRange = TextRange()
 
  public init (delegate: SelectionControllerDelegate) {
    self.delegate = delegate
  }

  public func onMousePressed(event: MouseEvent,
                             handled: Bool,
                             initialFocusState: InitialFocusStateOnMousePress) -> Bool {
   
    guard let rendertext = maybeRenderText else {
      return false
    }
  
    trackMouseClicks(event: event)
   
    if handled {
      return true
    }

    if event.onlyLeftMouseButton {
      if delegate.supportsDrag {
        delegate.hasTextBeingDragged = false
      }

      switch aggregatedClicks {
        case 0:
          // If the click location is within an existing selection, it may be a
          // potential drag and drop.
          if delegate.supportsDrag &&
              rendertext.isPointInSelection(point: FloatPoint(event.location)) {
            delegate.hasTextBeingDragged = true
          } else {
            delegate.onBeforePointerAction()
            let selectionChanged = rendertext.moveCursorTo(
                point: FloatPoint(event.location), select: event.isShiftDown)
            delegate.onAfterPointerAction(textChanged: false, selectionChanged: selectionChanged)
          }
        case 1:
          // Select the word at the click location on a double click.
          selectWord(point: event.location)
          doubleClickWord = rendertext.selection
        case 2:
          // Select all the text on a triple click.
          selectAll()
        default:
          assert(false)
      }
    }

    if event.onlyRightMouseButton {
      if PlatformStyle.selectAllOnRightClickWhenUnfocused &&
          initialFocusState == .Unfocused {
        selectAll()
      } else if PlatformStyle.selectWordOnRightClick &&
                !rendertext.isPointInSelection(point: FloatPoint(event.location)) {
        selectWord(point: event.location)
      }
    }

    if handlesSelectionClipboard && event.onlyMiddleMouseButton &&
        !delegate.isReadonly {
      delegate.onBeforePointerAction()
      let selectionChanged =
          rendertext.moveCursorTo(point: FloatPoint(event.location), select: false)
      let textChanged = delegate.pasteSelectionClipboard()
      delegate.onAfterPointerAction(textChanged: textChanged,
                                    selectionChanged: selectionChanged || textChanged)
    }

    return true
  }
  
  public func onMouseDragged(event: MouseEvent) -> Bool {
    lastDragLocation = event.location

    // Don't adjust the cursor on a potential drag and drop.
    if delegate.hasTextBeingDragged || !event.onlyLeftMouseButton {
      return true
    }

    // A timer is used to continuously scroll while selecting beyond side edges.
    let x = event.location.x
    let width = delegate.viewWidth
    let dragSelectionDelay = delegate.dragSelectionDelay
    if (x >= 0 && x <= width) || dragSelectionDelay == 0 {
      dragSelectionTimer.stop()
      selectThroughLastDragLocation()
    } else if !dragSelectionTimer.isRunning {
      // Select through the edge of the visible text, then start the scroll timer.
      lastDragLocation.x = min(max(0, x), width)
      selectThroughLastDragLocation()

      dragSelectionTimer.start(delay: TimeDelta.from(milliseconds: Int64(dragSelectionDelay)),
      { self.selectThroughLastDragLocation() })
    }

    return true
  }
  
  public func onMouseReleased(event: MouseEvent) {
 
    guard let rendertext = maybeRenderText else {
      return
    }

    dragSelectionTimer.stop()

    // Cancel suspected drag initiations, the user was clicking in the selection.
    if delegate.hasTextBeingDragged {
      delegate.onBeforePointerAction()
      let selectionChanged = rendertext.moveCursorTo(point: FloatPoint(event.location), select: false)
      delegate.onAfterPointerAction(textChanged: false, selectionChanged: selectionChanged)
    }

    if delegate.supportsDrag {
      delegate.hasTextBeingDragged = false
    }

    if handlesSelectionClipboard && !rendertext.selection.isEmpty {
      delegate.updateSelectionClipboard()
    }

  }

  public func onMouseCaptureLost() {
    guard let rendertext = maybeRenderText else {
      return
    }

    dragSelectionTimer.stop()

    if handlesSelectionClipboard && !rendertext.selection.isEmpty {
      delegate.updateSelectionClipboard()
    }
  }
 
  public func offsetDoubleClickWord(offset: Int) {
    doubleClickWord.start = doubleClickWord.start + offset
    doubleClickWord.end = doubleClickWord.end + offset
  }

  fileprivate func trackMouseClicks(event: MouseEvent) {
    if event.onlyLeftMouseButton {
      let timeDelta: TimeDelta = event.timestamp - lastClickTime
      let delta: IntVec2 = IntPoint(event.rootLocation) - lastClickLocation
      if !lastClickTime.isNull &&
          timeDelta.milliseconds <= getDoubleClickInterval() &&
          !View.exceededDragThreshold(delta: delta) {
        // Upon clicking after a triple click, the count should go back to
        // double click and alternate between double and triple. This assignment
        // maps 0 to 1, 1 to 2, 2 to 1.
        aggregatedClicks = (aggregatedClicks % 2) + 1
      } else {
        aggregatedClicks = 0
      }
      lastClickTime = event.timestamp
      lastClickLocation = IntPoint.toRounded(point: event.rootLocation)
    }
  }

  // Selects the word at the given |point|.
  fileprivate func selectWord(point: IntPoint) {
    guard let rendertext = maybeRenderText else {
      return
    }
    delegate.onBeforePointerAction()
    let _ = rendertext.moveCursorTo(point: FloatPoint(point), select: false)
    rendertext.selectWord()
    delegate.onAfterPointerAction(textChanged: false, selectionChanged: true)
  }

  // Selects all the text.
  fileprivate func selectAll() {
    guard let rendertext = maybeRenderText else {
      return
    }
    delegate.onBeforePointerAction()
    rendertext.selectAll(reversed: false)
    delegate.onAfterPointerAction(textChanged: false, selectionChanged: true)
  }

  fileprivate func selectThroughLastDragLocation() {
    guard let rendertext = maybeRenderText else {
      return
    }

    delegate.onBeforePointerAction()
    let _ = rendertext.moveCursorTo(point: FloatPoint(lastDragLocation), select: true)

    if aggregatedClicks == 1 {
      rendertext.selectWord()
      // Expand the selection so the initially selected word remains selected.
      var selection = rendertext.selection
      let lmin = min(selection.minimum, doubleClickWord.minimum)
      let lmax = max(selection.maximum, doubleClickWord.maximum)
      let reversed = selection.isReversed
      selection.start = (reversed ? lmax : lmin)
      selection.end = (reversed ? lmin : lmax)
      let _ = rendertext.selectRange(range: selection)
    }

    delegate.onAfterPointerAction(textChanged: false, selectionChanged: true)
  }

}
