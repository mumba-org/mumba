// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Base
import Graphics

public class DialogClientView : ClientView,
                                ButtonListener,
                                DialogObserver {

 public var buttonRowInsets: IntInsets {
   didSet {
     if widget != nil {
       updateDialogButtons()
     }
   }
 }

 public override var canClose: Bool {
   if let dialog = self.dialogDelegate, !self.delegateAllowedClose {
    delegateAllowedClose = dialog.close()
   }
   return delegateAllowedClose
 }

 public override var minimumSize: IntSize {
   get {
     return getBoundingSizeForVerticalStack(
      super.minimumSize, 
      buttonRowContainer!.minimumSize)
   }
   set {
     _minimumSize = newValue
   }
 }

 public override var maximumSize: IntSize {
  let unconstrained = 0
  var maxSize = super.maximumSize

  if maxSize.height != unconstrained {
    maxSize.enlarge(width: 0, height: buttonRowContainer!.preferredSize.height)
  }
  return maxSize
 }

 public private(set) var cancelButton: LabelButton?
 public private(set) var okButton: LabelButton?
 //public var minimumSize: IntSize = IntSize()

 private var dialogDelegate: DialogDelegate? {
   return widget?.widgetDelegate?.asDialogDelegate()
 }

 private var extraViewSpacing: Int {
   if !shouldShow(extraView) || !(okButton != nil || cancelButton != nil) {
     return 0
   }
   
   if let extraViewPadding = dialogDelegate?.extraViewPadding {
     return extraViewPadding
   }

   return LayoutProvider.instance().getDistanceMetric(DistanceMetric.RelatedButtonHorizontal)
 }

 private var buttonRowViews: [View?] {
    let first: View? = shouldShow(extraView) ? extraView : nil
    var second: View? = cancelButton
    var third: View? = okButton
    if PlatformStyle.isOkButtonLeading {
      let tmp = second
      second = third
      third = tmp
    }
    return [first, second, third]
 }

 private var extraView: View?
 private var buttonRowContainer: ButtonRowContainer?
 private var delegateAllowedClose: Bool = false
 private var addingOrRemovingViews: Bool = false
 private var _minimumSize: IntSize = IntSize()

 public init(owner: UIWidget, contentsView: View) {
  buttonRowInsets = LayoutProvider.instance().getInsetsMetric(InsetsMetric.DialogButtonRow)
  super.init(owner: owner, contentsView: contentsView)
  buttonRowContainer = ButtonRowContainer(owner: self)
  // TODO: fix modifiers to accept 'EventFlags' type instead of pure Int
  addAccelerator(accelerator: Accelerator(keycode: KeyboardCode.KeyEscape, modifiers: EventFlags.None.rawValue))
  addChild(view: self.buttonRowContainer!)
 }

 deinit {
   if self.widget != nil {
     if let dialog = self.dialogDelegate {
       dialog.removeObserver(self)
     }
   }
 }

 public func acceptWindow() {
   guard let dialog = self.dialogDelegate else {
     return
   }
   if !delegateAllowedClose && dialog.accept() {
     delegateAllowedClose = true
     if let w = self.widget {
      w.close()
     }
   }
 }

 public func cancelWindow() {
   guard let dialog = self.dialogDelegate else {
     return
   }
   if !delegateAllowedClose && dialog.cancel() {
     delegateAllowedClose = true
     if let w = self.widget {
      w.close()
     }
   }
 }

 public override func asDialogClientView() -> DialogClientView? {
   return self
 }

 open override func calculatePreferredSize() -> IntSize {
    guard let dialog = dialogDelegate else {
      return IntSize()
    }
    var contentsSize = super.calculatePreferredSize()
    let contentMargins = dialog.margins
    contentsSize.enlarge(width: contentMargins.width, height: contentMargins.height)
    return getBoundingSizeForVerticalStack(
      contentsSize, buttonRowContainer!.preferredSize)
 }

 public override func layout() {
    buttonRowContainer!.size = IntSize(width: width, height: buttonRowContainer!.getHeightFor(width: width))

    buttonRowContainer!.y = height - buttonRowContainer!.height
    
    if let view = self.contentsView {
      var contentsBounds = IntRect(width: width, height: buttonRowContainer!.y)
      contentsBounds.inset(insets: dialogDelegate!.margins)
      //view.boundsRect = contentsBounds
      view.bounds = contentsBounds
    }
 }

 public override func viewHierarchyChanged(details: ViewHierarchyChangedDetails) {
    super.viewHierarchyChanged(details: details)

    if details.isAdd {
      ////print("inside if details.isAdd..")
      if details.child === self {
        updateDialogButtons()
        if let dialog = dialogDelegate {
          dialog.addObserver(self)
        }
      }
      ////print("inside if details.isAdd: returning")
      return
    }

    ////print("details.parent !== buttonRowContainer ?")
    if details.parent !== buttonRowContainer {
      ////print("details.parent !== buttonRowContainer ? yes.. returning")
      return
    }

    ////print("if addingOrRemovingViews")
    if addingOrRemovingViews {
      ////print("if addingOrRemovingViews: yes.. returning")
      return
    }

    ////print("if let buttonRow = buttonRowContainer")
    if let buttonRow = buttonRowContainer {
      ////print("buttonRow.layoutManager = nil")
      buttonRow.layoutManager = nil
    }

    ////print("if details.child === self.okButton")
    if details.child === self.okButton {
      ////print("if details.child === self.okButton: yes.. self.okButton = nil")
      self.okButton = nil
    } else if details.child === self.cancelButton {
      ////print("if details.child === self.cancelButton: yes.. self.cancelButton = nil")
      self.cancelButton = nil
    } else if details.child === self.extraView {
      ////print("if details.child === self.extraView: yes.. self.extraView = nil")
      self.extraView = nil
    }
 }

 open override func acceleratorPressed(accelerator: Accelerator) -> Bool {
    if let w = self.widget {
      w.close()
    }
    return true
 }

 public override func onThemeChanged(theme: Theme) {
   if let dialog = dialogDelegate, dialog.shouldUseCustomFrame {
     self.background = BackgroundFactory.makeSolidBackground(
       color: self.theme.getSystemColor(id: Theme.ColorId.DialogBackground))
   }
 }

 open override func childPreferredSizeChanged(child: View) {
   if !addingOrRemovingViews && child === extraView {
    layout()
   }
 }

 open override func childVisibilityChanged(child: View) {
   if child === self.extraView {
     updateDialogButtons()
   }
   childPreferredSizeChanged(child: child)
 }

 public func onDialogModelChanged() {
   updateDialogButtons()
 }

 public func buttonPressed(sender: Button, event: Graphics.Event) {
    //guard let dialog = dialogDelegate else {
    //  return
    //}
    guard dialogDelegate != nil else {
      return
    }
    
    if sender === self.okButton {
      acceptWindow()
    } else if sender === self.cancelButton {
      cancelWindow()
    } //else {
    //  assert(false)
    //}
 }

 private func updateDialogButtons() {
   setupLayout()
   invalidateLayout()
 }

 private func updateDialogButton(member: inout LabelButton?, type: DialogButton) {
    guard let dialog = dialogDelegate else {
      return
    }
    
    if (dialog.dialogButtons & type.rawValue) == 0 {
      member = nil
      return
    }

    if member == nil {
      let title = dialog.getDialogButtonLabel(button: type)
      var button: LabelButton?

      //let isDefault = dialog.defaultDialogButton == type.rawValue &&
      //                        (type != DialogButton.Cancel ||
      //                        PlatformStyle.dialogDefaultButtonCanBeCancel)

      button = createButton(listener: self, text: title)
               //isDefault ? MdTextButton.createSecondaryUiBlueButton(self, title)
               //          : MdTextButton.createSecondaryUiButton(self, title)

      let minimumWidth = LayoutProvider.instance().getDistanceMetric(DistanceMetric.DialogButtonMinimumWidth)
      button!.minSize = IntSize(width: minimumWidth, height: 0)

      button!.group = buttonGroup
      member = button
    }
    dialog.updateButton(button: member!, type: type)
 }

 private func setupLayout() {
   let lastAddingOrRemovingViews = addingOrRemovingViews
   addingOrRemovingViews = true

   defer {
      addingOrRemovingViews = lastAddingOrRemovingViews
   }

   let viewTracker = ViewTracker(view: focusManager!.focusedView)

    let layout = GridLayout(host: buttonRowContainer!)
    buttonRowContainer!.layoutManager = layout
    layout.minimumSize = self.minimumSize

    setupViews()

    let views = buttonRowViews

    if let extra = extraView, views[0] == nil {
      addChild(view: extra)
    }
    
    var nullViewCount = 0
    for view in views {
      if view == nil { 
        nullViewCount += 1 
      } 
    }

    if nullViewCount == views.count {
      return
    }

    let fixed: Float = 0.0
    let stretchy: Float = 1.0

    let layoutProvider = LayoutProvider.instance()
    let buttonSpacing: Int = (okButton != nil && cancelButton != nil)
                                  ? layoutProvider.getDistanceMetric(
                                      DistanceMetric.RelatedButtonHorizontal)
                                  : 0

    let buttonRowId = 0
    let columnSet = layout.addColumnSet(id: buttonRowId)

    columnSet.addPaddingColumn(resizePercent: fixed, width: buttonRowInsets.left)
    columnSet.addColumn(
      halign: .Fill, 
      valign: .Fill, 
      resizePercent: fixed, 
      sizeType: .UsePref, 
      fixedWidth: 0,
      minWidth: 0)
    columnSet.addPaddingColumn(resizePercent: stretchy,  width: self.extraViewSpacing)
    columnSet.addColumn(
      halign: .Fill, 
      valign: .Fill, 
      resizePercent: fixed, 
      sizeType: .UsePref, 
      fixedWidth: 0, 
      minWidth: 0)
    columnSet.addPaddingColumn(resizePercent: fixed, width: buttonSpacing)
    columnSet.addColumn(
        halign: .Fill,
        valign: .Fill,
        resizePercent: fixed,
        sizeType: .UsePref,
        fixedWidth: 0,
        minWidth: 0)
    columnSet.addPaddingColumn(resizePercent: fixed, width: buttonRowInsets.right)

    let viewToColumnIndex: [Int] = [1, 3, 5]
    var link: [Int] = [-1, -1, -1]
    var linkIndex = 0

    layout.startRowWithPadding(verticalResize: fixed, columnSetId: buttonRowId, paddingResize: fixed, padding: self.buttonRowInsets.top)
    for viewIndex in 0..<views.count {
      if views[viewIndex] != nil {
        layout.addView(view: views[viewIndex]!)
        link[linkIndex] = viewToColumnIndex[viewIndex]
        linkIndex += 1
      } else {
        layout.skipColumns(colCount: 1)
      }
    }

    columnSet.linkedColumnSizeLimit = layoutProvider.getDistanceMetric(
      DistanceMetric.ButtonMaxLinkableWidth)

    /// If views[0] is non-null, it is a visible extraView and its column
    /// will be in link[0]. Skip that if it is not a button, or if it is a
    /// specific subclass of Button that should never be linked. Otherwise, link
    /// everything.
    var skipFirstLink: Bool = false
        if let view = views[0] {
          if view as? Button == nil ||
             view.className == Checkbox.viewClassName ||
             view.className == ImageButton.viewClassName {
            skipFirstLink = true
          }
        }
        //views[0] != nil && views[0] as? Button == nil ||
       //             views[0]!.className == Checkbox.viewClassName ||
        //            views[0]!.className == ImageButton.viewClassName
    
    if skipFirstLink {
      columnSet.linkColumnSizes(first: link[1], link[2], -1)
    } else {
      columnSet.linkColumnSizes(first: link[0], link[1], link[2], -1)
    }

    layout.addPaddingRow(verticalResize: fixed, pixelCount: buttonRowInsets.bottom)

    if let previouslyFocusedView = viewTracker.view, focusManager!.focusedView == nil, contains(view: previouslyFocusedView) {
      previouslyFocusedView.requestFocus()
    }
 }

 private func setupViews() {
    buttonRowContainer!.removeAllChildren(deleteChildren: false)
    
    if let extra = extraView {
      removeChild(view: extra)
    }

    updateDialogButton(member: &self.okButton, type: DialogButton.Ok)
    updateDialogButton(member: &self.cancelButton, type: DialogButton.Cancel)

    if extraView != nil {
      return
    }

    extraView = dialogDelegate!.createExtraView()
    if let btn = extraView as? Button {
      btn.group = buttonGroup
    }
 }

}

fileprivate class ButtonRowContainer : View {
  
  weak var owner: DialogClientView?

  init(owner: DialogClientView) {
    self.owner = owner
  }

  open override func childPreferredSizeChanged(child: View) {
    if let client = owner {
      client.childPreferredSizeChanged(child: child)
    }
  }

  open override func childVisibilityChanged(child: View) {
    if let client = owner {
      client.childVisibilityChanged(child: child)
    }
  }

}

fileprivate func getBoundingSizeForVerticalStack(_ size1: IntSize,
                                                 _ size2: IntSize) -> IntSize {
  return IntSize(width: max(size1.width, size2.width),
                 height: size1.height + size2.height)
}

fileprivate func shouldShow(_ view: View?) -> Bool {
  if let v = view {
    return v.isVisible
  }
  return false
}

fileprivate func createButton(listener: ButtonListener, text: String) -> LabelButton {
  let button = LabelButton(listener: listener, text: text, context: TextContext.button)
  button.style = Button.Style.Button
  return button
}

fileprivate let buttonGroup = 9999