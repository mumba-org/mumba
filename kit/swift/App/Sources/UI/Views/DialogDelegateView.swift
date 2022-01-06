// Copyright (c) 2019 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import Graphics

open class DialogDelegateView : View,
                                DialogDelegate {

  open override var widget: UIWidget? {
    //get {
      return super.widget
    //}
    //set {
    //  //print("warning: trying to set the UIWidget of DialogDelegateView, but the parent(View)\n dont allow it.. we need check the code logic and see if is supposed to be like this")
      //super.widget = newValue
    //}
  }

  public var contentsView: View? {
    return self
  }

  public var dialogClientView: DialogClientView? {
    return widget!.clientView!.asDialogClientView()
  }

  public var margins: IntInsets = IntInsets()
  private var observers: [DialogObserver] = []
  
  public override init() {
    super.init()
    //ownedByClient = true
  }

  public func deleteDelegate() {}

  open override func viewHierarchyChanged(details: ViewHierarchyChangedDetails) {
    //if details.isAdd && details.child === self && widget != nil {
    //  notifyAccessibilityEvent(Ax.Event.kAlert, true)
    //}
  }

  public func dialogModelChanged() {
    for observer in observers {
      observer.onDialogModelChanged()
    }
  }

  public func addObserver(_ observer: DialogObserver) {
    observers.append(observer)
  }
  
  public func removeObserver(_ observer: DialogObserver) {
    if let index = observers.firstIndex(where: { $0 === observer }) {
      observers.remove(at: index)
    }
  }

  public func updateButton(button: LabelButton, type: DialogButton) {
    button.text = getDialogButtonLabel(button: type)
    button.isEnabled = isDialogButtonEnabled(button: type)
    var isDefault = type.rawValue == defaultDialogButton
    if !PlatformStyle.dialogDefaultButtonCanBeCancel &&
        type == DialogButton.Cancel {
      isDefault = false
    }
    button.isDefault = isDefault
  }

}
