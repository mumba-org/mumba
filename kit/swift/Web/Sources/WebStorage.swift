// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public enum WebStorageQuotaType : Int {
	case Temporary = 0
    case Persistent
}

public class WebStorageQuotaCallbacks {
	
	var reference: WebStorageQuotaCallbacksRef

	init(reference: WebStorageQuotaCallbacksRef) {
		self.reference = reference
	}
}

public class WebStorageNamespace {
	var reference: WebStorageNamespaceRef

	init(reference: WebStorageNamespaceRef) {
		self.reference = reference
	}
}