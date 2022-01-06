// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

public enum WebExceptionCode : Int {
  case None = 0
  case IndexSizeError
  case HierarchyRequestError
  case WrongDocumentError
  case InvalidCharacterError
  case NoModificationAllowedError
  case NotFoundError
  case NotSupportedError
  case InUseAttributeError // Historical. Only used in setAttributeNode etc which have been removed from the DOM specs.

  // Introduced in DOM Level 2:
  case InvalidStateError
  case SyntaxError
  case InvalidModificationError
  case NamespaceError
  case InvalidAccessError

  // Introduced in DOM Level 3:
  case TypeMismatchError // Historical; use TypeError instead

  // XMLHttpRequest extension:
  case SecurityError

  // Others introduced in HTML5:
  case NetworkError
  case AbortError
  case URLMismatchError
  case QuotaExceededError
  case TimeoutError
  case InvalidNodeTypeError
  case DataCloneError

  // These are IDB-specific.
  case UnknownError
  case ConstraintError
  case DataError
  case TransactionInactiveError
  case ReadOnlyError
  case VersionError

  // File system
  case NotReadableError
  case EncodingError
  case PathExistsError

  // SQL
  case SQLDatabaseError // Naming conflict with DatabaseError class.

  // Web Crypto
  case OperationError

  // Push API
  case PermissionDeniedError
}