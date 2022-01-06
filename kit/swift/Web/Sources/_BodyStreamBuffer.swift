// Copyright (c) 2021 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

import MumbaShims

public struct BodyStreamBuffer {

  public var stream: ReadableStream {

  }

  let reference: BodyStreamBufferRef
  
  init(reference: BodyStreamBufferRef) {
    self.reference = reference
  }

  // Callable only when neither locked nor disturbed.
  scoped_refptr<BlobDataHandle> DrainAsBlobDataHandle(
      BytesConsumer::BlobSizePolicy,
      ExceptionState&);
  scoped_refptr<EncodedFormData> DrainAsFormData(ExceptionState&);
  void StartLoading(FetchDataLoader*,
                    FetchDataLoader::Client* /* client */);
  void StartLoading(FetchDataLoader*,
                    FetchDataLoader::Client* /* client */,
                    ExceptionState&);
  void Tee(BodyStreamBuffer**, BodyStreamBuffer**, ExceptionState&);

  // UnderlyingSourceBase
  ScriptPromise pull(ScriptState*) override;
  ScriptPromise Cancel(ScriptState*, ScriptValue reason) override;

  base::Optional<bool> IsStreamReadable(ExceptionState&);
  base::Optional<bool> IsStreamClosed(ExceptionState&);
  base::Optional<bool> IsStreamErrored(ExceptionState&);
  base::Optional<bool> IsStreamLocked(ExceptionState&);
  bool IsStreamLockedForDCheck(ExceptionState&);
  base::Optional<bool> IsStreamDisturbed(ExceptionState&);
  bool IsStreamDisturbedForDCheck(ExceptionState&);
  void CloseAndLockAndDisturb(ExceptionState&);
  ScriptState* GetScriptState() { return script_state_.get(); }

  bool IsAborted();

}