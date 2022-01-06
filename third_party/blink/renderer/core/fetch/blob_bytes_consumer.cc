// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/fetch/blob_bytes_consumer.h"

#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/fetch/form_data_bytes_consumer.h"
#include "third_party/blink/renderer/platform/blob/blob_data.h"
//#include "third_party/blink/renderer/platform/network/wrapped_data_pipe_getter.h"

namespace blink {

BlobBytesConsumer::BlobBytesConsumer(
    ExecutionContext* execution_context,
    scoped_refptr<BlobDataHandle> blob_data_handle)
    : execution_context_(execution_context),
      blob_data_handle_(std::move(blob_data_handle)) {}

BlobBytesConsumer::~BlobBytesConsumer() {
}

// BytesConsumer::Result BlobBytesConsumer::BeginRead(const char** buffer,
//                                                    size_t* available) {
//   if (!nested_consumer_) {
//     if (!blob_data_handle_)
//       return Result::kDone;

//     scoped_refptr<EncodedFormData> form_data = EncodedFormData::Create();
//     form_data->AppendDataPipe(base::MakeRefCounted<WrappedDataPipeGetter>(
//         blob_data_handle_->AsDataPipeGetter()));
//     nested_consumer_ = new FormDataBytesConsumer(
//         execution_context_, std::move(form_data));
//     if (client_)
//       nested_consumer_->SetClient(client_);
//     blob_data_handle_ = nullptr;
//     client_ = nullptr;
//   }
//   return nested_consumer_->BeginRead(buffer, available);
// }

BytesConsumer::Result BlobBytesConsumer::BeginRead(const char** buffer,
                                                   size_t* available) {
  // *buffer = nullptr;
  // *available = 0;

  // if (state_ == PublicState::kClosed) {
  //   // It's possible that |cancel| has been called before the first
  //   // |beginRead| call. That's why we need to check this condition
  //   // before checking |isClean()|.
  //   return Result::kDone;
  // }

  // if (IsClean()) {
  //   DCHECK(blob_url_.IsEmpty());
  //   blob_url_ =
  //       BlobURL::CreatePublicURL(GetExecutionContext()->GetSecurityOrigin());
  //   if (blob_url_.IsEmpty()) {
  //     GetError();
  //   } else {
  //     BlobRegistry::RegisterPublicBlobURL(
  //         GetExecutionContext()->GetMutableSecurityOrigin(), blob_url_,
  //         blob_data_handle_);

  //     // m_loader is non-null only in tests.
  //     if (!loader_)
  //       loader_ = CreateLoader();

  //     ResourceRequest request(blob_url_);
  //     request.SetRequestContext(WebURLRequest::kRequestContextInternal);
  //     request.SetFetchRequestMode(
  //         network::mojom::FetchRequestMode::kSameOrigin);
  //     request.SetFetchCredentialsMode(
  //         network::mojom::FetchCredentialsMode::kOmit);
  //     request.SetUseStreamOnResponse(true);
  //     // We intentionally skip
  //     // 'setExternalRequestStateFromRequestorAddressSpace', as 'blob:'
  //     // can never be external.
  //     loader_->Start(request);
  //   }
  //   blob_data_handle_ = nullptr;
  // }
  // DCHECK_NE(state_, PublicState::kClosed);

  // if (state_ == PublicState::kErrored)
  //   return Result::kError;

  // if (!body_) {
  //   // The response has not arrived.
  //   return Result::kShouldWait;
  // }

  // auto result = body_->BeginRead(buffer, available);
  // switch (result) {
  //   case Result::kOk:
  //   case Result::kShouldWait:
  //     break;
  //   case Result::kDone:
  //     has_seen_end_of_data_ = true;
  //     if (has_finished_loading_)
  //       Close();
  //     return state_ == PublicState::kClosed ? Result::kDone
  //                                           : Result::kShouldWait;
  //   case Result::kError:
  //     GetError();
  //     break;
  // }
  //return result;
  DCHECK(false);
  return Result::kDone;
}

BytesConsumer::Result BlobBytesConsumer::EndRead(size_t read) {
  DCHECK(nested_consumer_);
  return nested_consumer_->EndRead(read);
}

scoped_refptr<BlobDataHandle> BlobBytesConsumer::DrainAsBlobDataHandle(
    BlobSizePolicy policy) {
  if (!blob_data_handle_)
    return nullptr;
  if (policy == BlobSizePolicy::kDisallowBlobWithInvalidSize &&
      blob_data_handle_->size() == UINT64_MAX)
    return nullptr;
  return std::move(blob_data_handle_);
}

scoped_refptr<EncodedFormData> BlobBytesConsumer::DrainAsFormData() {
  scoped_refptr<BlobDataHandle> handle =
      DrainAsBlobDataHandle(BlobSizePolicy::kAllowBlobWithInvalidSize);
  if (!handle)
    return nullptr;
  scoped_refptr<EncodedFormData> form_data = EncodedFormData::Create();
  form_data->AppendBlob(handle->Uuid(), handle);
  return form_data;
}

void BlobBytesConsumer::SetClient(BytesConsumer::Client* client) {
  DCHECK(!client_);
  DCHECK(client);
  if (nested_consumer_)
    nested_consumer_->SetClient(client);
  else
    client_ = client;
}

void BlobBytesConsumer::ClearClient() {
  client_ = nullptr;
  if (nested_consumer_)
    nested_consumer_->ClearClient();
}

void BlobBytesConsumer::Cancel() {
  if (nested_consumer_)
    nested_consumer_->Cancel();
  blob_data_handle_ = nullptr;
  client_ = nullptr;
}

BytesConsumer::Error BlobBytesConsumer::GetError() const {
  DCHECK(nested_consumer_);
  return nested_consumer_->GetError();
}

BytesConsumer::PublicState BlobBytesConsumer::GetPublicState() const {
  if (!nested_consumer_) {
    return blob_data_handle_ ? PublicState::kReadableOrWaiting
                             : PublicState::kClosed;
  }
  return nested_consumer_->GetPublicState();
}

void BlobBytesConsumer::Trace(blink::Visitor* visitor) {
  visitor->Trace(execution_context_);
  visitor->Trace(nested_consumer_);
  visitor->Trace(client_);
  BytesConsumer::Trace(visitor);
}

}  // namespace blink
