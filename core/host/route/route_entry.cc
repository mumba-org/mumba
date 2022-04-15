// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/route/route_entry.h"

#include "base/base64.h"
#include "base/base64url.h"
#include "base/strings/string_util.h"
#include "core/host/route/route_scheme.h"
#include "core/host/rpc/server/host_rpc_service.h"
#include "core/host/share/share.h"

namespace host {

net::RpcMethodType GetRpcMethodTypeFromEntry(common::mojom::RouteEntryRPCMethodType type) {
  switch (type) {
    case common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_NORMAL:
      return net::RpcMethodType::kNORMAL;
    case common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_CLIENT_STREAM:
      return net::RpcMethodType::kCLIENT_STREAM;
    case common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_SERVER_STREAM:
      return net::RpcMethodType::kSERVER_STREAM;
    case common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_BIDI_STREAM:
      return net::RpcMethodType::kBIDI_STREAM; 
  }
  return net::RpcMethodType::kNORMAL;
}

common::mojom::RouteEntryRPCMethodType GetEntryFromRpcMethodType(net::RpcMethodType type) {
  switch (type) {
    case net::RpcMethodType::kNORMAL:
      return common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_NORMAL;
    case net::RpcMethodType::kCLIENT_STREAM:
      return common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_CLIENT_STREAM;
    case net::RpcMethodType::kSERVER_STREAM:
      return common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_SERVER_STREAM;
    case net::RpcMethodType::kBIDI_STREAM:
      return common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_BIDI_STREAM; 
  }
  return common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_NORMAL;
}

char RouteEntry::kClassName[] = "route";


GURL RouteEntry::ResolveRpcRoute(const GURL& input_url) const {
  std::string route_path;
  std::string route_scheme;
  std::string route_method;
  std::string route_query;
  route_scheme = parent()->name();
  std::string route_host = service()->host();
  // this works to define to listen on any device
  // but as a target is invalid
  if (route_host == "0.0.0.0") {
    route_host = "127.0.0.1";
  }
  
  switch (transport_type()) {
    case common::mojom::RouteEntryTransportType::kROUTE_ENTRY_TRANSPORT_IPC:
      route_scheme = "ipc";
      break;
    case common::mojom::RouteEntryTransportType::kROUTE_ENTRY_TRANSPORT_RPC:
      route_scheme = "rpc";
      break;
    case common::mojom::RouteEntryTransportType::kROUTE_ENTRY_TRANSPORT_HTTP:
      route_scheme = "http";
      break;
    default: 
      route_scheme = "rpc";
  }

  // switch (rpc_method_type()) {
  //   case common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_NORMAL:
  //     route_method = "FetchUnary";
  //     break;
  //   case common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_CLIENT_STREAM:
  //     route_method = "FetchClientStream";
  //     break;
  //   case common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_SERVER_STREAM:
  //     route_method = "FetchServerStream";
  //     break;
  //   case common::mojom::RouteEntryRPCMethodType::kRPC_METHOD_BIDI_STREAM:
  //     route_method = "FetchBidiStream";
  //     break;
  //   default:
  //     route_method = "FetchUnary";
  // }

  // std::string route_service = fullname();
  // auto dot_offset = route_service.find(".");
  // if (dot_offset != std::string::npos) {
  //   route_service = route_service.substr(dot_offset + 1);
  //   auto next_dot = route_service.find(".");
  //   if (next_dot != std::string::npos) {
  //     route_service = route_service.substr(0, next_dot);
  //   }
  // }
  //std::string route_service = "FetchService";
  
  //route_path = route_collection + "/" + route_service + "/" + route_method;
  base::ReplaceChars(fullname(), ".", "/", &route_path);
  std::string route_string;
  route_string = route_scheme + "://" + route_host + ":" + base::NumberToString(service()->port()) + "/" + route_path;
  base::TimeTicks now = base::TimeTicks::Now();

  std::string encoded_url;
  base::Base64UrlEncode(input_url.spec(), base::Base64UrlEncodePolicy::OMIT_PADDING, &encoded_url);

  if (is_rpc_method()){
    route_query = input_url.query();
  } else {
    if (!input_url.query().empty()) {
      std::string encoded_route_params;
      base::Base64UrlEncode(input_url.query(), base::Base64UrlEncodePolicy::OMIT_PADDING, &encoded_route_params);
      route_query = "started_time=" + base::IntToString(now.ToInternalValue()) + "&content_type=text/plain&url=" + encoded_url + "&size=" + base::IntToString(encoded_route_params.size()) + "&data=" + encoded_route_params;
    } else {
      route_query = "started_time=" + base::IntToString(now.ToInternalValue()) + "&content_type=text/plain&url=" + encoded_url + "&size=0&data=0";
    }
  }

  if (!route_query.empty()) {
    route_string += "?" + route_query;
  }
  return GURL(route_string);
}

scoped_refptr<net::IOBufferWithSize> RouteEntry::Serialize() const {
  // FIXME: implement
  return scoped_refptr<net::IOBufferWithSize>();
}

void RouteEntry::OnDHTAnnounceReply(Share* share, int peers) {

}

void RouteEntry::OnShareMetadataReceived(Share* share) {

}

void RouteEntry::OnShareMetadataError(Share* share, int error) {

}

void RouteEntry::OnSharePieceReadError(Share* share, int piece_offset, int error) {

}

void RouteEntry::OnSharePiecePass(Share* share, int piece_offset) {

}

void RouteEntry::OnSharePieceFailed(Share* share, int piece_offset) {

}

void RouteEntry::OnSharePieceRead(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result) {

}

void RouteEntry::OnSharePieceWrite(Share* share, int piece, int64_t offset, int64_t size, int64_t block_size, int result) {

}

void RouteEntry::OnSharePieceFinished(Share* share, int piece_offset) {

}

void RouteEntry::OnSharePieceHashFailed(Share* share, int piece_offset) {

}

void RouteEntry::OnShareFileCompleted(Share* share, int piece_offset) {

}

void RouteEntry::OnShareFinished(Share* share) {

}

void RouteEntry::OnShareDownloading(Share* share) {

}

void RouteEntry::OnShareCheckingFiles(Share* share) {

}

void RouteEntry::OnShareDownloadingMetadata(Share* share) {

}

void RouteEntry::OnShareSeeding(Share* share) {

}

void RouteEntry::OnSharePaused(Share* share) {

}

void RouteEntry::OnShareResumed(Share* share) {

}

void RouteEntry::OnShareChecked(Share* share) {

}

void RouteEntry::OnShareDeleted(Share* share) {

}

void RouteEntry::OnShareDeletedError(Share* share, int error) {

}

void RouteEntry::OnShareFileRenamed(Share* share, int file_offset, const std::string& name) {
  
}

void RouteEntry::OnShareFileRenamedError(Share* share, int index, int error) {

}

}