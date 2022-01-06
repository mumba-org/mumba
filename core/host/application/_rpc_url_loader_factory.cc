// Copyright (c) 2020 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "core/host/rpc/rpc_url_loader_factory.h"

#include "base/bind.h"
#include "base/debug/crash_logging.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
#include "base/memory/ref_counted_memory.h"
#include "base/single_thread_task_runner.h"
#include "base/strings/string_piece.h"
#include "base/task_scheduler/post_task.h"
#include "core/host/application/application_contents.h"
#include "core/host/application/entry_node.h"
#include "core/host/application/application_window_host.h"
#include "core/host/application/resource_context_impl.h"
#include "core/host/application/network_error_url_loader.h"
#include "core/host/application/url_data_manager_backend.h"
#include "core/host/application/url_data_source.h"

namespace host {

namespace {

base::LazyInstance<std::map<GlobalFrameRoutingId,
                            std::unique_ptr<RpcURLLoaderFactory>>>::Leaky
    g_app_url_loader_factories = LAZY_INSTANCE_INITIALIZER;

constexpr size_t kMaxChunkSize = 512 * 1024;

}

RpcURLLoaderFactory::RpcURLLoaderFactory(
  ApplicationWindowHost* application_window_host,
  const std::string& scheme,
  base::flat_set<std::string> allowed_hosts)
    : ApplicationContentsObserver(ApplicationContents::FromApplicationWindowHost(application_window_host)),
      application_window_host_(application_window_host),
      scheme_(scheme),
      allowed_hosts_(std::move(allowed_hosts)),
      headers_sent_(false) {

}

RpcURLLoaderFactory::~RpcURLLoaderFactory(){}

network::mojom::URLLoaderFactoryPtr RpcURLLoaderFactory::CreateBinding() {
  network::mojom::URLLoaderFactoryPtr factory;
  loader_factory_bindings_.AddBinding(this, mojo::MakeRequest(&factory));
  return factory;
}

// network::mojom::URLLoaderFactory implementation:
void RpcURLLoaderFactory::CreateLoaderAndStart(
  network::mojom::URLLoaderRequest loader,
  int32_t routing_id,
  int32_t request_id,
  uint32_t options,
  const network::ResourceRequest& request,
  network::mojom::URLLoaderClientPtr client,
  const net::MutableNetworkTrafficAnnotationTag&
      traffic_annotation) {
  //DCHECK_CURRENTLY_ON(HostThread::UI);
  
  impl_task_runner_ = base::ThreadTaskRunnerHandle::Get();
  
  if (request.url.scheme() != scheme_) {
    DLOG(ERROR) << "bad scheme: '" << request.url.scheme() << "'. scheme '" << scheme_ << "' expected.";
    //ReceivedBadMessage(application_window_host_->GetProcess(),
    //                   bad_message::WEBUI_BAD_SCHEME_ACCESS);
    client->OnComplete(network::URLLoaderCompletionStatus(net::ERR_FAILED));
    return;
  }

  if (!allowed_hosts_.empty() &&
      (!request.url.has_host() ||
       allowed_hosts_.find(request.url.host()) == allowed_hosts_.end())) {
    // Temporary reporting the bad App host for for http://crbug.com/837328.
    static auto* crash_key = base::debug::AllocateCrashKeyString(
        "app_url", base::debug::CrashKeySize::Size64);
    base::debug::SetCrashKeyString(crash_key, request.url.spec());

    DLOG(ERROR) << "bad host: \"" << request.url.host() << '"';
    //ReceivedBadMessage(render_frame_host_->GetProcess(),
    //                   bad_message::WEBUI_BAD_HOST_ACCESS);
    client->OnComplete(network::URLLoaderCompletionStatus(net::ERR_FAILED));
    return;
  }

  //HostThread::PostTask(
  //    HostThread::IO, FROM_HERE,
  //    base::BindOnce(
  //        &RpcURLLoaderFactory::StartURLLoader, 
  //        base::Unretained(this), 
  //        request, 
  //        application_window_host_->GetProcess()->GetID(), 
  //        application_window_host_->GetRoutingID(),
  //        client.PassInterface(),
  //        application_window_host_->application_contents()));
  //        //GetStoragePartition()->application_contents()->GetResourceContext()));

  StartURLLoader(
          request, 
          application_window_host_->GetProcess()->GetID(), 
          application_window_host_->GetRoutingID(),
          client.PassInterface(),
          application_window_host_->application_contents());
}

void RpcURLLoaderFactory::Clone(network::mojom::URLLoaderFactoryRequest request) {
  loader_factory_bindings_.AddBinding(this, std::move(request));
}

// WebContentsObserver implementation:
void RpcURLLoaderFactory::ApplicationWindowDeleted(ApplicationWindowHost* application_window_host) {
  //DLOG(INFO) << "RpcURLLoaderFactory::ApplicationWindowDeleted: application_window_host = " << application_window_host;
  //HostThread::PostTask(
  //  HostThread::IO, 
  //impl_task_runner_->PostTask(
  //  FROM_HERE, 
  //  base::BindOnce(&RpcURLLoaderFactory::ApplicationWindowDeletedOnIOThread, base::Unretained(this), base::Unretained(application_window_host)));
}

void RpcURLLoaderFactory::ApplicationWindowDeletedOnIOThread(ApplicationWindowHost* application_window_host) {
  if (application_window_host != application_window_host_)
    return;
  g_app_url_loader_factories.Get().erase(
      GlobalFrameRoutingId(application_window_host_->GetRoutingID(),
                           application_window_host_->GetProcess()->GetID()));
}

void RpcURLLoaderFactory::CallOnError(int error_code) {
  CompleteRequest(error_code, 0, 0);
}

void RpcURLLoaderFactory::CompleteRequest(int code, size_t data_length, size_t body_length) {
  network::URLLoaderCompletionStatus status(code);
  status.encoded_data_length = data_length;
  status.encoded_body_length = body_length;
  client_->OnComplete(status);
}

void RpcURLLoaderFactory::DataAvailable(
  network::mojom::URLLoaderClientPtrInfo client_info,
  const GURL& url,
  const std::string& path,
  scoped_refptr<network::ResourceResponse> headers,
  const ui::TemplateReplacements* replacements,
  bool gzipped,
  scoped_refptr<URLDataSource> source,
  int call_id,
  scoped_refptr<base::RefCountedMemory> contents,
  bool should_complete) {
  //if (!client_) {
  //client_.reset();
  client_.Bind(std::move(client_info));
  //}
  //base::CreateSequencedTaskRunnerWithTraits(
  //     {base::TaskPriority::USER_BLOCKING, base::MayBlock(),
  //      base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN})
  //     ->PostTask(FROM_HERE,
  //                base::BindOnce(&RpcURLLoaderFactory::ReadDataImpl, 
  //                               base::Unretained(this),
  //                               path,
  //                               headers, 
  //                               replacements, 
  //                               gzipped,
  //                               source, 
  //                               bytes));
  
  ReadDataImpl(call_id, url, path, headers, replacements, gzipped, source, std::move(contents), should_complete);
}

void RpcURLLoaderFactory::ReadData(
  const GURL& url,
  const std::string& path,
  scoped_refptr<network::ResourceResponse> headers,
  const ui::TemplateReplacements* replacements,
  bool gzipped,
  scoped_refptr<URLDataSource> source,
  int call_id,
  scoped_refptr<base::RefCountedMemory> contents,
  bool should_complete) {  
  //base::CreateSequencedTaskRunnerWithTraits(
  //     {base::TaskPriority::USER_BLOCKING, base::MayBlock(),
  //      base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN})
  //     ->PostTask(FROM_HERE,
  //                base::BindOnce(&RpcURLLoaderFactory::ReadDataImpl, 
  //                               base::Unretained(this),
  //                               path,
  //                               headers, 
  //                               replacements, 
  //                               gzipped,
  //                               source, 
  //                               bytes));
  ReadDataImpl(call_id, url, path, headers, replacements, gzipped, source, std::move(contents), should_complete);
}

MojoResult RpcURLLoaderFactory::BeginWrite(void** data,
                                           uint32_t* available) {
  MojoResult result = data_pipe_->producer_handle->BeginWriteData(
      data, available, MOJO_WRITE_DATA_FLAG_NONE);
  if (result == MOJO_RESULT_OK)
    *available = std::min(*available, static_cast<uint32_t>(kMaxChunkSize));
  //else if (result == MOJO_RESULT_SHOULD_WAIT)
  //  handle_watcher_.ArmOrNotify();
  return result;
}

void RpcURLLoaderFactory::ReadDataImpl(
                   int call_id,
                   const GURL& url,
                   const std::string& path,
                   scoped_refptr<network::ResourceResponse> headers,
                   const ui::TemplateReplacements* replacements,
                   bool gzipped,
                   scoped_refptr<URLDataSource> source,
                   scoped_refptr<base::RefCountedMemory> contents,
                   bool should_complete) {
  DLOG(INFO) << "RpcURLLoaderFactory::ReadDataImpl: should_complete? " << should_complete << " contents ? " << contents;
  bool first_time = !headers_sent_;

  if (!headers_sent_) {
    std::string content_size_string = contents == nullptr ? "0" : base::IntToString(contents->size());
    headers->head.headers->AddHeader("Content-Length: " + content_size_string);
    client_->OnReceiveResponse(headers->head, nullptr);
    headers_sent_ = true;
  }

  // we should complete, and we dont have any bytes.. complete and exit
  if (should_complete && !contents) {
    DLOG(INFO) << "RpcURLLoaderFactory::ReadDataImpl: should_complete = true and contents = null. completing ...";
    network::URLLoaderCompletionStatus status(net::OK);
    // TODO: we need a aggregatory count for the bytes sent
    status.encoded_data_length = 0;
    status.encoded_body_length = 0;
    client_->OnComplete(status);
    headers_sent_ = false;
    return;
  }
 
  if (!contents) {
    DLOG(INFO) << "RpcURLLoaderFactory::ReadDataImpl: contents = null. completing with error..";
    CallOnError(net::ERR_FAILED);
    headers_sent_ = false;
    return;
  }

  // Treats empty gzipped data as unzipped.
  //if (!contents->size()) {
  //  gzipped = false;
  //}

  // if (replacements) {
  //   std::string temp_string;
  //   // We won't know the the final output size ahead of time, so we have to
  //   // use an intermediate string.
  //   base::StringPiece source;
  //   std::string temp_str;
  //   if (gzipped) {
  //     temp_str.resize(compression::GetUncompressedSize(input));
  //     source.set(temp_str.c_str(), temp_str.size());
  //     CHECK(compression::GzipUncompress(input, source));
  //     gzipped = false;
  //   } else {
  //     source = input;
  //   }
  //   temp_str = ui::ReplaceTemplateExpressions(source, *replacements);
  //   bytes = base::RefCountedString::TakeString(&temp_str);
  //   input.set(reinterpret_cast<const char*>(bytes->front()), bytes->size());
  // }

  //if (!data_pipe_) {
    DLOG(INFO) << "RpcURLLoaderFactory::ReadDataImpl: creating data pipe";
    data_pipe_ = std::make_unique<mojo::DataPipe>(512 * 1024);
  //}

  
  if (!contents) {
    DLOG(INFO) << "ReadDataImpl: no data. calling error";    
    CallOnError(net::ERR_FAILED);
    headers_sent_ = false;
    //data_pipe_.reset();
    return;   
  }

  uint32_t input_size = 0;
  const uint8_t* input_buffer = contents->front();
  while (input_size < contents->size()) { // begin write loop  
    void* output_buffer = nullptr;
    size_t rest = contents->size() - input_size;
    uint32_t allocated_bytes = std::min(kMaxChunkSize, rest);
    MojoResult result = BeginWrite(&output_buffer, &allocated_bytes);
    if (result != MOJO_RESULT_OK) {
      DLOG(INFO) << "RpcURLLoaderFactory::ReadDataImpl: data_pipe_->producer_handle->BeginWriteData() error. allocated_bytes = " << allocated_bytes << " input_size = " << input_size << " contents->size() = " << contents->size();
      network::URLLoaderCompletionStatus status(net::ERR_FAILED);
      client_->OnComplete(status);
      headers_sent_ = false;
      //data_pipe_.reset();
      return;
    }

    //CHECK_GE(allocated_bytes, input_size);
    if (!output_buffer) {
      DLOG(INFO) << "ReadDataImpl: buffer is NULL. calling error";
      network::URLLoaderCompletionStatus status(net::ERR_FAILED);
      client_->OnComplete(status);
      headers_sent_ = false;
      //data_pipe_.reset();
      return; 
    }

    //DLOG(INFO) << "ReadDataImpl: allocated_bytes = " << allocated_bytes << " input_size = " << input_size << " contents->size() = " << contents->size() << " output_buffer = " << output_buffer << " input_buffer = " << input_buffer;
    memcpy(output_buffer, input_buffer, allocated_bytes);
    result = data_pipe_->producer_handle->EndWriteData(allocated_bytes);
    if (result != MOJO_RESULT_OK) {
      DLOG(INFO) << "ReadDataImpl: EndWriteData() returned error. calling error";
      network::URLLoaderCompletionStatus status(net::ERR_FAILED);
      client_->OnComplete(status);
      headers_sent_ = false;
      //data_pipe_.reset();
      return;
    }
    input_size += allocated_bytes;
    input_buffer += allocated_bytes;
    
  } // end write loop

  //if (first_time) {
    client_->OnStartLoadingResponseBody(std::move(data_pipe_->consumer_handle));
  //}

  // here, we do have the bytes, and also want to complete, so call it here
  DLOG(INFO) << "ReadDataImpl: should_complete ? " << should_complete;
  if (should_complete) {
    DLOG(INFO) << "ReadDataImpl: should_complete = true. completing with OK";
    network::URLLoaderCompletionStatus status(net::OK);
    status.encoded_data_length = input_size;
    status.encoded_body_length = input_size;
    client_->OnComplete(status);
    headers_sent_ = false;
    //data_pipe_.reset();
    return;
  }

  // NOTE: added here

  auto data_available_callback =
      base::Bind(&RpcURLLoaderFactory::ReadData, 
                 base::Unretained(this),
                 url, path, headers, nullptr, false,
                 source);
  
  scoped_refptr<base::SingleThreadTaskRunner> target_runner =
      source->TaskRunnerForRequestPath(url.scheme(), path);
  if (!target_runner) {
    source->OnDataSent(call_id, input_size, std::move(data_available_callback));
    return;
  }

  // The DataSource wants StartDataRequest to be called on a specific
  // thread, usually the UI thread, for this path.
  target_runner->PostTask(
      FROM_HERE,
      base::BindOnce(&URLDataSource::OnDataSent,
                      source, call_id, input_size, base::Passed(std::move(data_available_callback))));
  // NOTE: commented here for tests.. but we need this.. uncomment later
}


void RpcURLLoaderFactory::StartURLLoader(
  const network::ResourceRequest& request,
  int32_t process_id, 
  int32_t routing_id,
  network::mojom::URLLoaderClientPtrInfo client_info,
  ApplicationContents* app_contents) {
  
  // NOTE: this duplicates code in URLDataManagerBackend::StartRequest.
  if (!URLDataManagerBackend::CheckURLIsValid(request.url)) {
    DLOG(ERROR) << "URL " << request.url << " is declared invalid";
    CallOnError(net::ERR_INVALID_URL);
    return;
  }

  ResourceContext* resource_context = app_contents->GetResourceContext();

  URLDataManagerBackend* data_manager = GetURLDataManagerForResourceContext(resource_context);
  URLDataSource* source = data_manager->GetDataSourceFromURL(request.url);
  if (!source) {
    DLOG(ERROR) << "No URLDataSource found for " << request.url;
    CallOnError(net::ERR_INVALID_URL);
    return;
  }

  //if (!source->source()->ShouldServiceRequest(request.url, resource_context,
  //                                            -1)) {
  //  DLOG(ERROR) << "source()->ShouldServiceRequest() = false for " << request.url;
  //  CallOnError(std::move(client_info), net::ERR_INVALID_URL);
  //  return;
  //}

  std::string path;
  URLDataManagerBackend::URLToRequestPath(request.url, &path);

  std::string origin_header;
  request.headers.GetHeader(net::HttpRequestHeaders::kOrigin, &origin_header);

  scoped_refptr<net::HttpResponseHeaders> headers =
      source->GetHeaders(request.url.scheme(), path, origin_header);

  scoped_refptr<network::ResourceResponse> resource_response(
      new network::ResourceResponse);
  resource_response->head.headers = headers;
  resource_response->head.mime_type = source->GetMimeType(request.url.scheme(), path);
  // TODO: fill all the time related field i.e. request_time response_time
  // request_start response_start

  ResourceRequestInfo::ApplicationContentsGetter wc_getter =
      base::Bind(ApplicationContents::FromID, process_id, routing_id);

  bool gzipped = source->IsGzipped(request.url.scheme(), path);
  const ui::TemplateReplacements* replacements = nullptr;
  if (source->GetMimeType(request.url.scheme(), path) == "text/html")
    replacements = source->GetReplacements();

  // To keep the same behavior as the old WebUI code, we call the source to get
  // the value for |gzipped| and |replacements| on the IO thread. Since
  // |replacements| is owned by |source| keep a reference to it in the callback.
  auto data_available_callback =
      base::Bind(&RpcURLLoaderFactory::DataAvailable, 
                 base::Unretained(this),
                 base::Passed(std::move(client_info)),
                 request.url,
                 path, 
                 resource_response, 
                 replacements, 
                 gzipped,
                 base::RetainedRef(source));

  // TODO(jam): once we only have this code path for WebUI, and not the
  // URLLRequestJob one, then we should switch data sources to run on the UI
  // thread by default.
  scoped_refptr<base::SingleThreadTaskRunner> target_runner =
      source->TaskRunnerForRequestPath(request.url.scheme(), path);
  if (!target_runner) {
    source->StartDataRequest(request.url, path, std::move(wc_getter),
                             std::move(data_available_callback));
    return;
  }

  // The DataSource wants StartDataRequest to be called on a specific
  // thread, usually the UI thread, for this path.
  target_runner->PostTask(
      FROM_HERE,
      base::BindOnce(&URLDataSource::StartDataRequest,
                     base::Unretained(source), request.url, path,
                     std::move(wc_getter), std::move(data_available_callback)));
}

std::unique_ptr<network::mojom::URLLoaderFactory> CreateAppURLLoader(
  ApplicationWindowHost* application_window_host,
  const std::string& scheme,
  base::flat_set<std::string> allowed_hosts) {
  return std::make_unique<RpcURLLoaderFactory>(
    application_window_host, 
    scheme,
    std::move(allowed_hosts));
}

network::mojom::URLLoaderFactoryPtr CreateAppURLLoaderBinding(
  ApplicationWindowHost* application_window_host,
  const std::string& scheme) {
  //DCHECK(base::ThreadTaskRunnerHandle::Get() == g_app_url_loader_factories.Get()[routing_id]->impl_task_runner());
  DCHECK(HostThread::CurrentlyOn(HostThread::IO));
  
  GlobalFrameRoutingId routing_id(application_window_host->GetRoutingID(),
                                  application_window_host->GetProcess()->GetID());
  if (g_app_url_loader_factories.Get().find(routing_id) ==
          g_app_url_loader_factories.Get().end() ||
      g_app_url_loader_factories.Get()[routing_id]->scheme() != scheme) {
    g_app_url_loader_factories.Get()[routing_id] =
        std::make_unique<RpcURLLoaderFactory>(application_window_host, scheme,
                                                base::flat_set<std::string>());
  }
  return g_app_url_loader_factories.Get()[routing_id]->CreateBinding();
}

}