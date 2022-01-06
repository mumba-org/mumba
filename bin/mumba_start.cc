#include "base/command_line.h"
#include "base/strings/string_number_conversions.h"
#include "base/at_exit.h"
#include "rpc/grpc.h"
#include "rpc/byte_buffer.h"
#include "rpc/byte_buffer_reader.h"
#include "mumba/app/resources/grit/content_resources.h"
#include "ui/base/resource/resource_bundle.h"
#include "third_party/protobuf/src/google/protobuf/compiler/parser.h"
#include "third_party/protobuf/src/google/protobuf/io/tokenizer.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl.h"
#include "third_party/protobuf/src/google/protobuf/stubs/strutil.h"
#include "third_party/protobuf/src/google/protobuf/io/zero_copy_stream_impl_lite.h"
#include "third_party/protobuf/src/google/protobuf/arena.h"
#include "third_party/protobuf/src/google/protobuf/arenastring.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_table_driven.h"
#include "third_party/protobuf/src/google/protobuf/generated_message_util.h"
#include "third_party/protobuf/src/google/protobuf/inlined_string_field.h"
#include "third_party/protobuf/src/google/protobuf/metadata.h"
#include "third_party/protobuf/src/google/protobuf/message.h"
#include "third_party/protobuf/src/google/protobuf/dynamic_message.h"
#include "third_party/protobuf/src/google/protobuf/text_format.h"

void* tag(intptr_t i) { return (void*)i; } 

gpr_timespec grpc_timeout_milliseconds_to_deadline(int64_t time_ms) {
   return gpr_time_add(
       gpr_now(GPR_CLOCK_MONOTONIC),
       gpr_time_from_micros((int64_t)1e3 * time_ms,
                            GPR_TIMESPAN));
}

static gpr_timespec ms_from_now(int ms) {
  return grpc_timeout_milliseconds_to_deadline(ms);
}

static void drain_cq(grpc_completion_queue* cq) {
   grpc_event ev;
   do {
     ev = grpc_completion_queue_pluck(cq, tag(1), ms_from_now(1000), nullptr);
   } while (ev.type != GRPC_QUEUE_SHUTDOWN);
}

class SingleFileErrorCollector : public google::protobuf::io::ErrorCollector {
 public:
  SingleFileErrorCollector(const std::string& filename)
    : filename_(filename),
      had_errors_(false) {}
  ~SingleFileErrorCollector() {}

  bool had_errors() { return had_errors_; }

  // implements ErrorCollector ---------------------------------------
  void AddError(int line, int column, const std::string& message) override {
    had_errors_ = true;
    printf("protobuf error %d:%d: %s\n", line, column, message.c_str());
  }

 private:
  std::string filename_;
  bool had_errors_;
};

bool LoadProtobufFromBundle(int id, std::string* out) {
  base::FilePath dir;
  base::GetCurrentDirectory(&dir);
  base::FilePath pak = dir.AppendASCII("gen/mumba/app/resources/content_resources_100_percent.pak");
  ui::ResourceBundle::InitSharedInstanceWithPakPath(pak);
  ui::ResourceBundle& bundle = ui::ResourceBundle::GetSharedInstance();
  base::StringPiece contents = bundle.GetRawDataResource(id);
  if (contents.empty()) {
    return false;
  }
  base::internal::CopyToString(contents, out);
  return true;
}

const google::protobuf::FileDescriptor* BuildProto(google::protobuf::DescriptorPool& pool, const std::string& data) {
  google::protobuf::io::ArrayInputStream input(data.data(), data.size());
  SingleFileErrorCollector file_error_collector("_");
  google::protobuf::io::Tokenizer tokenizer(&input, &file_error_collector);
  google::protobuf::compiler::Parser parser;
 
  google::protobuf::FileDescriptorProto file_proto;
  file_proto.set_name("mumba"); 
  if (!parser.Parse(&tokenizer, &file_proto)) {
    return nullptr;
  }
  return pool.BuildFile(file_proto);
}

const google::protobuf::Descriptor* GetMessageDescriptorNamed(const google::protobuf::FileDescriptor* descr, const std::string& name) {
  const google::protobuf::Descriptor* result = nullptr;
  for (int i = 0; i < descr->message_type_count(); i++) {
    const google::protobuf::Descriptor* current = descr->message_type(i);
    if (current->name() == name) {
      result = current;
      break;
    }
  }
  return result;
}

bool GetOutputBuffer(grpc_byte_buffer* buffer, std::string* out) {
  grpc_byte_buffer_reader reader;  
  grpc_byte_buffer_reader_init(&reader, buffer);
  grpc_slice resp_slice = grpc_byte_buffer_reader_readall(&reader);
  grpc_byte_buffer_reader_destroy(&reader);

  size_t bytes_readed = GRPC_SLICE_LENGTH(resp_slice);

  char* char_buffer = grpc_slice_to_c_string(resp_slice);
  out->assign(char_buffer, bytes_readed);
  
  grpc_slice_unref(resp_slice);

  if (char_buffer) {
    gpr_free(char_buffer);
  }

  return true;
}

void ProcessResponse(const google::protobuf::Descriptor* output_descr, grpc_byte_buffer* out_buffer) {
  std::string encoded_data;
  std::string text_output;
  google::protobuf::DynamicMessageFactory factory;
  if (out_buffer == nullptr) {
    DLOG(INFO) << "ProcessResponse: output buffer is null";
    return;
  }
  if (!GetOutputBuffer(out_buffer, &encoded_data)) {
    DLOG(INFO) << "ProcessResponse: failed to copy output buffer";
    return;
  }

  const google::protobuf::Message* message = factory.GetPrototype(output_descr);
  if (!message) {
    DLOG(INFO) << "ProcessResponse: failed to create message from descriptor";
    return;
  }
  google::protobuf::Message* new_message = message->New();
  if (!new_message->ParseFromString(encoded_data)) {
    DLOG(INFO) << "ProcessResponse: failed to parse input data into the output message";
    return;
  }
  google::protobuf::TextFormat::PrintToString(*new_message, &text_output);
  printf("%s", text_output.c_str());
}

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  google::protobuf::DescriptorPool pool;
  grpc_call_error rc = GRPC_CALL_OK;
  grpc_metadata_array begin_metadata;
  grpc_metadata_array end_metadata;
  grpc_byte_buffer* input_buffer;
  grpc_byte_buffer* output_buffer;
  std::string port_string("27761");
  std::string host_string("127.0.0.1");
  int int_port = 27761;

  base::CommandLine::Init(argc, argv);

  std::string mumba_proto;
  if (!LoadProtobufFromBundle(IDR_MUMBA_PROTO, &mumba_proto)) {
    printf("service list: failed to load protobuf source from package bundle\n");
    return 1;
  }

  const google::protobuf::FileDescriptor* file_descr = BuildProto(pool, mumba_proto); 
  if (file_descr == nullptr) {
    printf("service list: failed to build protobuf\n");
    return 1;
  }

  const google::protobuf::Descriptor* output_descr = GetMessageDescriptorNamed(file_descr, "ReplyStatus");
  if (!output_descr) {
    printf("service list: failed to get the output protobuf descriptor\n");
    return 1;
  }

  base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();
  auto args = cmd->GetArgs();

  if (args.size() == 0) {
    printf("start: not enough args. needs service name\n");
    return 1;
  }

  if (cmd->HasSwitch("host")) {
    host_string = cmd->GetSwitchValueASCII("host");
  }

  if (cmd->HasSwitch("port")) {
    port_string = cmd->GetSwitchValueASCII("port");
    if (!base::StringToInt(port_string, &int_port)) {
      printf("application install: port parameter is not a integer\n");
      return 1;
    }
  }

  std::string full_address = host_string + ":" + port_string;

  grpc_metadata_array_init(&begin_metadata);
  grpc_metadata_array_init(&end_metadata);

  grpc_slice input_buffer_slice = grpc_slice_from_static_string(args[0].c_str());
  input_buffer = grpc_raw_byte_buffer_create(&input_buffer_slice, 1);

  grpc_metadata meta_c[2] = {{grpc_slice_from_static_string("key1"),
                              grpc_slice_from_static_string("val1"),
                              0,
                              {{NULL, NULL, NULL, NULL}}},
                             {grpc_slice_from_static_string("key2"),
                              grpc_slice_from_static_string("val2"),
                              0,
                              {{NULL, NULL, NULL, NULL}}}};
 

  grpc_init();

  grpc_channel* channel = grpc_insecure_channel_create(full_address.c_str(), nullptr, nullptr);
  if (!channel) {
    printf("channel creation error\n");
    return 1;
  }
 
  grpc_slice host = grpc_slice_from_static_string(full_address.c_str());
  grpc_slice method = grpc_slice_from_static_string("/mumba.Shell/StartService");

  grpc_completion_queue* completion_queue = grpc_completion_queue_create_for_pluck(nullptr);

  if (!completion_queue) {
    printf("completion queue creation error\n");
    return 1;
  }

  grpc_call* call = grpc_channel_create_call(
    channel, 
    nullptr, 
    GRPC_PROPAGATE_DEFAULTS,
    completion_queue, 
    method,
    &host, 
    gpr_inf_future(GPR_CLOCK_REALTIME), 
    nullptr);

  if (!call) {
    printf("call creation error\n");
    return 1;
  }

  grpc_status_code status;
  grpc_slice status_details;

  grpc_op ops[6];
  memset(ops, 0, sizeof(ops));
  ops[0].op = GRPC_OP_SEND_INITIAL_METADATA;
  ops[0].data.send_initial_metadata.count = 2;
  ops[0].data.send_initial_metadata.metadata = meta_c;
  ops[0].flags = 0;
  ops[0].reserved = NULL;

  ops[1].op = GRPC_OP_SEND_MESSAGE;
  ops[1].data.send_message.send_message = input_buffer;
  ops[1].flags = 0;
  ops[1].reserved = NULL;

  ops[2].op = GRPC_OP_SEND_CLOSE_FROM_CLIENT;
  ops[2].flags = 0;
  ops[2].reserved = NULL;

  ops[3].op = GRPC_OP_RECV_INITIAL_METADATA;
  ops[3].data.recv_initial_metadata.recv_initial_metadata = &begin_metadata;
  ops[3].flags = 0;
  ops[3].reserved = NULL;

  ops[4].op = GRPC_OP_RECV_MESSAGE;
  ops[4].data.recv_message.recv_message = &output_buffer;
  ops[4].flags = 0;
  ops[4].reserved = NULL;

  ops[5].op = GRPC_OP_RECV_STATUS_ON_CLIENT;
  ops[5].data.recv_status_on_client.trailing_metadata = &end_metadata;
  ops[5].data.recv_status_on_client.status = &status;
  ops[5].data.recv_status_on_client.status_details = &status_details;
  ops[5].flags = 0;
  ops[5].reserved = NULL;

  rc = grpc_call_start_batch(call, ops, sizeof(ops) / sizeof(ops[0]), tag(1), nullptr);
  
  if (rc != GRPC_CALL_OK) {
    printf("error in grpc_call_start_batch\n");
    return 1;
  }

  grpc_event event = grpc_completion_queue_pluck(completion_queue, tag(1), grpc_timeout_milliseconds_to_deadline(3000), nullptr);

  switch (event.type) {
    case GRPC_OP_COMPLETE:
      ProcessResponse(output_descr, output_buffer);
      break;
    case GRPC_QUEUE_SHUTDOWN:
      break;
    case GRPC_QUEUE_TIMEOUT:
      printf("event: timeout\n");
      break;
  }

  grpc_completion_queue_shutdown(completion_queue);

  //drain_cq(completion_queue);
  
  grpc_completion_queue_destroy(completion_queue);

  grpc_slice_unref(host);
  grpc_slice_unref(method);

  grpc_slice_unref(input_buffer_slice);

  grpc_metadata_array_destroy(&begin_metadata);
  grpc_metadata_array_destroy(&end_metadata);

  grpc_byte_buffer_destroy(input_buffer);
  grpc_byte_buffer_destroy(output_buffer);
  
  grpc_channel_destroy(channel);
  grpc_shutdown();

  printf("exit with no error\n");

  return 0;
}