#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/strings/string_number_conversions.h"
#include "rpc/grpc.h"

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

// bool EncodeMessage(Protocol* proto, std::map<std::string, std::string> kvmap, std::string* out) {
//   ProtocolRegistry* protocol_registry = proto->registry();
//   google::protobuf::DescriptorPool* descriptor_pool = protocol_registry->descriptor_pool();
//   google::protobuf::DynamicMessageFactory factory(descriptor_pool);
//   const google::protobuf::Descriptor* message_descriptor = proto->GetMessageDescriptorNamed("EntryRequest");
//   if (!message_descriptor) {
//     DLOG(INFO) << "EncodeMessage(Request): failed while trying to find 'EntryRequest' in proto '" << proto->package() << "'";
//     return false;
//   }
//   const google::protobuf::Message* message = factory.GetPrototype(message_descriptor);
//   google::protobuf::Message* mutable_message = message->New();
//   const google::protobuf::Reflection* reflection = mutable_message->GetReflection();
//   // theres parameters in url? try to find fields with the same name
//   if (kvmap.size() > 0) {
//     for (auto it = kvmap.begin(); it != kvmap.end(); ++it) {
//       for (int i = 0; i < message_descriptor->field_count(); ++i) {
//         const google::protobuf::FieldDescriptor* field_descriptor = message_descriptor->field(i);
//         if (field_descriptor && field_descriptor->name() == it->first) {
//           switch (field_descriptor->cpp_type()) {
//             case google::protobuf::FieldDescriptor::CPPTYPE_STRING: {
//               reflection->SetString(mutable_message, field_descriptor, it->second);
//               break;
//             }
//             case google::protobuf::FieldDescriptor::CPPTYPE_INT32: {
//               int number;
//               DCHECK(base::StringToInt(it->second, &number));
//               reflection->SetInt32(mutable_message, field_descriptor, number);
//               break;
//             }
//             case google::protobuf::FieldDescriptor::CPPTYPE_INT64: {
//               int64_t number;
//               DCHECK(base::StringToInt64(it->second, &number));
//               reflection->SetInt64(mutable_message, field_descriptor, number);
//               break;
//             }
//             case google::protobuf::FieldDescriptor::CPPTYPE_UINT32: {
//               unsigned number;
//               DCHECK(base::StringToUint(it->second, &number));
//               reflection->SetUInt32(mutable_message, field_descriptor, number);
//               break;
//             }
//             case google::protobuf::FieldDescriptor::CPPTYPE_UINT64: {
//               uint64_t number;
//               DCHECK(base::StringToUint64(it->second, &number));
//               reflection->SetUInt64(mutable_message, field_descriptor, number);
//               break;
//             }
//             case google::protobuf::FieldDescriptor::CPPTYPE_DOUBLE: {
//               double number;
//               DCHECK(base::StringToDouble(it->second, &number));
//               reflection->SetDouble(mutable_message, field_descriptor, number);
//               break;
//             }
//             case google::protobuf::FieldDescriptor::CPPTYPE_FLOAT: {
//               double number;
//               DCHECK(base::StringToDouble(it->second, &number));
//               // static_cast will do ? cant remember that other unusual/fancy cast name for those situations
//               reflection->SetFloat(mutable_message, field_descriptor, static_cast<float>(number));
//               break;
//             }
//             case google::protobuf::FieldDescriptor::CPPTYPE_BOOL: {
//               bool boolean = it->second == "true" ? true : false;
//               reflection->SetBool(mutable_message, field_descriptor, boolean);
//               break;
//             }
//             case google::protobuf::FieldDescriptor::CPPTYPE_ENUM: {
//               int number;
//               DCHECK(base::StringToInt(it->second, &number));
//               const google::protobuf::EnumDescriptor* enum_descr = field_descriptor->enum_type();
//               const google::protobuf::EnumValueDescriptor* enum_value_descr =  enum_descr->FindValueByNumber(number);
//               if (enum_value_descr) {
//                 reflection->SetEnum(mutable_message, field_descriptor, enum_value_descr);
//               }
//               break;
//             }
//             // do nothing
//             case google::protobuf::FieldDescriptor::CPPTYPE_MESSAGE:
//             default:
//              break;
//           }
//           break;
//         }
//       }
//     }
//   }
  
//   if (!mutable_message->SerializeToString(out)) {
//     return false;
//   }
//   return true;
// }

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  grpc_call_error rc = GRPC_CALL_OK;
  grpc_metadata_array begin_metadata;
  grpc_metadata_array end_metadata;
  grpc_byte_buffer* input_buffer;
  grpc_byte_buffer* output_buffer;
  std::string port_string("27761");
  std::string host_string("127.0.0.1");
  int int_port = 27761;

  base::CommandLine::Init(argc, argv);

  base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();
  auto args = cmd->GetArgs();

  if (args.size() == 0) {
    printf("app_launch: not enough args. needs url\n");
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

  printf("application install: sending '%s'\n", args[0].c_str());
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
  grpc_slice method = grpc_slice_from_static_string("/mumba.Shell/LaunchApplication");

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
      printf("event: complete -> %d\n", event.success);
      break;
    case GRPC_QUEUE_SHUTDOWN:
      printf("event: shutdown\n");
      break;
    case GRPC_QUEUE_TIMEOUT:
      printf("event: timeout\n");
      break;
  }

  printf("leaving...\n");

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