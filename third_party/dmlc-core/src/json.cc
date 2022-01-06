// Copyright by Contributors

#include <dmlc/base.h>
#include <dmlc/json.h>
#include <dmlc/recordio.h>
#include <dmlc/logging.h>
#include <algorithm>

#undef LOG_INFO
#undef LOG_WARNING
#undef LOG_ERROR
#undef LOG_FATAL
#undef LOG_DFATAL

#include "base/memory/singleton.h"


namespace dmlc {
namespace json {

// static
AnyJSONManager* AnyJSONManager::GetInstance() {
  //return base::Singleton<AnyJSONManager>::get();
  static AnyJSONManager inst;
  return &inst;
}

// static
AnyJSONManager* AnyJSONManager::Global() {
  return AnyJSONManager::GetInstance();
}

}
}