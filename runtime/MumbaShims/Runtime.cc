// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "Runtime.h"

#include "Sandbox.h"
#include "runtime/MumbaShims/v8/v8_engine.h"
#include "base/i18n/icu_util.h"
#include "base/at_exit.h"
#include "base/allocator/allocator_extension.h"
#include "base/command_line.h"
#include "base/debug/debugger.h"
#include "base/lazy_instance.h"
#include "base/logging.h"
//#include "base/memory/scoped_ptr.h"
//#include "base/memory/scoped_vector.h"
#include "base/path_service.h"
#include "base/process/memory.h"
//#include "base/profiler/alternate_timer.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "base/threading/thread_local.h"
#include "base/message_loop/message_loop.h"
#include "base/threading/thread_task_runner_handle.h"
#include "core/shared/common/paths.h"
#include "core/shared/common/content_descriptors.h"
#if defined(USE_TCMALLOC)
#include "third_party/tcmalloc/chromium/src/gperftools/tcmalloc.h"
#include "third_party/tcmalloc/chromium/src/gperftools/malloc_extension.h"
#endif
#include "third_party/pdfium/public/fpdf_doc.h"
#include "third_party/pdfium/public/fpdf_edit.h"
#include "third_party/pdfium/public/fpdf_ext.h"
#include "third_party/pdfium/public/fpdf_flatten.h"
#include "third_party/pdfium/public/fpdf_ppo.h"
#include "third_party/pdfium/public/fpdf_save.h"
#include "third_party/pdfium/public/fpdf_searchex.h"
#include "third_party/pdfium/public/fpdf_sysfontinfo.h"
#include "third_party/pdfium/public/fpdf_transformpage.h"
#include "v8/include/libplatform/libplatform.h"

#if defined(OS_POSIX)
#include <signal.h>

#include "base/posix/global_descriptors.h"

#endif // OS_POSIX

#if defined(OS_LINUX)
#include <glib.h>
#include <glib-object.h>
//#include <gtk.h>
#endif

#if defined(ENABLE_WEBRTC)
#include "third_party/libjingle/overrides/init_webrtc.h"
#endif

//#include "WebPlatform.h"

//WebPlatform* g_webplatform = nullptr;

//#if defined(OS_LINUX)

void EnumFonts(struct _FPDF_SYSFONTINFO* sysfontinfo, void* mapper) {
  FPDF_AddInstalledFont(mapper, "Arial", FXFONT_DEFAULT_CHARSET);

  const FPDF_CharsetFontMap* font_map = FPDF_GetDefaultTTFMap();
  for (; font_map->charset != -1; ++font_map) {
    FPDF_AddInstalledFont(mapper, font_map->fontname, font_map->charset);
  }
}

void* MapFont(struct _FPDF_SYSFONTINFO*, int weight, int italic,
              int charset, int pitch_family, const char* face, int* exact) {
  
  // pp::BrowserFontDescription description;

  // // Pretend the system does not have the Symbol font to force a fallback to
  // // the built in Symbol font in CFX_FontMapper::FindSubstFont().
  // if (strcmp(face, "Symbol") == 0)
  //   return NULL;

  // if (pitch_family & FXFONT_FF_FIXEDPITCH) {
  //   description.set_family(PP_BROWSERFONT_TRUSTED_FAMILY_MONOSPACE);
  // } else if (pitch_family & FXFONT_FF_ROMAN) {
  //   description.set_family(PP_BROWSERFONT_TRUSTED_FAMILY_SERIF);
  // }

  // static const struct {
  //   const char* pdf_name;
  //   const char* face;
  //   bool bold;
  //   bool italic;
  // } kPdfFontSubstitutions[] = {
  //   {"Courier", "Courier New", false, false},
  //   {"Courier-Bold", "Courier New", true, false},
  //   {"Courier-BoldOblique", "Courier New", true, true},
  //   {"Courier-Oblique", "Courier New", false, true},
  //   {"Helvetica", "Arial", false, false},
  //   {"Helvetica-Bold", "Arial", true, false},
  //   {"Helvetica-BoldOblique", "Arial", true, true},
  //   {"Helvetica-Oblique", "Arial", false, true},
  //   {"Times-Roman", "Times New Roman", false, false},
  //   {"Times-Bold", "Times New Roman", true, false},
  //   {"Times-BoldItalic", "Times New Roman", true, true},
  //   {"Times-Italic", "Times New Roman", false, true},

  //   // MS P?(Mincho|Gothic) are the most notable fonts in Japanese PDF files
  //   // without embedding the glyphs. Sometimes the font names are encoded
  //   // in Japanese Windows's locale (CP932/Shift_JIS) without space.
  //   // Most Linux systems don't have the exact font, but for outsourcing
  //   // fontconfig to find substitutable font in the system, we pass ASCII
  //   // font names to it.
  //   {"MS-PGothic", "MS PGothic", false, false},
  //   {"MS-Gothic", "MS Gothic", false, false},
  //   {"MS-PMincho", "MS PMincho", false, false},
  //   {"MS-Mincho", "MS Mincho", false, false},
  //   // MS PGothic in Shift_JIS encoding.
  //   {"\x82\x6C\x82\x72\x82\x6F\x83\x53\x83\x56\x83\x62\x83\x4E",
  //    "MS PGothic", false, false},
  //   // MS Gothic in Shift_JIS encoding.
  //   {"\x82\x6C\x82\x72\x83\x53\x83\x56\x83\x62\x83\x4E",
  //    "MS Gothic", false, false},
  //   // MS PMincho in Shift_JIS encoding.
  //   {"\x82\x6C\x82\x72\x82\x6F\x96\xBE\x92\xA9",
  //    "MS PMincho", false, false},
  //   // MS Mincho in Shift_JIS encoding.
  //   {"\x82\x6C\x82\x72\x96\xBE\x92\xA9",
  //    "MS Mincho", false, false},
  // };

  // // Similar logic exists in PDFium's CFX_FolderFontInfo::FindFont().
  // if (charset == FXFONT_ANSI_HARSET && (pitch_family & FXFONT_FF_FIXEDPITCH))
  //   face = "Courier New";

  // // Map from the standard PDF fonts to TrueType font names.
  // size_t i;
  // for (i = 0; i < arraysize(kPdfFontSubstitutions); ++i) {
  //   if (strcmp(face, kPdfFontSubstitutions[i].pdf_name) == 0) {
  //     description.set_face(kPdfFontSubstitutions[i].face);
  //     if (kPdfFontSubstitutions[i].bold)
  //       description.set_weight(PP_BROWSERFONT_TRUSTED_WEIGHT_BOLD);
  //     if (kPdfFontSubstitutions[i].italic)
  //       description.set_italic(true);
  //     break;
  //   }
  // }

  // if (i == arraysize(kPdfFontSubstitutions)) {
  //   // Convert to UTF-8 before calling set_face().
  //   std::string face_utf8;
  //   if (base::IsStringUTF8(face)) {
  //     face_utf8 = face;
  //   } else {
  //     std::string encoding;
  //     if (base::DetectEncoding(face, &encoding)) {
  //       // ConvertToUtf8AndNormalize() clears |face_utf8| on failure.
  //       base::ConvertToUtf8AndNormalize(face, encoding, &face_utf8);
  //     }
  //   }

  //   if (face_utf8.empty())
  //     return nullptr;

  //   description.set_face(face_utf8);
  //   description.set_weight(WeightToBrowserFontTrustedWeight(weight));
  //   description.set_italic(italic > 0);
  // }

  // PP_Resource font_resource = pp::PDF::GetFontFileWithFallback(
  //     pp::InstanceHandle(g_last_instance_id),
  //     &description.pp_font_description(),
  //     static_cast<PP_PrivateFontCharset>(charset));
  // long res_id = font_resource;
  // return reinterpret_cast<void*>(res_id);
  return nullptr;
}

unsigned long GetFontData(struct _FPDF_SYSFONTINFO*, void* font_id,
                          unsigned int table, unsigned char* buffer,
                          unsigned long buf_size) {
  // uint32_t size = buf_size;
  // long res_id = reinterpret_cast<long>(font_id);
  // if (!pp::PDF::GetFontTableForPrivateFontFile(res_id, table, buffer, &size))
  //   return 0;
  // return size;
  return 0;
}

////void null_log_handler(const char *, GLogLevelFlags, const char *, void *) {
// //DLOG(INFO) << "null_log_handler";
//}

//GLogWriterOutput null_log_writer(GLogLevelFlags, const _GLogField *, unsigned long, void *) {
// //DLOG(INFO) << "null_log_writer";
// GLogWriterOutput output{};
// return output;
//}

void DeleteFont(struct _FPDF_SYSFONTINFO*, void* font_id) {
  //long res_id = reinterpret_cast<long>(font_id);
  //pp::Module::Get()->core()->ReleaseResource(res_id);
}


FPDF_SYSFONTINFO g_font_info = {
  1,
  0,
  EnumFonts,
  MapFont,
  0,
  GetFontData,
  0,
  0,
  DeleteFont
};

void Unsupported_Handler(UNSUPPORT_INFO*, int type) {
  //if (!g_engine_for_unsupported) {
  //  NOTREACHED();
  //  return;
  //}

  //g_engine_for_unsupported->UnsupportedFeature(type);
}

UNSUPPORT_INFO g_unsupported_info = {
  1,
  Unsupported_Handler
};

//#endif // OS_LINUX

class RuntimeMessageLoop : public base::MessageLoopForUI {//IO {
public: 
 RuntimeMessageLoop() {}
 ~RuntimeMessageLoop() override {}

 void BindToCurrentThread() {
   //base::MessageLoopForIO::BindToCurrentThread();
   base::MessageLoopForUI::BindToCurrentThread();
 }

};

struct RuntimeGlobals {
  std::unique_ptr<base::AtExitManager> at_exit;
  std::unique_ptr<RuntimeMessageLoop> message_loop;
  //std::unique_ptr<base::RunLoop> runloop;
};

RuntimeGlobals* g_runtime = {0};

#if defined(USE_TCMALLOC)
 // static
bool Runtime::GetAllocatorWasteSizeThunk(size_t* size) {
 size_t heap_size, allocated_bytes, unmapped_bytes;
 MallocExtension* ext = MallocExtension::instance();
 if (ext->GetNumericProperty("generic.heap_size", &heap_size) &&
  ext->GetNumericProperty("generic.current_allocated_bytes",
  &allocated_bytes) &&
  ext->GetNumericProperty("tcmalloc.pageheap_unmapped_bytes",
  &unmapped_bytes)) {
  *size = heap_size - allocated_bytes - unmapped_bytes;
  return true;
 }
 DCHECK(false);
 return false;
}

 // static
void Runtime::GetStatsThunk(char* buffer, int buffer_length) {
 MallocExtension::instance()->GetStats(buffer, buffer_length);
}

 // static
void Runtime::ReleaseFreeMemoryThunk() {
 MallocExtension::instance()->ReleaseFreeMemory();
}
#endif
  
//static  
bool Runtime::Init() {

  g_runtime = new RuntimeGlobals{};
  g_runtime->at_exit.reset(new base::AtExitManager());
  
  base::EnableTerminationOnOutOfMemory();

  base::CommandLine::Init(0, nullptr);

  // glib stuff
  //g_log_set_default_handler(null_log_handler,nullptr);
  //g_log_set_writer_func(null_log_writer, nullptr, nullptr);

//#if defined(USE_TCMALLOC)
  // For tcmalloc, we need to tell it to behave like new.
//  tc_set_new_mode(1);

//  base::allocator::SetGetAllocatorWasteSizeFunction(
//   GetAllocatorWasteSizeThunk);
//  base::allocator::SetGetStatsFunction(GetStatsThunk);
//  base::allocator::SetReleaseFreeMemoryFunction(ReleaseFreeMemoryThunk);
//#endif
  // TODO: we need to have the .dat file somewhere by default
  // so this will work
  //if(!base::i18n::InitializeICU())
  //  return false;
  common::RegisterPathProvider();
 
  base::i18n::InitializeICU();

#if defined(OS_POSIX)
  base::GlobalDescriptors* g_fds = base::GlobalDescriptors::GetInstance();
  g_fds->Set(kMojoIPCChannel,
   kMojoIPCChannel + base::GlobalDescriptors::kBaseDescriptor); 
#endif

  //FPDF_LIBRARY_ONFIG config;
  //config.version = 2;
  //config.m_pUserFontPaths = nullptr;
  //config.m_pIsolate = v8::Isolate::GetCurrent();
  //config.m_v8EmbedderSlot = 2;//gin::kEmbedderPDFium;
  //FPDF_InitLibraryWithConfig(&config);
  FPDF_InitLibrary();
//#if defined(OS_LINUX)
  // Font loading doesn't work in the renderer sandbox in Linux.
  FPDF_SetSystemFontInfo(&g_font_info);

//#endif

  FSDK_SetUnSpObjProcessHandler(&g_unsupported_info);


  // TODO: We have a problem with the runtime, given web platform
  // uses gin runtime.. 

  //mumba::V8Runtime* v8runtime = mumba::V8Runtime::GetInstance();
  //if (!v8runtime->Init()) {
  //  return false;
  //}

  // TODO: to be implemented.. 
  // we gonna need to create the BlinkPlatform impl 
  //g_webplatform = new WebPlatform();

  //blink::initialize(g_webplatform);

#if defined(ENABLE_WEBRTC)
  //InitializeWebRtcModule();
#endif

  std::unique_ptr<RuntimeMessageLoop> main_message_loop(new RuntimeMessageLoop());
  base::PlatformThread::SetName("RuntimeMain");
  std::unique_ptr<base::RunLoop> runloop(new base::RunLoop());
  

  //main_message_loop->BindToCurrentThread();
  g_runtime->message_loop = std::move(main_message_loop);

  //g_runtime->runloop = std::move(runloop);

  //scoped_refptr<base::SingleThreadTaskRunner> main_task_runner = base::ThreadTaskRunnerHandle::Get();
  //DCHECK(main_task_runner);

  // create the global sandbox
  Sandbox* sandbox = Sandbox::CreateInstance();
  if(!sandbox->Init()) {
    return false;
  }

  return true;
}

void Runtime::RunMainLoop() {
  //g_runtime->runloop->Run();
  base::RunLoop().Run();
}

//static 
void Runtime::Shutdown() {
  //mumba::V8Runtime* v8runtime = mumba::V8Runtime::GetInstance();
  //v8runtime->Shutdown();
  Sandbox* sandbox = Sandbox::GetInstance();
  sandbox->Leave();
  //blink::shutdown();
  FPDF_DestroyLibrary();
  //delete g_webplatform;
  delete g_runtime;
}

Runtime::Runtime() {}
Runtime::~Runtime() {}
