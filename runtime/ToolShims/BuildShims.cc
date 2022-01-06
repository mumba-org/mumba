// Copyright (c) 2016 Mumba. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "BuildShims.h"

#include "base/command_line.h"
#include "base/at_exit.h"
#include "base/process/launch.h"
#include "base/threading/thread.h"
#include "base/files/file_util.h"
#include "base/files/file.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/task_scheduler/task_scheduler.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/synchronization/waitable_event.h"
#include "base/hash.h"
#include "crypto/secure_hash.h"
#include "crypto/sha2.h"
#include "db/db.h"
#include "db/sqliteInt.h"
#include "builder/build.h"
#include "data/io/memory.h"
#include "data/ipc/reader.h"
#include "data/pretty_print.h"
#include "data/record_batch.h"
#include "data/status.h"
#include "data/table.h"
#include "data/type.h"
#include "data/type_traits.h"

#include "builder/browse.h"
#include "builder/build.h"
#include "builder/build_log.h"
#include "builder/deps_log.h"
#include "builder/clean.h"
#include "builder/debug_flags.h"
#include "builder/disk_interface.h"
#include "builder/graph.h"
#include "builder/graphviz.h"
#include "builder/manifest_parser.h"
#include "builder/metrics.h"
#include "builder/state.h"
#include "builder/util.h"
#include "builder/version.h"

int DBTest() {
  base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();
  
  base::FilePath dir_path("/home/fabiok/.config/mumba/packages");
  std::unique_ptr<db::Context> db;
  bool already_created = false;

  auto args = cmd->GetArgs();

  if (!args.size() || args.size() < 2) {
    printf("usage: [db name] [create,drop,get,put] [args]\n");
    return 1;
  }

  std::string db_name = args[0];
  std::string command = args[1];
  
  db::Init();

  base::FilePath db_path = dir_path.AppendASCII(db_name);

  if (base::PathExists(db_path)) {
    already_created = true;
    db = db::Open(db_path, 1, false);
    if (!db) {
      printf("db open failed\n");
      db::Shutdown();
      return 1;
    }
  } else if (command == "create") {
    db = db::Create(db_path, 1);
    if (!db) {
      printf("db creation failed\n");
      db::Shutdown();
      return 1;
    }
    db->Close();
    db::Shutdown();
    return 0;
  }

  if (db) {
    if (command == "put") {
      if (args.size() < 4) {
        printf("error (put): missing args for (key) and (value)\n");
        db->Close();
        db::Shutdown();
        return 1;
      }
      std::string key = args[2];
      std::string value = args[3];
      
      auto tr = db->BeginTransaction(true);
      
      auto kv = std::make_pair(base::StringPiece(key), base::StringPiece(value));
      
      auto cursor = db->CreateCursor(true);
      cursor->Insert(kv);
      tr->Commit();
    } else if (command == "get") {
      if (args.size() < 3) {
        printf("error (get): missing arg for (key)\n");
        db->Close();
        db::Shutdown();
        return 1;
      }    
      std::string key = args[2];
      auto tr = db->BeginTransaction(false);
      auto cursor = db->CreateCursor(false);
      base::StringPiece data;   
      if (cursor->GetValue(key, &data)) {
        printf("'%s' => '%s'\n", key.c_str(), (data.size() ? data.as_string().c_str() : "(null)"));
        std::string sha256_hash(crypto::kSHA256Length, 0);
        std::unique_ptr<crypto::SecureHash> ctx = crypto::SecureHash::Create(crypto::SecureHash::SHA256);
        ctx->Update(data.data(), data.size());
        ctx->Finish(const_cast<char *>(sha256_hash.data()), sha256_hash.size());
        std::string hex = base::ToLowerASCII(base::HexEncode(sha256_hash.data(), sha256_hash.size()));
        printf("hash: %s\n", hex.c_str());
        ctx.reset();
      } else {
        printf("'%s' not found.\n", key.c_str());
      }

      tr->Commit();
      cursor.reset();
      
    } else if (command == "list") {
      auto tr = db->BeginTransaction(false);
      auto cursor = db->CreateCursor(false);
      cursor->First();
      while (!cursor->IsEof()) {
        uint64_t a, b, c, d, e;
        base::StringPiece data = cursor->GetData();
        //printf("key: '%s' value: '%s' [%zu]\n", key.c_str(), (data.size() ? data.as_string().c_str() : "(null)"), data.size());
        const uint8_t * ptr = reinterpret_cast<const uint8_t *>(data.data());
        csqliteGetVarint(ptr, (u64*)&a);
        csqliteGetVarint(ptr+1, (u64*)&b);
        csqliteGetVarint(ptr+2, (u64*)&c);
        csqliteGetVarint(ptr+3, (u64*)&d);
        ptr += a;
        int rlen = data.size() - a;
        //uint8_t * end = const_cast<uint8_t *>(ptr) + rlen;
        //*end = '\0';
        base::StringPiece value(reinterpret_cast<const char *>(ptr), rlen);
        if (a == 5) {
          csqliteGetVarint(ptr+4, (u64*)&e);

          printf("[0]: %lu [1]: %lu [2]: %lu [3]: %lu [4]: %lu value: '%s' [%zu]\n", a, b, c, d, e, value.as_string().c_str(), data.size());
        } else {
          printf("[0]: %lu [1]: %lu [2]: %lu [3]: %lu value: '%s' [%zu]\n", a, b, c, d, value.as_string().c_str(), data.size());
        }
        cursor->Next();
      }
      tr->Commit();
      cursor.reset();
    } else if (command == "putfile") {
      if (args.size() < 3) {
        printf("error (putfile): missing arg for (file)\n");
        db->Close();
        db::Shutdown();
        return 1;
      }    
      std::string path_str = args[2];
      base::FilePath path(path_str);
      if (base::PathExists(path)) {
        std::string data;
        if (base::ReadFileToString(path, &data)) {
          std::string sha256_hash(crypto::kSHA256Length, 0);
          std::unique_ptr<crypto::SecureHash> ctx = crypto::SecureHash::Create(crypto::SecureHash::SHA256);
          ctx->Update(data.data(), data.size());
          ctx->Finish(const_cast<char *>(sha256_hash.data()), sha256_hash.size());
          std::string hex = base::ToLowerASCII(base::HexEncode(sha256_hash.data(), sha256_hash.size()));
          printf("hash: %s\n", hex.c_str());

          auto tr = db->BeginTransaction(true);
          auto kv = std::make_pair(base::StringPiece(path.value()), base::StringPiece(data));
          auto cursor = db->CreateCursor(true);
          bool ok = cursor->Insert(kv);
          ctx.reset();
          tr->Commit();
          printf("insert '%s' %s\n", path_str.c_str(), (ok ? "ok" : "failed"));
        }
      }
    } else if (command == "getfile") {
      if (args.size() < 3) {
        printf("error (get): missing arg for (key)\n");
        db->Close();
        db::Shutdown();
        return 1;
      }    
      std::string key = args[2];
      auto tr = db->BeginTransaction(false);
      auto cursor = db->CreateCursor(false);
      base::StringPiece data;
      if (cursor->GetValue(key, &data)) {
        std::string sha256_hash(crypto::kSHA256Length, 0);
        std::unique_ptr<crypto::SecureHash> ctx = crypto::SecureHash::Create(crypto::SecureHash::SHA256);
        ctx->Update(data.data(), data.size());
        ctx->Finish(const_cast<char *>(sha256_hash.data()), sha256_hash.size());
        std::string hex = base::ToLowerASCII((base::HexEncode(sha256_hash.data(), sha256_hash.size())));
        
        printf("hash: %s\n", hex.c_str());

        base::FilePath path(key);  
        std::string ext = path.Extension();
        base::FilePath dest(path.RemoveExtension().value() + "_copy" + ext);
        DLOG(INFO) << "writing file to '" << dest << "' ...";

        int wr = base::WriteFile(dest, data.data(), data.size());
        if (wr == (int)data.size()) {
          DLOG(INFO) << "done.";
        } else {
          DLOG(INFO) << "failed.";
        }
        ctx.reset();
      }

      tr->Commit();
      cursor.reset();
    } 
    db->Close();
  }

  db::Shutdown();

  return 0;
}

// int BundleExample() {
//   CFURLRef url = CFURLCreateWithString(kCFAllocatorSystemDefault, CFSTR("/workspace/source/WinObjC/tests/testapps/MinApp/MinApp/"), nullptr);
//   CFBundleRef bundle = CFBundleCreate(kCFAllocatorSystemDefault, url);
//   if (!bundle) {
//     printf("couldn't create the bundle\n");
//   }

//   CFStringRef id = CFBundleGetIdentifier(bundle);
//   if (!id) {
//     printf("No bundle identifier\n");
//   //  return 1;
//   } else {
//     printf("identifier: %s\n", CFStringGetCStringPtr(id, CFStringGetSystemEncoding()));
//   }
  
//   UInt32 packageType = 0; 
//   UInt32 packageCreator = 0;
//   CFBundleGetPackageInfo(bundle, &packageType, &packageCreator);

//   printf("package info: type: %d , creator: %d\n", packageType, packageCreator);

//   return 0;
// }

void PrintHelp() {
  const char kHELP_STR[] = "usage: [output dir]";
  printf(kHELP_STR);
}

enum BuildMode {
  kUNDEFINED = 0,
  kDEBUG_MODE = 1,
  kRELEASE_MODE = 2
};

/// Command-line options.
struct Options {
  /// Build file to load.
  const char* input_file;

  /// Directory to change into before running.
  const char* working_dir;
  /// Whether duplicate rules for one target should warn or print an error.
  bool dupe_edges_should_err = false;

  BuildMode mode = kUNDEFINED;
};

base::FilePath GetOutputDirectoryForOptions(const base::FilePath& path, const Options& options) {
  if (options.mode == kDEBUG_MODE) {
    return path.AppendASCII("out").AppendASCII("Debug");
  } else if (options.mode == kRELEASE_MODE) {
    return path.AppendASCII("out").AppendASCII("Release");
  }
  // kUNDEFINED
  return path.AppendASCII("out").AppendASCII("Default");
}


/// The Ninja main() loads up a series of data structures; various tools need
/// to poke into these, so store them as fields on an object.
struct NinjaMain : public builder::BuildLogUser {
  NinjaMain(const char* ninja_command, const builder::BuildConfig& config) :
      ninja_command_(ninja_command), config_(config) {}

  /// Command line used to run Ninja.
  const char* ninja_command_;

  /// Build configuration set from flags (e.g. parallelism).
  const builder::BuildConfig& config_;

  /// Loaded state (rules, nodes).
  builder::State state_;

  /// Functions for accesssing the disk.
  builder::RealDiskInterface disk_interface_;

  /// The build directory, used for storing the build log etc.
  std::string build_dir_;

  builder::BuildLog build_log_;
  builder::DepsLog deps_log_;

  /// Rebuild the build manifest, if necessary.
  /// Returns true if the manifest was rebuilt.
  bool RebuildManifest(const char* input_file, std::string* err) {
    std::string path = input_file;
    uint64_t slash_bits;  // Unused because this path is only used for lookup.
    if (!builder::util::CanonicalizePath(&path, &slash_bits, err))
      return false;
    builder::Node* node = state_.LookupNode(path);
    if (!node)
      return false;

    builder::Builder builder(&state_, config_, &build_log_, &deps_log_, &disk_interface_);
    if (!builder.AddTarget(node, err))
      return false;

    if (builder.AlreadyUpToDate())
      return false;  // Not an error, but we didn't rebuild.

    if (!builder.Build(err))
      return false;

    // The manifest was only rebuilt if it is now dirty (it may have been cleaned
    // by a restat).
    if (!node->dirty()) {
      // Reset the state to prevent problems like
      // https://github.com/ninja-build/ninja/issues/874
      state_.Reset();
      return false;
    }

    return true;
  }

  bool OpenBuildLog(bool recompact_only = false) {
    std::string log_path = ".ninja_log";
    if (!build_dir_.empty())
      log_path = build_dir_ + "/" + log_path;

    std::string err;
    if (!build_log_.Load(log_path, &err)) {
      builder::util::Error("loading build log %s: %s", log_path.c_str(), err.c_str());
      return false;
    }
    if (!err.empty()) {
      // Hack: Load() can return a warning via err by returning true.
      builder::util::Warning("%s", err.c_str());
      err.clear();
    }

    if (recompact_only) {
      bool success = build_log_.Recompact(log_path, *this, &err);
      if (!success)
        builder::util::Error("failed recompaction: %s", err.c_str());
      return success;
    }

   // if (!config_.dry_run) {
      if (!build_log_.OpenForWrite(log_path, *this, &err)) {
        builder::util::Error("opening build log: %s", err.c_str());
        return false;
      }
    //}

    return true;
  }

  /// Open the deps log: load it, then open for writing.
  /// @return false on error.
  bool OpenDepsLog(bool recompact_only = false) {
    std::string path = ".ninja_deps";
    if (!build_dir_.empty())
      path = build_dir_ + "/" + path;

    std::string err;
    if (!deps_log_.Load(path, &state_, &err)) {
      builder::util::Error("loading deps log %s: %s", path.c_str(), err.c_str());
      return false;
    }
    if (!err.empty()) {
      // Hack: Load() can return a warning via err by returning true.
      builder::util::Warning("%s", err.c_str());
      err.clear();
    }

    if (recompact_only) {
      bool success = deps_log_.Recompact(path, &err);
      if (!success)
        builder::util::Error("failed recompaction: %s", err.c_str());
      return success;
    }

    if (!config_.dry_run) {
      if (!deps_log_.OpenForWrite(path, &err)) {
        builder::util::Error("opening deps log: %s", err.c_str());
        return false;
      }
    }

    return true;
  }


  bool EnsureBuildDirExists() {
    build_dir_ = state_.bindings_.LookupVariable("builddir");
    if (!build_dir_.empty() && !config_.dry_run) {
      if (!disk_interface_.MakeDirs(build_dir_ + "/.") && errno != EEXIST) {
        builder::util::Error("creating build directory %s: %s",
              build_dir_.c_str(), strerror(errno));
        return false;
      }
    }
    return true;
  }

  builder::Node* CollectTarget(const std::string& input_path, std::string* err) {
    uint64_t slash_bits;
    std::string path = input_path;
    if (!builder::util::CanonicalizePath(&path, &slash_bits, err))
      return NULL;

    // Special syntax: "foo.cc^" means "the first output of foo.cc".
    bool first_dependent = false;
    if (!path.empty() && path[path.size() - 1] == '^') {
      path.resize(path.size() - 1);
      first_dependent = true;
    }

    builder::Node* node = state_.LookupNode(path);
    if (node) {
      if (first_dependent) {
        if (node->out_edges().empty()) {
          *err = "'" + path + "' has no out edge";
          return NULL;
        }
        builder::Edge* edge = node->out_edges()[0];
        if (edge->outputs_.empty()) {
          edge->Dump();
          builder::util::Fatal("edge has no outputs");
        }
        node = edge->outputs_[0];
      }
      return node;
    } else {
      *err =
          "unknown target '" + builder::Node::PathDecanonicalized(path, slash_bits) + "'";
      if (path == "clean") {
        *err += ", did you mean 'ninja -t clean'?";
      } else if (path == "help") {
        *err += ", did you mean 'ninja -h'?";
      } else {
        builder::Node* suggestion = state_.SpellcheckNode(path);
        if (suggestion) {
          *err += ", did you mean '" + suggestion->path() + "'?";
        }
      }
      return NULL;
    }
  }

  bool CollectTargetsFromArgs(const std::vector<std::string>& args,
                              std::vector<builder::Node*>* targets, std::string* err) {
    if (args.size() == 0) {
      *targets = state_.DefaultNodes(err);
      return err->empty();
    }

    for (const auto& arg : args) {
      builder::Node* node = CollectTarget(arg, err);
      if (node == NULL)
        return false;
      targets->push_back(node);
    }
    return true;
  }

  int RunBuild(const std::vector<std::string>& args) {
    std::string err;
    std::vector<builder::Node*> targets;
    if (!CollectTargetsFromArgs(args, &targets, &err)) {
      builder::util::Error("%s", err.c_str());
      return 1;
    }

    disk_interface_.AllowStatCache(false);//builder::g_experimental_statcache);

    builder::Builder builder(&state_, config_, &build_log_, &deps_log_, &disk_interface_);
    for (size_t i = 0; i < targets.size(); ++i) {
      if (!builder.AddTarget(targets[i], &err)) {
        if (!err.empty()) {
          builder::util::Error("%s", err.c_str());
          return 1;
        } else {
          // Added a target that is already up-to-date; not really
          // an error.
        }
      }
    }

    // Make sure restat rules do not see stale timestamps.
    disk_interface_.AllowStatCache(false);

    if (builder.AlreadyUpToDate()) {
      printf("ninja: no work to do.\n");
      return 0;
    }

    if (!builder.Build(&err)) {
      printf("ninja: build stopped: %s.\n", err.c_str());
      if (err.find("interrupted by user") != std::string::npos) {
        return 2;
      }
      return 1;
    }

    return 0;
  }

  virtual bool IsPathDead(builder::StringPiece s) const {
    builder::Node* n = state_.LookupNode(s);
    if (!n || !n->in_edge())
      return false;
    // Just checking n isn't enough: If an old output is both in the build log
    // and in the deps log, it will have a Node object in state_.  (It will also
    // have an in edge if one of its inputs is another output that's in the deps
    // log, but having a deps edge product an output thats input to another deps
    // edge is rare, and the first recompaction will delete all old outputs from
    // the deps log, and then a second recompaction will clear the build log,
    // which seems good enough for this corner case.)
    // Do keep entries around for files which still exist on disk, for
    // generators that want to use this information.
    std::string err;
    builder::TimeStamp mtime = disk_interface_.Stat(s.AsString(), &err);
    if (mtime == -1)
      builder::util::Error("%s", err.c_str());  // Log and ignore Stat() errors.
    return mtime == 0;
  }

};

int _mumba_build_main(int argc, char** argv) {
  base::CommandLine::Init(argc, argv);
  base::CommandLine* cmd = base::CommandLine::ForCurrentProcess();
  base::FilePath out_dir;
  Options options = {};
  
  const auto& args = cmd->GetArgs();

  if (cmd->HasSwitch("release")) {
    options.mode = kRELEASE_MODE;
  }
  
  if (cmd->HasSwitch("debug")) {
    options.mode = kDEBUG_MODE;
  }

  if (!cmd->HasSwitch("root")) {
    base::FilePath current_dir; 
    if (!base::GetCurrentDirectory(&current_dir)) {
      builder::util::Error("could not get the current directory");
      return 1;
    }
    // we expect that the ninja files are on out
    out_dir = GetOutputDirectoryForOptions(current_dir, options);
  } else {
    base::FilePath given_dir = base::FilePath(args[0]); 
    out_dir = GetOutputDirectoryForOptions(given_dir, options);
  }

  if (!base::DirectoryExists(out_dir)) {
    builder::util::Error("The output directory %s does not exist. You need to run gen first", out_dir.value().c_str());
    return 1;
  }

  base::FilePath ninja_file = out_dir.AppendASCII("build.ninja");

  if (!base::PathExists(ninja_file)) {
    builder::util::Error("The ninja file 'build.ninja' not found on %s", ninja_file.value().c_str());
    return 1;
  }

  builder::BuildConfig config;
  options.input_file = ninja_file.value().c_str();

  if (!base::SetCurrentDirectory(out_dir)) {
    builder::util::Error("unable to change the current directory for process to %s", out_dir.value().c_str());
    return 1; 
  }

    // Limit number of rebuilds, to prevent infinite loops.
  const int kCycleLimit = 100;
  for (int cycle = 1; cycle <= kCycleLimit; ++cycle) {
    NinjaMain ninja("build", config);

    builder::ManifestParser parser(&ninja.state_, &ninja.disk_interface_,
                          options.dupe_edges_should_err
                              ? builder::kDupeEdgeActionError
                              : builder::kDupeEdgeActionWarn);
    std::string err;
    if (!parser.Load(options.input_file, &err)) {
      builder::util::Error("%s", err.c_str());
      return 1;
    }

    //if (options.tool && options.tool->when == Tool::RUN_AFTER_LOAD)
    //  return (ninja.*options.tool->func)(&options, argc, argv);

    if (!ninja.EnsureBuildDirExists())
      return 1;

    if (!ninja.OpenBuildLog() || !ninja.OpenDepsLog())
      return 1;

    //if (options.tool && options.tool->when == Tool::RUN_AFTER_LOGS)
    //  return (ninja.*options.tool->func)(&options, argc, argv);

    // Attempt to rebuild the manifest before building anything else
    if (ninja.RebuildManifest(options.input_file, &err)) {
      // In dry_run mode the regeneration will succeed without changing the
      // manifest forever. Better to return immediately.
      //if (config.dry_run)
      //  return 0;
      // Start the build over with the new manifest.
      continue;
    } else if (!err.empty()) {
      builder::util::Error("rebuilding '%s': %s", options.input_file, err.c_str());
      return 1;
    }

    int result = ninja.RunBuild(cmd->GetArgs());
    //if (builder::g_metrics)
    //  ninja.DumpMetrics();
    return result;
  }

  builder::util::Error("manifest '%s' still dirty after %d tries\n",
      options.input_file, kCycleLimit);
  return 1;
}