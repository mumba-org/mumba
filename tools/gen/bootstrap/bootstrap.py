#!/usr/bin/env python
# Copyright 2014 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This file isn't officially supported by the Chromium project. It's maintained
# on a best-effort basis by volunteers, so some things may be broken from time
# to time. If you encounter errors, it's most often due to files in base that
# have been added or moved since somebody last tried this script. Generally
# such errors are easy to diagnose.

"""Bootstraps gn.

It is done by first building it manually in a temporary directory, then building
it with its own BUILD.gn to the final destination.
"""

import contextlib
import errno
import logging
import optparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile

BOOTSTRAP_DIR = os.path.dirname(os.path.abspath(__file__))
GN_ROOT = os.path.dirname(BOOTSTRAP_DIR)
TOOLS_ROOT = os.path.dirname(GN_ROOT)
SRC_ROOT = os.path.dirname(os.path.dirname(GN_ROOT))

is_win = sys.platform.startswith('win')
is_linux = sys.platform.startswith('linux')
is_mac = sys.platform.startswith('darwin')
is_aix = sys.platform.startswith('aix')
is_posix = is_linux or is_mac or is_aix

def check_call(cmd, **kwargs):
  logging.debug('Running: %s', ' '.join(cmd))

  subprocess.check_call(cmd, cwd=GN_ROOT, **kwargs)

def check_output(cmd, cwd=GN_ROOT, **kwargs):
  logging.debug('Running: %s', ' '.join(cmd))

  return subprocess.check_output(cmd, cwd=cwd, **kwargs)

def mkdir_p(path):
  try:
    os.makedirs(path)
  except OSError as e:
    if e.errno == errno.EEXIST and os.path.isdir(path):
      pass
    else: raise

@contextlib.contextmanager
def scoped_tempdir():
  path = tempfile.mkdtemp()
  try:
    yield path
  finally:
    shutil.rmtree(path)


def run_build(tempdir, options):
  if options.build_path:
    build_rel = options.build_path
  elif options.debug:
    build_rel = os.path.join('out', 'Debug')
  else:
    build_rel = os.path.join('out', 'Release')
  build_root = os.path.join(SRC_ROOT, build_rel)

  print(build_root)

  windows_x64_toolchain = None
  if is_win:
    windows_x64_toolchain = windows_prepare_toolchain(tempdir)
    os.environ["PATH"] = windows_x64_toolchain["paths"]

  print 'Building gn manually in a temporary directory for bootstrapping...'
  build_gn_with_ninja_manually(tempdir, options, windows_x64_toolchain)
  #temp_gn = os.path.join(tempdir, 'gn')
  temp_gn = os.path.join(tempdir, 'jabberwock_gen')
  #out_gn = os.path.join(build_root, 'gn')
  out_gn = os.path.join(build_root, 'jabberwock_gen')

  if is_win:
    temp_gn += '.exe'
    out_gn += '.exe'

  if options.no_rebuild:
    print(build_root)
    mkdir_p(build_root)
    shutil.copy2(temp_gn, out_gn)
  else:
    print 'Building gn using itself to %s...' % build_rel
    build_gn_with_gn(temp_gn, build_root, options)

  if options.output:
    # Preserve the executable permission bit.
    shutil.copy2(out_gn, options.output)

def windows_target_build_arch():
    # Target build architecture set by vcvarsall.bat
    target_arch = os.environ.get('Platform')
    if target_arch in ['x64', 'x86']: return target_arch

    if platform.machine().lower() in ['x86_64', 'amd64']: return 'x64'
    return 'x86'

def windows_prepare_toolchain(tempdir):

  def CallPythonScopeScript(command, **kwargs):
    response = check_output(command, **kwargs)

    _globals = {"__builtins__":None}
    _locals = {}
    exec(response, _globals, _locals)

    return _locals

  toolchain_paths = CallPythonScopeScript(
      [sys.executable,
       os.path.join(SRC_ROOT, "build", "vs_toolchain.py"),
      "get_toolchain_dir"],
      cwd=tempdir)

  windows_x64_toolchain =  CallPythonScopeScript(
      [sys.executable,
       os.path.join(SRC_ROOT, "build", "toolchain",
                    "win", "setup_toolchain.py"),
       toolchain_paths["vs_path"],
       toolchain_paths["sdk_path"],
       toolchain_paths["runtime_dirs"],
       "win",
       "x64",
       "environment.x64",
       "true"
      ],
      cwd=tempdir)

  return windows_x64_toolchain

def main(argv):
  parser = optparse.OptionParser(description=sys.modules[__name__].__doc__)
  parser.add_option('-d', '--debug', action='store_true',
                    help='Do a debug build. Defaults to release build.')
  parser.add_option('-o', '--output',
                    help='place output in PATH', metavar='PATH')
  parser.add_option('-s', '--no-rebuild', action='store_true',
                    help='Do not rebuild GN with GN.')
  parser.add_option('--no-clean', action='store_true',
                    help='Re-used build directory instead of using new '
                         'temporary location each time')
  parser.add_option('--gn-gen-args', help='Args to pass to gn gen --args')
  parser.add_option('--build-path', help='The directory in which to build gn, '
                    'relative to the src directory. (eg. out/Release)'
                    'In the no-clean mode an absolute path will also force '
                    'the out_bootstrap to be located in the parent directory')
  parser.add_option('-v', '--verbose', action='store_true',
                    help='Log more details')
  options, args = parser.parse_args(argv)

  if args:
    parser.error('Unrecognized command line arguments: %s.' % ', '.join(args))

  logging.basicConfig(level=logging.DEBUG if options.verbose else logging.ERROR)

  try:
    if options.no_clean:
      out_bootstrap_dir = SRC_ROOT
      if options.build_path and os.path.isabs(options.build_path):
        out_bootstrap_dir = os.path.dirname(options.build_path)
      build_dir = os.path.join(out_bootstrap_dir, 'out_bootstrap')
      if not os.path.exists(build_dir):
        os.makedirs(build_dir)
      return run_build(build_dir, options)
    else:
      with scoped_tempdir() as tempdir:
        return run_build(tempdir, options)
  except subprocess.CalledProcessError as e:
    print >> sys.stderr, str(e)
    return 1
  return 0

def write_compiled_message(root_gen_dir, source):
  path = os.path.join(root_gen_dir, os.path.dirname(source))
  mkdir_p(path)
  check_call([
      'mc.exe',
      '-r', path, '-h', path,
      '-u', '-um',
      os.path.join(SRC_ROOT, source),
  ])

def write_buildflag_header_manually(root_gen_dir, header, flags):
  mkdir_p(os.path.join(root_gen_dir, os.path.dirname(header)))

  # Don't use tempfile.NamedTemporaryFile() here.
  # It doesn't work correctly on Windows.
  # see: http://bugs.python.org/issue14243
  temp_path = os.path.join(root_gen_dir, header + '.tmp')
  with open(temp_path, 'w') as f:
    f.write('--flags')
    for name,value in flags.items():
      f.write(' ' + name + '=' + value)

  check_call([
      sys.executable,
      os.path.join(SRC_ROOT, 'build', 'write_buildflag_header.py'),
      '--output', header,
      '--gen-dir', root_gen_dir,
      '--definitions', temp_path,
  ])

  os.remove(temp_path)

def write_build_date_header(root_gen_dir):
  check_call([
       sys.executable,
       os.path.join(SRC_ROOT, 'build', 'write_build_date_header.py'),
       os.path.join(root_gen_dir, 'lib/base/generated_build_date.h'),
       'default',
  ])

def build_gn_with_ninja_manually(tempdir, options, windows_x64_toolchain):
  root_gen_dir = os.path.join(tempdir, 'gen')
  mkdir_p(root_gen_dir)
  lib_gen_dir = os.path.join(tempdir, 'gen', 'lib')
  mkdir_p(lib_gen_dir)

  write_buildflag_header_manually(
      root_gen_dir,
      'lib/base/synchronization/synchronization_buildflags.h',
      {'ENABLE_MUTEX_PRIORITY_INHERITANCE': 'false'})

  write_buildflag_header_manually(root_gen_dir, 'lib/base/allocator/buildflags.h',
      {'USE_ALLOCATOR_SHIM': 'true' if is_linux else 'false'})

  write_buildflag_header_manually(root_gen_dir,
                                  'lib/base/debug/debugging_buildflags.h',
      {
          'ENABLE_LOCATION_SOURCE': 'false',
          'ENABLE_PROFILING': 'false',
          'CAN_UNWIND_WITH_FRAME_POINTERS': 'false',
          'UNSAFE_DEVELOPER_BUILD': 'false',
          'CAN_UNWIND_WITH_CFI_TABLE': 'false',
      })

  write_buildflag_header_manually(root_gen_dir,
                                  'lib/base/memory/protected_memory_buildflags.h',
                                  { 'USE_LLD': 'false' })

  write_buildflag_header_manually(root_gen_dir, 'lib/base/cfi_buildflags.h',
      {
          'CFI_CAST_CHECK': 'false',
          'CFI_ICALL_CHECK': 'false',
          'CFI_ENFORCEMENT_TRAP': 'false',
          'CFI_ENFORCEMENT_DIAGNOSTIC': 'false'
      })

  write_build_date_header(root_gen_dir)

  if is_mac:
    # //base/build_time.cc needs base/generated_build_date.h,
    # and this file is only included for Mac builds.
    mkdir_p(os.path.join(root_gen_dir, 'lib/base'))
    check_call([
        sys.executable,
        os.path.join(SRC_ROOT, 'build', 'write_build_date_header.py'),
        os.path.join(root_gen_dir, 'base', 'generated_build_date.h'),
        'default'
    ])

  if is_win:
    write_buildflag_header_manually(root_gen_dir,
                                    'lib/base/win/base_win_buildflags.h',
        {'SINGLE_MODULE_MODE_HANDLE_VERIFIER': 'true'})

    write_compiled_message(root_gen_dir,
        'lib/base/trace_event/etw_manifest/chrome_events_win.man')

  write_buildflag_header_manually(
      root_gen_dir, 'lib/base/android/library_loader.h',
      {'USE_LLD': 'false', 'SUPPORTS_CODE_ORDERING': 'false'})

  write_gn_ninja(os.path.join(tempdir, 'build.ninja'),
                 root_gen_dir, lib_gen_dir, options, windows_x64_toolchain)
  cmd = ['ninja', '-C', tempdir, '-w', 'dupbuild=err']
  if options.verbose:
    cmd.append('-v')

  #if is_win:
  #  cmd.append('gn.exe')
  #else:
  #  cmd.append('gn')

  if is_win:
    cmd.append('jabberwock_gen.exe')
  else:
    cmd.append('jabberwock_gen')

  check_call(cmd)

def write_generic_ninja(path, static_libraries, executables,
                        cc, cxx, ar, ld,
                        cflags=[], cflags_cc=[], ldflags=[],
                        include_dirs=[], solibs=[]):
  ninja_header_lines = [
    'cc = ' + cc,
    'cxx = ' + cxx,
    'ar = ' + ar,
    'ld = ' + ld,
    '',
  ]

  if is_win:
    template_filename = 'build_vs.ninja.template'
  elif is_mac:
    template_filename = 'build_mac.ninja.template'
  elif is_aix:
    template_filename = 'build_aix.ninja.template'
  else:
    template_filename = 'build.ninja.template'

  with open(os.path.join(GN_ROOT, 'bootstrap', template_filename)) as f:
    ninja_template = f.read()

  if is_win:
    executable_ext = '.exe'
    library_ext = '.lib'
    object_ext = '.obj'
  else:
    executable_ext = ''
    library_ext = '.a'
    object_ext = '.o'

  def escape_path_ninja(path):
      return path.replace('$ ', '$$ ').replace(' ', '$ ').replace(':', '$:')

  def src_to_obj(path):
    return escape_path_ninja('%s' % os.path.splitext(path)[0] + object_ext)

  def library_to_a(library):
    return '%s%s' % (library, library_ext)

  ninja_lines = []
  def build_source(src_file, settings):
    ninja_lines.extend([
        'build %s: %s %s' % (src_to_obj(src_file),
                             settings['tool'],
                             escape_path_ninja(
                                 os.path.join(SRC_ROOT, src_file))),
        '  includes = %s' % ' '.join(
            ['-I' + escape_path_ninja(dirname) for dirname in
             include_dirs + settings.get('include_dirs', [])]),
        '  cflags = %s' % ' '.join(cflags + settings.get('cflags', [])),
        '  cflags_cc = %s' %
            ' '.join(cflags_cc + settings.get('cflags_cc', [])),
    ])

  for library, settings in static_libraries.iteritems():
    for src_file in settings['sources']:
      build_source(src_file, settings)

    ninja_lines.append('build %s: alink_thin %s' % (
        library_to_a(library),
        ' '.join([src_to_obj(src_file) for src_file in settings['sources']])))

  for executable, settings in executables.iteritems():
    for src_file in settings['sources']:
      build_source(src_file, settings)

    ninja_lines.extend([
      'build %s%s: link %s | %s' % (
          executable, executable_ext,
          ' '.join([src_to_obj(src_file) for src_file in settings['sources']]),
          ' '.join([library_to_a(library) for library in settings['libs']])),
      '  ldflags = %s' % ' '.join(ldflags),
      '  solibs = %s' % ' '.join(solibs),
      '  libs = %s' % ' '.join(
          [library_to_a(library) for library in settings['libs']]),
    ])

  ninja_lines.append('')  # Make sure the file ends with a newline.

  with open(path, 'w') as f:
    f.write('\n'.join(ninja_header_lines))
    f.write(ninja_template)
    f.write('\n'.join(ninja_lines))

def write_gn_ninja(path, root_gen_dir, lib_gen_dir, options, windows_x64_toolchain):
  if is_win:
    CCPATH = windows_x64_toolchain["vc_bin_dir"]

    cc = os.environ.get('CC', os.path.join(CCPATH, 'cl.exe'))
    cxx = os.environ.get('CXX', os.path.join(CCPATH, 'cl.exe'))
    ld = os.environ.get('LD', os.path.join(CCPATH, 'link.exe'))
    ar = os.environ.get('AR', os.path.join(CCPATH, 'lib.exe'))
  elif is_aix:
    cc = os.environ.get('CC', 'gcc')
    cxx = os.environ.get('CXX', 'c++')
    ld = os.environ.get('LD', cxx)
    ar = os.environ.get('AR', 'ar -X64')
  else:
    cc = os.environ.get('CC', 'cc')
    cxx = os.environ.get('CXX', 'c++')
    ld = cxx
    ar = os.environ.get('AR', 'ar')

  cflags = os.environ.get('CFLAGS', '').split()
  cflags_cc = os.environ.get('CXXFLAGS', '').split()
  ldflags = os.environ.get('LDFLAGS', '').split()
  lib_dir = os.path.join(SRC_ROOT, 'lib')

  include_dirs = [root_gen_dir, lib_gen_dir, SRC_ROOT, TOOLS_ROOT, lib_dir]
  libs = []

  # //base/allocator/allocator_extension.cc needs this macro defined,
  # otherwise there would be link errors.
  cflags.extend(['-DNO_TCMALLOC', '-D__STDC_FORMAT_MACROS'])

  if is_posix:
    if options.debug:
      cflags.extend(['-O0', '-g'])
    else:
      # The linux::ppc64 BE binary doesn't "work" when
      # optimization level is set to 2 (0 works fine).
      # Note that the current bootstrap script has no way to detect host_cpu.
      # This can be easily fixed once we start building using a GN binary,
      # as the optimization flag can then just be set using the
      # logic inside //build/toolchain.
      cflags.extend(['-O2', '-g0'])

    cflags.extend([
        '-D_FILE_OFFSET_BITS=64',
        '-D__STDC_CONSTANT_MACROS', '-D__STDC_FORMAT_MACROS',
        '-pthread',
        '-pipe',
        '-fno-exceptions'
    ])
    cflags_cc.extend(['-std=c++14', '-Wno-c++11-narrowing'])
    if is_aix:
     cflags.extend(['-maix64'])
     ldflags.extend([ '-maix64 -Wl,-bbigtoc' ])
  elif is_win:
    if not options.debug:
      cflags.extend(['/Ox', '/DNDEBUG', '/GL'])
      ldflags.extend(['/LTCG', '/OPT:REF', '/OPT:ICF'])

    cflags.extend([
        '/FS',
        '/Gy',
        '/W3', '/wd4244',
        '/Zi',
        '/DWIN32_LEAN_AND_MEAN', '/DNOMINMAX',
        '/D_CRT_SECURE_NO_DEPRECATE', '/D_SCL_SECURE_NO_DEPRECATE',
        '/D_WIN32_WINNT=0x0A00', '/DWINVER=0x0A00',
        '/DUNICODE', '/D_UNICODE',
    ])
    cflags_cc.extend([
        '/GR-',
        '/D_HAS_EXCEPTIONS=0',
    ])

    target_arch = windows_target_build_arch()
    if target_arch == 'x64':
        ldflags.extend(['/MACHINE:x64'])
    else:
        ldflags.extend(['/MACHINE:x86'])

  static_libraries = {
      'base': {'sources': [], 'tool': 'cxx', 'include_dirs': []},
      'dynamic_annotations': {'sources': [], 'tool': 'cc', 'include_dirs': []},
      #'gn_lib': {'sources': [], 'tool': 'cxx', 'include_dirs': []},
      'gen': {'sources': [], 'tool': 'cxx', 'include_dirs': []},
  }

  #executables = {
  #    'gn': {'sources': ['tools/gen/gn_main.cc'],
  #           'tool': 'cxx', 'include_dirs': [], 'libs': []},
  #}

  executables = {
      'jabberwock_gen': {
        'sources': [
          'jabberwock/app/jabberwock_gen_bin.cc',
          'runtime/ToolShims/GenShims.cc'
        ],
       'tool': 'cxx', 'include_dirs': [], 'libs': []},
  }

  for name in os.listdir(GN_ROOT):
    if not name.endswith('.cc'):
      continue
    if name.endswith('_unittest.cc'):
      continue
    if name == 'run_all_unittests.cc':
      continue
    if name == 'test_with_scheduler.cc':
      continue
    if name == 'test_with_scope.cc':
      continue
    if name == 'gn_main.cc':
      continue
    full_path = os.path.join(GN_ROOT, name)
    #static_libraries['gn_lib']['sources'].append(
    static_libraries['gen']['sources'].append(
        os.path.relpath(full_path, SRC_ROOT))

  static_libraries['dynamic_annotations']['sources'].extend([
      'lib/base/third_party/dynamic_annotations/dynamic_annotations.c',
      'lib/base/third_party/superfasthash/superfasthash.c',
  ])
  static_libraries['base']['sources'].extend([
      'lib/base/allocator/allocator_check.cc',
      'lib/base/allocator/allocator_extension.cc',
      'lib/base/at_exit.cc',
      'lib/base/base_paths.cc',
      'lib/base/base_switches.cc',
      'lib/base/build_time.cc',
      'lib/base/callback_helpers.cc',
      'lib/base/callback_internal.cc',
      'lib/base/command_line.cc',
      'lib/base/debug/activity_tracker.cc',
      'lib/base/debug/alias.cc',
      'lib/base/debug/crash_logging.cc',
      'lib/base/debug/dump_without_crashing.cc',
      'lib/base/debug/stack_trace.cc',
      'lib/base/debug/task_annotator.cc',
      'lib/base/debug/thread_heap_usage_tracker.cc',
      'lib/base/environment.cc',
      'lib/base/feature_list.cc',
      'lib/base/files/file.cc',
      'lib/base/files/file_enumerator.cc',
      'lib/base/files/file_path.cc',
      'lib/base/files/file_path_constants.cc',
      'lib/base/files/file_tracing.cc',
      'lib/base/files/file_util.cc',
      'lib/base/files/important_file_writer.cc',
      'lib/base/files/memory_mapped_file.cc',
      'lib/base/files/scoped_file.cc',
      'lib/base/hash.cc',
      'lib/base/json/json_parser.cc',
      'lib/base/json/json_reader.cc',
      'lib/base/json/json_string_value_serializer.cc',
      'lib/base/json/json_writer.cc',
      'lib/base/json/string_escape.cc',
      'lib/base/lazy_instance_helpers.cc',
      'lib/base/location.cc',
      'lib/base/logging.cc',
      'lib/base/md5.cc',
      'lib/base/memory/ref_counted.cc',
      'lib/base/memory/ref_counted_memory.cc',
      'lib/base/memory/read_only_shared_memory_region.cc',
      'lib/base/memory/shared_memory_handle.cc',
      'lib/base/memory/shared_memory_tracker.cc',
      'lib/base/memory/shared_memory_mapping.cc',
      'lib/base/memory/platform_shared_memory_region.cc',
      'lib/base/memory/weak_ptr.cc',
      'lib/base/message_loop/incoming_task_queue.cc',
      'lib/base/message_loop/message_loop.cc',
      'lib/base/message_loop/message_loop_current.cc',
      'lib/base/message_loop/message_loop_task_runner.cc',
      'lib/base/message_loop/message_pump.cc',
      'lib/base/message_loop/message_pump_default.cc',
      'lib/base/message_loop/watchable_io_message_pump_posix.cc',
      'lib/base/metrics/bucket_ranges.cc',
      'lib/base/metrics/dummy_histogram.cc',
      'lib/base/metrics/field_trial.cc',
      'lib/base/metrics/field_trial_param_associator.cc',
      'lib/base/metrics/field_trial_params.cc',
      'lib/base/metrics/histogram.cc',
      'lib/base/metrics/histogram_base.cc',
      'lib/base/metrics/histogram_functions.cc',
      'lib/base/metrics/histogram_samples.cc',
      'lib/base/metrics/histogram_snapshot_manager.cc',
      'lib/base/metrics/metrics_hashes.cc',
      'lib/base/metrics/persistent_histogram_allocator.cc',
      'lib/base/metrics/persistent_memory_allocator.cc',
      'lib/base/metrics/persistent_sample_map.cc',
      'lib/base/metrics/sample_map.cc',
      'lib/base/metrics/sample_vector.cc',
      'lib/base/metrics/sparse_histogram.cc',
      'lib/base/metrics/statistics_recorder.cc',
      'lib/base/observer_list_threadsafe.cc',
      'lib/base/path_service.cc',
      'lib/base/pending_task.cc',
      'lib/base/pickle.cc',
      'lib/base/process/kill.cc',
      'lib/base/process/memory.cc',
      'lib/base/process/process_handle.cc',
      'lib/base/process/process_iterator.cc',
      'lib/base/process/process_metrics.cc',
      'lib/base/rand_util.cc',
      'lib/base/run_loop.cc',
      'lib/base/sequence_token.cc',
      'lib/base/sequence_checker_impl.cc',
      'lib/base/sequenced_task_runner.cc',
      'lib/base/sha1.cc',
      'lib/base/strings/pattern.cc',
      'lib/base/strings/string_number_conversions.cc',
      'lib/base/strings/string_piece.cc',
      'lib/base/strings/string_split.cc',
      'lib/base/strings/string_util.cc',
      'lib/base/strings/string_util_constants.cc',
      'lib/base/strings/stringprintf.cc',
      'lib/base/strings/utf_string_conversion_utils.cc',
      'lib/base/strings/utf_string_conversions.cc',
      'lib/base/synchronization/atomic_flag.cc',
      'lib/base/synchronization/lock.cc',
      'lib/base/sys_info.cc',
      'lib/base/task_runner.cc',
      'lib/base/task_scheduler/delayed_task_manager.cc',
      'lib/base/task_scheduler/environment_config.cc',
      'lib/base/task_scheduler/post_task.cc',
      'lib/base/task_scheduler/priority_queue.cc',
      'lib/base/task_scheduler/scheduler_lock_impl.cc',
      'lib/base/task_scheduler/scheduler_single_thread_task_runner_manager.cc',
      'lib/base/task_scheduler/scheduler_worker.cc',
      'lib/base/task_scheduler/scheduler_worker_pool.cc',
      'lib/base/task_scheduler/scheduler_worker_pool_impl.cc',
      'lib/base/task_scheduler/scheduler_worker_pool_params.cc',
      'lib/base/task_scheduler/scheduler_worker_stack.cc',
      'lib/base/task_scheduler/scoped_set_task_priority_for_current_thread.cc',
      'lib/base/task_scheduler/sequence.cc',
      'lib/base/task_scheduler/sequence_sort_key.cc',
      'lib/base/task_scheduler/task.cc',
      'lib/base/task_scheduler/task_scheduler.cc',
      'lib/base/task_scheduler/task_scheduler_impl.cc',
      'lib/base/task_scheduler/task_tracker.cc',
      'lib/base/task_scheduler/task_traits.cc',
      'lib/base/third_party/dmg_fp/dtoa_wrapper.cc',
      'lib/base/third_party/dmg_fp/g_fmt.cc',
      'lib/base/third_party/icu/icu_utf.cc',
      'lib/base/third_party/nspr/prtime.cc',
      'lib/base/threading/post_task_and_reply_impl.cc',
      'lib/base/threading/scoped_blocking_call.cc',
      'lib/base/threading/sequence_local_storage_map.cc',
      'lib/base/threading/sequenced_task_runner_handle.cc',
      'lib/base/threading/simple_thread.cc',
      'lib/base/threading/thread.cc',
      'lib/base/threading/thread_checker_impl.cc',
      'lib/base/threading/thread_collision_warner.cc',
      'lib/base/threading/thread_id_name_manager.cc',
      'lib/base/threading/thread_local_storage.cc',
      'lib/base/threading/thread_restrictions.cc',
      'lib/base/threading/thread_task_runner_handle.cc',
      'lib/base/time/clock.cc',
      'lib/base/time/default_clock.cc',
      'lib/base/time/default_tick_clock.cc',
      'lib/base/time/tick_clock.cc',
      'lib/base/time/time.cc',
      'lib/base/timer/elapsed_timer.cc',
      'lib/base/timer/timer.cc',
      'lib/base/trace_event/category_registry.cc',
      'lib/base/trace_event/event_name_filter.cc',
      'lib/base/trace_event/heap_profiler_allocation_context.cc',
      'lib/base/trace_event/heap_profiler_allocation_context_tracker.cc',
      'lib/base/trace_event/heap_profiler_allocation_register.cc',
      'lib/base/trace_event/heap_profiler_event_filter.cc',
      'lib/base/trace_event/heap_profiler_heap_dump_writer.cc',
      'lib/base/trace_event/heap_profiler_serialization_state.cc',
      'lib/base/trace_event/heap_profiler_stack_frame_deduplicator.cc',
      'lib/base/trace_event/heap_profiler_type_name_deduplicator.cc',
      'lib/base/trace_event/malloc_dump_provider.cc',
      'lib/base/trace_event/memory_allocator_dump.cc',
      'lib/base/trace_event/memory_allocator_dump_guid.cc',
      'lib/base/trace_event/memory_dump_manager.cc',
      'lib/base/trace_event/memory_dump_provider_info.cc',
      'lib/base/trace_event/memory_dump_request_args.cc',
      'lib/base/trace_event/memory_dump_scheduler.cc',
      'lib/base/trace_event/memory_infra_background_whitelist.cc',
      'lib/base/trace_event/memory_peak_detector.cc',
      'lib/base/trace_event/memory_usage_estimator.cc',
      'lib/base/trace_event/process_memory_dump.cc',
      'lib/base/trace_event/sharded_allocation_register.cc',
      'lib/base/trace_event/trace_buffer.cc',
      'lib/base/trace_event/trace_config.cc',
      'lib/base/trace_event/trace_config_category_filter.cc',
      'lib/base/trace_event/trace_event_argument.cc',
      'lib/base/trace_event/trace_event_filter.cc',
      'lib/base/trace_event/trace_event_impl.cc',
      'lib/base/trace_event/trace_event_memory_overhead.cc',
      'lib/base/trace_event/trace_log.cc',
      'lib/base/trace_event/trace_log_constants.cc',
      'lib/base/trace_event/tracing_agent.cc',
      'lib/base/unguessable_token.cc',
      'lib/base/value_iterators.cc',
      'lib/base/values.cc',
      'lib/base/vlog.cc',
  ])

  if is_posix:
    static_libraries['base']['sources'].extend([
        'lib/base/base_paths_posix.cc',
        'lib/base/debug/debugger_posix.cc',
        'lib/base/debug/stack_trace_posix.cc',
        'lib/base/files/file_enumerator_posix.cc',
        'lib/base/files/file_descriptor_watcher_posix.cc',
        'lib/base/files/file_posix.cc',
        'lib/base/files/file_util_posix.cc',
        'lib/base/files/memory_mapped_file_posix.cc',
        'lib/base/memory/shared_memory_helper.cc',
        'lib/base/message_loop/message_pump_libevent.cc',
        'lib/base/posix/file_descriptor_shuffle.cc',
        'lib/base/posix/global_descriptors.cc',
        'lib/base/posix/safe_strerror.cc',
        'lib/base/process/kill_posix.cc',
        'lib/base/process/process_handle_posix.cc',
        'lib/base/process/process_metrics_posix.cc',
        'lib/base/process/process_posix.cc',
        'lib/base/rand_util_posix.cc',
        'lib/base/strings/string16.cc',
        'lib/base/synchronization/condition_variable_posix.cc',
        'lib/base/synchronization/lock_impl_posix.cc',
        'lib/base/sys_info_posix.cc',
        'lib/base/task_scheduler/task_tracker_posix.cc',
        'lib/base/threading/platform_thread_internal_posix.cc',
        'lib/base/threading/platform_thread_posix.cc',
        'lib/base/threading/thread_local_storage_posix.cc',
        'lib/base/time/time_conversion_posix.cc',
        'lib/base/trace_event/heap_profiler_allocation_register_posix.cc',
    ])
    static_libraries['libevent'] = {
        'sources': [
            'lib/base/third_party/libevent/buffer.c',
            'lib/base/third_party/libevent/evbuffer.c',
            'lib/base/third_party/libevent/evdns.c',
            'lib/base/third_party/libevent/event.c',
            'lib/base/third_party/libevent/event_tagging.c',
            'lib/base/third_party/libevent/evrpc.c',
            'lib/base/third_party/libevent/evutil.c',
            'lib/base/third_party/libevent/http.c',
            'lib/base/third_party/libevent/log.c',
            'lib/base/third_party/libevent/poll.c',
            'lib/base/third_party/libevent/select.c',
            'lib/base/third_party/libevent/signal.c',
            'lib/base/third_party/libevent/strlcpy.c',
        ],
        'tool': 'cc',
        'include_dirs': [],
        'cflags': cflags + ['-DHAVE_CONFIG_H'],
    }
    static_libraries['jsoncpp'] = {
     'sources': [
       "third_party/jsoncpp/overrides/include/json/value.h",
       "third_party/jsoncpp/overrides/src/lib_json/json_reader.cpp",
       "third_party/jsoncpp/overrides/src/lib_json/json_value.cpp",
       "third_party/jsoncpp/source/include/json/assertions.h",
       "third_party/jsoncpp/source/include/json/autolink.h",
       "third_party/jsoncpp/source/include/json/config.h",
       "third_party/jsoncpp/source/include/json/features.h",
       "third_party/jsoncpp/source/include/json/forwards.h",
       "third_party/jsoncpp/source/include/json/json.h",
       "third_party/jsoncpp/source/include/json/reader.h",
       "third_party/jsoncpp/source/include/json/writer.h",
       "third_party/jsoncpp/source/src/lib_json/json_batchallocator.h",
      # "third_party/jsoncpp/source/src/lib_json/json_tool.h",
       "third_party/jsoncpp/source/src/lib_json/json_writer.cpp",
      ],
      'tool': 'cxx',
      'include_dirs': [ 
        SRC_ROOT + "/third_party/jsoncpp/source/src/lib_json", 
        SRC_ROOT + "/third_party/jsoncpp/overrides/include", 
        SRC_ROOT + "/third_party/jsoncpp/source/include",
      ],
      'cflags': cflags + ['-DJSON_USE_EXCEPTION=0'],
    }

  if is_linux or is_aix:
    static_libraries['xdg_user_dirs'] = {
        'sources': [
            'lib/base/third_party/xdg_user_dirs/xdg_user_dir_lookup.cc',
        ],
        'tool': 'cxx',
    }
    static_libraries['base']['sources'].extend([
        'lib/base/memory/shared_memory_handle_posix.cc',
        'lib/base/memory/shared_memory_posix.cc',
        'lib/base/memory/platform_shared_memory_region_posix.cc',
        'lib/base/nix/xdg_util.cc',
        'lib/base/process/internal_linux.cc',
        'lib/base/process/memory_linux.cc',
        'lib/base/process/process_handle_linux.cc',
        'lib/base/process/process_info_linux.cc',
        'lib/base/process/process_iterator_linux.cc',
        'lib/base/process/process_linux.cc',
        'lib/base/process/process_metrics_linux.cc',
        'lib/base/strings/sys_string_conversions_posix.cc',
        'lib/base/synchronization/waitable_event_posix.cc',
        'lib/base/sys_info_linux.cc',
        'lib/base/time/time_exploded_posix.cc',
        'lib/base/time/time_now_posix.cc',
        'lib/base/threading/platform_thread_linux.cc',
    ])
    if is_linux:
      libcxx_root = SRC_ROOT + '/buildtools/third_party/libc++/trunk'
      libcxxabi_root = SRC_ROOT + '/buildtools/third_party/libc++abi/trunk'
      cflags_cc.extend([
          '-nostdinc++',
          '-isystem' + libcxx_root + '/include',
          '-isystem' + libcxxabi_root + '/include',
      ])
      ldflags.extend(['-nodefaultlibs'])
      libs.extend([
          '-lc',
          '-lgcc_s',
          '-lm',
          '-lpthread',
      ])
      static_libraries['libc++'] = {
          'sources': [
              libcxx_root + '/src/algorithm.cpp',
              libcxx_root + '/src/any.cpp',
              libcxx_root + '/src/bind.cpp',
              libcxx_root + '/src/chrono.cpp',
              libcxx_root + '/src/charconv.cpp',
              libcxx_root + '/src/condition_variable_destructor.cpp',
              libcxx_root + '/src/condition_variable.cpp',
              libcxx_root + '/src/debug.cpp',
              libcxx_root + '/src/exception.cpp',
              libcxx_root + '/src/functional.cpp',
              libcxx_root + '/src/future.cpp',
              libcxx_root + '/src/hash.cpp',
              libcxx_root + '/src/ios.cpp',
              libcxx_root + '/src/iostream.cpp',
              libcxx_root + '/src/locale.cpp',
              libcxx_root + '/src/memory.cpp',
              libcxx_root + '/src/mutex.cpp',
              libcxx_root + '/src/new.cpp',
              libcxx_root + '/src/optional.cpp',
              libcxx_root + '/src/random.cpp',
              libcxx_root + '/src/regex.cpp',
              libcxx_root + '/src/shared_mutex.cpp',
              libcxx_root + '/src/stdexcept.cpp',
              libcxx_root + '/src/string.cpp',
              libcxx_root + '/src/strstream.cpp',
              libcxx_root + '/src/system_error.cpp',
              libcxx_root + '/src/thread.cpp',
              libcxx_root + '/src/typeinfo.cpp',
              libcxx_root + '/src/utility.cpp',
              libcxx_root + '/src/valarray.cpp',
              libcxx_root + '/src/variant.cpp',
              libcxx_root + '/src/vector.cpp',
          ],
          'tool': 'cxx',
          'cflags': cflags + [
              '-D_LIBCPP_NO_EXCEPTIONS',
              '-D_LIBCPP_BUILDING_LIBRARY',
              '-DLIBCXX_BUILDING_LIBCXXABI',
          ]
      }
      static_libraries['libc++abi'] = {
          'sources': [
              libcxxabi_root + '/src/abort_message.cpp',
              libcxxabi_root + '/src/cxa_aux_runtime.cpp',
              libcxxabi_root + '/src/cxa_default_handlers.cpp',
              libcxxabi_root + '/src/cxa_demangle.cpp',
              libcxxabi_root + '/src/cxa_exception_storage.cpp',
              libcxxabi_root + '/src/cxa_guard.cpp',
              libcxxabi_root + '/src/cxa_handlers.cpp',
              libcxxabi_root + '/src/cxa_noexception.cpp',
              libcxxabi_root + '/src/cxa_unexpected.cpp',
              libcxxabi_root + '/src/cxa_vector.cpp',
              libcxxabi_root + '/src/cxa_virtual.cpp',
              libcxxabi_root + '/src/fallback_malloc.cpp',
              libcxxabi_root + '/src/private_typeinfo.cpp',
              libcxxabi_root + '/src/stdlib_exception.cpp',
              libcxxabi_root + '/src/stdlib_stdexcept.cpp',
              libcxxabi_root + '/src/stdlib_typeinfo.cpp',
          ],
          'tool': 'cxx',
          'cflags': cflags + [
              '-DLIBCXXABI_SILENT_TERMINATE',
              '-D_LIBCXXABI_NO_EXCEPTIONS',
          ]
      }
      static_libraries['base']['sources'].extend([
        'lib/base/allocator/allocator_shim.cc',
        'lib/base/allocator/allocator_shim_default_dispatch_to_glibc.cc',
      ])
      libs.extend(['-lrt', '-latomic'])
      static_libraries['libevent']['include_dirs'].extend([
          os.path.join(SRC_ROOT, 'lib', 'base', 'third_party', 'libevent', 'linux')
      ])
      static_libraries['libevent']['sources'].extend([
         'lib/base/third_party/libevent/epoll.c',
      ])
    else:
      ldflags.extend(['-pthread'])
      libs.extend(['-lrt'])
      static_libraries['base']['sources'].extend([
          'lib/base/process/internal_aix.cc'
      ])
      static_libraries['libevent']['include_dirs'].extend([
          os.path.join(SRC_ROOT, 'base', 'third_party', 'libevent', 'aix')
      ])
      static_libraries['libevent']['include_dirs'].extend([
          os.path.join(SRC_ROOT, 'base', 'third_party', 'libevent', 'compat')
      ])

  if is_mac:
    static_libraries['base']['sources'].extend([
        'lib/base/base_paths_mac.mm',
        'lib/base/files/file_util_mac.mm',
        'lib/base/mac/bundle_locations.mm',
        'lib/base/mac/call_with_eh_frame.cc',
        'lib/base/mac/call_with_eh_frame_asm.S',
        'lib/base/mac/foundation_util.mm',
        'lib/base/mac/mach_logging.cc',
        'lib/base/mac/scoped_mach_port.cc',
        'lib/base/mac/scoped_mach_vm.cc',
        'lib/base/mac/scoped_nsautorelease_pool.mm',
        'lib/base/memory/shared_memory_handle_mac.cc',
        'lib/base/memory/shared_memory_mac.cc',
        'lib/base/memory/platform_shared_memory_region_mac.cc',
        'lib/base/message_loop/message_pump_mac.mm',
        'lib/base/process/process_handle_mac.cc',
        'lib/base/process/process_info_mac.cc',
        'lib/base/process/process_iterator_mac.cc',
        'lib/base/process/process_metrics_mac.cc',
        'lib/base/strings/sys_string_conversions_mac.mm',
        'lib/base/synchronization/waitable_event_mac.cc',
        'lib/base/sys_info_mac.mm',
        'lib/base/time/time_exploded_posix.cc',
        'lib/base/time/time_mac.cc',
        'lib/base/threading/platform_thread_mac.mm',
    ])
    static_libraries['libevent']['include_dirs'].extend([
        os.path.join(SRC_ROOT, 'base', 'third_party', 'libevent', 'mac')
    ])
    static_libraries['libevent']['sources'].extend([
        'lib/base/third_party/libevent/kqueue.c',
    ])

    libs.extend([
        '-framework', 'AppKit',
        '-framework', 'CoreFoundation',
        '-framework', 'Foundation',
        '-framework', 'Security',
    ])

  if is_win:
    static_libraries['base']['sources'].extend([
        "base/allocator/partition_allocator/address_space_randomization.cc",
        'lib/base/allocator/partition_allocator/page_allocator.cc',
        "base/allocator/partition_allocator/spin_lock.cc",
        'lib/base/base_paths_win.cc',
        'lib/base/cpu.cc',
        'lib/base/debug/close_handle_hook_win.cc',
        'lib/base/debug/debugger.cc',
        'lib/base/debug/debugger_win.cc',
        'lib/base/debug/profiler.cc',
        'lib/base/debug/stack_trace_win.cc',
        'lib/base/file_version_info_win.cc',
        'lib/base/files/file_enumerator_win.cc',
        'lib/base/files/file_path_watcher_win.cc',
        'lib/base/files/file_util_win.cc',
        'lib/base/files/file_win.cc',
        'lib/base/files/memory_mapped_file_win.cc',
        'lib/base/guid.cc',
        'lib/base/logging_win.cc',
        'lib/base/memory/memory_pressure_monitor_win.cc',
        'lib/base/memory/shared_memory_handle_win.cc',
        'lib/base/memory/shared_memory_win.cc',
        'lib/base/memory/platform_shared_memory_region_win.cc',
        'lib/base/message_loop/message_pump_win.cc',
        'lib/base/native_library_win.cc',
        'lib/base/power_monitor/power_monitor_device_source_win.cc',
        'lib/base/process/kill_win.cc',
        'lib/base/process/launch_win.cc',
        'lib/base/process/memory_win.cc',
        'lib/base/process/process_handle_win.cc',
        'lib/base/process/process_info_win.cc',
        'lib/base/process/process_iterator_win.cc',
        'lib/base/process/process_metrics_win.cc',
        'lib/base/process/process_win.cc',
        'lib/base/profiler/native_stack_sampler_win.cc',
        'lib/base/profiler/win32_stack_frame_unwinder.cc',
        'lib/base/rand_util_win.cc',
        'lib/base/strings/sys_string_conversions_win.cc',
        'lib/base/sync_socket_win.cc',
        'lib/base/synchronization/condition_variable_win.cc',
        'lib/base/synchronization/lock_impl_win.cc',
        'lib/base/synchronization/waitable_event_watcher_win.cc',
        'lib/base/synchronization/waitable_event_win.cc',
        'lib/base/sys_info_win.cc',
        'lib/base/threading/platform_thread_win.cc',
        'lib/base/threading/thread_local_storage_win.cc',
        'lib/base/time/time_win.cc',
        'lib/base/timer/hi_res_timer_manager_win.cc',
        'lib/base/trace_event/heap_profiler_allocation_register_win.cc',
        'lib/base/trace_event/trace_event_etw_export_win.cc',
        'lib/base/win/core_winrt_util.cc',
        'lib/base/win/enum_variant.cc',
        'lib/base/win/event_trace_controller.cc',
        'lib/base/win/event_trace_provider.cc',
        'lib/base/win/i18n.cc',
        'lib/base/win/iat_patch_function.cc',
        'lib/base/win/iunknown_impl.cc',
        'lib/base/win/message_window.cc',
        'lib/base/win/object_watcher.cc',
        'lib/base/win/pe_image.cc',
        'lib/base/win/process_startup_helper.cc',
        'lib/base/win/registry.cc',
        'lib/base/win/resource_util.cc',
        'lib/base/win/scoped_bstr.cc',
        'lib/base/win/scoped_com_initializer.cc',
        'lib/base/win/scoped_handle.cc',
        'lib/base/win/scoped_handle_verifier.cc',
        'lib/base/win/scoped_process_information.cc',
        'lib/base/win/scoped_variant.cc',
        'lib/base/win/scoped_winrt_initializer.cc',
        'lib/base/win/shortcut.cc',
        'lib/base/win/startup_information.cc',
        'lib/base/win/wait_chain.cc',
        'lib/base/win/win_util.cc',
        'lib/base/win/windows_version.cc',
        'lib/base/win/wrapped_window_proc.cc',
    ])

    libs.extend([
        'advapi32.lib',
        'dbghelp.lib',
        'kernel32.lib',
        'ole32.lib',
        'shell32.lib',
        'user32.lib',
        'userenv.lib',
        'version.lib',
        'winmm.lib',
        'ws2_32.lib',
        'Shlwapi.lib',
    ])

  # we just build static libraries that GN needs
  executables['jabberwock_gen']['libs'].extend(static_libraries.keys())

  write_generic_ninja(path, static_libraries, executables, cc, cxx, ar, ld,
                      cflags, cflags_cc, ldflags, include_dirs, libs)

def build_gn_with_gn(temp_gn, build_dir, options):
  gn_gen_args = options.gn_gen_args or ''
  if not options.debug:
    gn_gen_args += ' is_debug=false'
  cmd = [temp_gn, build_dir, 'jabberwock_gen', '--args=%s' % gn_gen_args,
          "--root="+SRC_ROOT
         ]
  print(cmd)
  check_call(cmd)

  cmd = ['ninja', '-C', build_dir, '-w', 'dupbuild=err']
  if options.verbose:
    cmd.append('-v')
  cmd.append('jabberwock_gen')
  #cmd.append('gn')
  print(cmd)
  check_call(cmd)

  # build.ninja currently refers back to gn from the temporary directory.
  # Regenerate the build files using the gn we just built so that the reference
  # gets updated to "./jabberwock_gen".
  cmd = [os.path.join(build_dir, 'jabberwock_gen'), build_dir, 'jabberwock_gen',
         '--args=%s' % gn_gen_args]
  #cmd = [os.path.join(build_dir, 'gn'), 'gen', build_dir,
  #       '--args=%s' % gn_gen_args]
  print(cmd)
  check_call(cmd)

  #if not options.debug and not is_win:
  #  check_call(['strip', os.path.join(build_dir, 'gn')])

  if not options.debug and not is_win:
    check_call(['strip', os.path.join(build_dir, 'jabberwock_gen')])


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
