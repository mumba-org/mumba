#!/usr/bin/env python3
# Copyright 2021 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

import argparse
import functools
import json
import os
import random
import subprocess
import sys
from multiprocessing import Pool
from pathlib import Path
from typing import Dict, Iterable, List, NamedTuple
import typing

import test_target
from test_target import TestTarget
import testvm
from test_config import CRATE_OPTIONS, TestOption, BUILD_FEATURES
from check_code_hygiene import (
    has_platform_dependent_code,
    has_crlf_line_endings,
)

USAGE = """\
Runs tests for crosvm locally, in a vm or on a remote device.

To build and run all tests locally:

    $ ./tools/run_tests --target=host

To cross-compile tests for aarch64 and run them on a built-in VM:

    $ ./tools/run_tests --target=vm:aarch64

The VM will be automatically set up and booted. It will remain running between
test runs and can be managed with `./tools/aarch64vm`.

Tests can also be run on a remote device via SSH. However it is your
responsiblity that runtime dependencies of crosvm are provided.

    $ ./tools/run_tests --target=ssh:hostname

The default test target can be managed with `./tools/set_test_target`

To see full build and test output, add the `-v` or `--verbose` flag.
"""

Arch = test_target.Arch

# Print debug info. Overriden by -v
VERBOSE = False

# Timeouts for tests to prevent them from running too long.
TEST_TIMEOUT_SECS = 60
LARGE_TEST_TIMEOUT_SECS = 120

# Double the timeout if the test is running in an emulation environment, which will be
# significantly slower than native environments.
EMULATION_TIMEOUT_MULTIPLIER = 2

# Number of parallel processes for executing tests.
PARALLELISM = 4

CROSVM_ROOT = Path(__file__).parent.parent.parent.resolve()
COMMON_ROOT = CROSVM_ROOT / "common"


class ExecutableResults(object):
    """Container for results of a test executable."""

    def __init__(self, name: str, success: bool, test_log: str):
        self.name = name
        self.success = success
        self.test_log = test_log


class Executable(NamedTuple):
    """Container for info about an executable generated by cargo build/test."""

    binary_path: Path
    crate_name: str
    cargo_target: str
    kind: str
    is_test: bool
    is_fresh: bool
    arch: Arch

    @property
    def name(self):
        return f"{self.crate_name}:{self.cargo_target}"


class Crate(NamedTuple):
    """Container for info about crate."""

    name: str
    path: Path


def get_workspace_excludes(target_arch: Arch):
    for crate, options in CRATE_OPTIONS.items():
        if TestOption.DO_NOT_BUILD in options:
            yield crate
        elif TestOption.DO_NOT_BUILD_X86_64 in options and target_arch == "x86_64":
            yield crate
        elif TestOption.DO_NOT_BUILD_AARCH64 in options and target_arch == "aarch64":
            yield crate
        elif TestOption.DO_NOT_BUILD_ARMHF in options and target_arch == "armhf":
            yield crate
        elif TestOption.DO_NOT_BUILD_WIN64 in options and target_arch == "win64":
            yield crate


def should_run_executable(executable: Executable, target_arch: Arch):
    options = CRATE_OPTIONS.get(executable.crate_name, [])
    if TestOption.DO_NOT_RUN in options:
        return False
    if TestOption.DO_NOT_RUN_X86_64 in options and target_arch == "x86_64":
        return False
    if TestOption.DO_NOT_RUN_AARCH64 in options and target_arch == "aarch64":
        return False
    if TestOption.DO_NOT_RUN_ARMHF in options and target_arch == "armhf":
        return False
    if TestOption.DO_NOT_RUN_ON_FOREIGN_KERNEL in options and target_arch != executable.arch:
        return False
    return True


def list_common_crates(target_arch: Arch):
    excluded_crates = list(get_workspace_excludes(target_arch))
    for path in COMMON_ROOT.glob("**/Cargo.toml"):
        if not path.parent.name in excluded_crates:
            yield Crate(name=path.parent.name, path=path.parent)


def exclude_crosvm(target_arch: Arch):
    return "crosvm" in get_workspace_excludes(target_arch)


def cargo(
    cargo_command: str, cwd: Path, flags: list[str], env: dict[str, str], build_arch: Arch
) -> Iterable[Executable]:
    """
    Executes a cargo command and returns the list of test binaries generated.

    The build log will be hidden by default and only printed if the build
    fails. In VERBOSE mode the output will be streamed directly.

    Note: Exits the program if the build fails.
    """
    cmd = [
        "cargo",
        cargo_command,
        "--message-format=json-diagnostic-rendered-ansi",
        *flags,
    ]
    if VERBOSE:
        print("$", " ".join(cmd))
    process = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
    )

    messages: List[str] = []

    # Read messages as cargo is running.
    assert process.stdout
    for line in iter(process.stdout.readline, ""):
        # any non-json line is a message to print
        if not line.startswith("{"):
            if VERBOSE:
                print(line.rstrip())
            messages.append(line.rstrip())
            continue
        json_line = json.loads(line)

        # 'message' type lines will be printed
        if json_line.get("message"):
            message = json_line.get("message").get("rendered")
            if VERBOSE:
                print(message)
            messages.append(message)

        # Collect info about test executables produced
        elif json_line.get("executable"):
            yield Executable(
                Path(json_line.get("executable")),
                crate_name=json_line.get("package_id", "").split(" ")[0],
                cargo_target=json_line.get("target").get("name"),
                kind=json_line.get("target").get("kind")[0],
                is_test=json_line.get("profile", {}).get("test", False),
                is_fresh=json_line.get("fresh", False),
                arch=build_arch,
            )

    if process.wait() != 0:
        if not VERBOSE:
            for message in messages:
                print(message)
        sys.exit(-1)


def cargo_build_executables(
    flags: list[str],
    build_arch: Arch,
    cwd: Path = Path("."),
    env: Dict[str, str] = {},
) -> Iterable[Executable]:
    """Build all test binaries for the given list of crates."""
    # Run build first, to make sure compiler errors of building non-test
    # binaries are caught.
    yield from cargo("build", cwd, flags, env, build_arch)

    # Build all tests and return the collected executables
    yield from cargo("test", cwd, ["--no-run", *flags], env, build_arch)


def build_common_crate(build_env: dict[str, str], build_arch: Arch, crate: Crate):
    print(f"Building tests for: common/{crate.name}")
    return list(cargo_build_executables([], build_arch, env=build_env, cwd=crate.path))


def build_all_binaries(target: TestTarget, build_arch: Arch):
    """Discover all crates and build them."""
    build_env = os.environ.copy()
    build_env.update(test_target.get_cargo_env(target, build_arch))

    print("Building crosvm workspace")
    yield from cargo_build_executables(
        [
            "--features=" + BUILD_FEATURES[build_arch],
            "--verbose",
            "--workspace",
            *[f"--exclude={crate}" for crate in get_workspace_excludes(build_arch)],
        ],
        build_arch,
        cwd=CROSVM_ROOT,
        env=build_env,
    )

    with Pool(PARALLELISM) as pool:
        for executables in pool.imap(
            functools.partial(build_common_crate, build_env, build_arch),
            list_common_crates(build_arch),
        ):
            yield from executables


def is_emulated(target: TestTarget, executable: Executable) -> bool:
    if target.is_host:
        # User-space emulation can run foreing-arch executables on the host.
        return executable.arch != target.arch
    elif target.vm:
        return target.vm == "aarch64"
    return False


def get_test_timeout(target: TestTarget, executable: Executable):
    large = TestOption.LARGE in CRATE_OPTIONS.get(executable.crate_name, [])
    timeout = LARGE_TEST_TIMEOUT_SECS if large else TEST_TIMEOUT_SECS
    if is_emulated(target, executable):
        return timeout * EMULATION_TIMEOUT_MULTIPLIER
    else:
        return timeout


def execute_test(target: TestTarget, executable: Executable):
    """
    Executes a single test on the given test targed

    Note: This function is run in a multiprocessing.Pool.

    Test output is hidden unless the test fails or VERBOSE mode is enabled.
    """
    options = CRATE_OPTIONS.get(executable.crate_name, [])
    args: list[str] = []
    if TestOption.SINGLE_THREADED in options:
        args += ["--test-threads=1"]

    binary_path = executable.binary_path

    if executable.arch == "win64" and executable.kind != "proc-macro" and os.name != "nt":
        args.insert(0, binary_path)
        binary_path = "wine64"


    # proc-macros and their tests are executed on the host.
    if executable.kind == "proc-macro":
        target = TestTarget("host")

    if VERBOSE:
        print(f"Running test {executable.name} on {target}...")
    try:
        # Pipe stdout/err to be printed in the main process if needed.
        test_process = test_target.exec_file_on_target(
            target,
            binary_path,
            args=args,
            timeout=get_test_timeout(target, executable),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        return ExecutableResults(
            executable.name,
            test_process.returncode == 0,
            test_process.stdout,
        )
    except subprocess.TimeoutExpired as e:
        # Append a note about the timeout to the stdout of the process.
        msg = f"\n\nProcess timed out after {e.timeout}s\n"
        return ExecutableResults(
            executable.name,
            False,
            e.stdout.decode("utf-8") + msg,
        )


def execute_all(
    executables: list[Executable],
    target: test_target.TestTarget,
    repeat: int,
):
    """Executes all tests in the `executables` list in parallel."""
    executables = [e for e in executables if should_run_executable(e, target.arch)]
    if repeat > 1:
        executables = executables * repeat
        random.shuffle(executables)

    sys.stdout.write(f"Running {len(executables)} test binaries on {target}")
    sys.stdout.flush()
    with Pool(PARALLELISM) as pool:
        for result in pool.imap(functools.partial(execute_test, target), executables):
            if not result.success or VERBOSE:
                msg = "passed" if result.success else "failed"
                print()
                print("--------------------------------")
                print("-", result.name, msg)
                print("--------------------------------")
                print(result.test_log)
            else:
                sys.stdout.write(".")
                sys.stdout.flush()
            yield result
    print()


def find_crosvm_binary(executables: list[Executable]):
    for executable in executables:
        if not executable.is_test and executable.cargo_target == "crosvm":
            return executable
    raise Exception("Cannot find crosvm executable")


def main():
    parser = argparse.ArgumentParser(usage=USAGE)
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Print all test output.",
    )
    parser.add_argument(
        "--target",
        help="Execute tests on the selected target. See ./tools/set_test_target",
    )
    parser.add_argument(
        "--arch",
        choices=typing.get_args(Arch),
        help="Target architecture to build for.",
    )
    parser.add_argument(
        "--build-only",
        action="store_true",
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=1,
        help="Repeat each test N times to check for flakes.",
    )
    args = parser.parse_args()

    global VERBOSE
    VERBOSE = args.verbose  # type: ignore
    os.environ["RUST_BACKTRACE"] = "1"

    target = (
        test_target.TestTarget(args.target) if args.target else test_target.TestTarget.default()
    )
    print("Test target:", target)

    build_arch = args.arch or target.arch
    print("Building for architecture:", build_arch)

    # Start booting VM while we build
    if target.vm:
        testvm.build_if_needed(target.vm)
        testvm.up(target.vm)

    hygiene, error = has_platform_dependent_code(Path("common/sys_util_core"))
    if not hygiene:
        print("Error: Platform dependent code not allowed in sys_util_core crate.")
        print("Offending line: " + error)
        sys.exit(-1)

    crlf_endings = has_crlf_line_endings()
    if crlf_endings:
        print("Error: Following files have crlf(dos) line encodings")
        print(*crlf_endings)
        sys.exit(-1)

    executables = list(build_all_binaries(target, build_arch))

    if args.build_only:
        print("Not running tests as requested.")
        sys.exit(0)

    # Upload dependencies plus the main crosvm binary for integration tests if the
    # crosvm binary is not excluded from testing.
    extra_files = (
        [find_crosvm_binary(executables).binary_path] if not exclude_crosvm(build_arch) else []
    )

    test_target.prepare_target(target, extra_files=extra_files)

    # Execute all test binaries
    test_executables = [e for e in executables if e.is_test]
    all_results = list(execute_all(test_executables, target, repeat=args.repeat))

    failed = [r for r in all_results if not r.success]
    if len(failed) == 0:
        print("All tests passed.")
        sys.exit(0)
    else:
        print(f"{len(failed)} of {len(all_results)} tests failed:")
        for result in failed:
            print(f"  {result.name}")
        sys.exit(-1)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as e:
        print("Command failed:", e.cmd)
        print(e.stdout)
        print(e.stderr)
        sys.exit(-1)
