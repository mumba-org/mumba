# The functions in this file let the vendors build and copy tools/libraries
# that they may find necessary for their products.

from files_to_include import DLLS, WINDOWS_BUILDABLE_DLLS, BINARIES, VS_PROJECTS_FROM_CMAKE


def build_dlls(crosvm_root, mode, job_type = "local", features=[]):
    pass


def copy_dlls(crosvm_root, target_paths, mode):
    pass
