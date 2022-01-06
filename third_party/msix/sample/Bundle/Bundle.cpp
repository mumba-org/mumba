#include "AppxPackaging.hpp"
#include "MSIXWindows.hpp"

#include <iostream>

#include "Helpers.hpp"

using namespace MsixSample::Helper;

int main(int argc, char* argv[])
{
  if (argc != 3) {
    printf("error: missing args [/input/path] [output.bundle]\n");
    return 1;
  }

  MSIX_BUNDLE_OPTIONS options = (MSIX_BUNDLE_OPTIONS)(MSIX_BUNDLE_OPTIONS::MSIX_OPTION_VERBOSE | MSIX_BUNDLE_OPTIONS::MSIX_OPTION_OVERWRITE | MSIX_BUNDLE_OPTIONS::MSIX_BUNDLE_OPTION_FLATBUNDLE);
  //MSIX_BUNDLE_OPTIONS options = (MSIX_BUNDLE_OPTIONS)(MSIX_BUNDLE_OPTIONS::MSIX_OPTION_VERBOSE | MSIX_BUNDLE_OPTIONS::MSIX_OPTION_OVERWRITE);

  HRESULT r = PackBundle(
    options,    
    const_cast<char*>(argv[1]),
    const_cast<char*>(argv[2]),
    nullptr,
    nullptr);
  
  return r;
}