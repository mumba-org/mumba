#include "AppxPackaging.hpp"
#include "MSIXWindows.hpp"

#include <iostream>

#include "Helpers.hpp"

using namespace MsixSample::Helper;

int main(int argc, char* argv[])
{
  if (argc != 3) {
    printf("error: missing args [input.bundle] [/output/path]\n");
    return 1;
  }

  MSIX_VALIDATION_OPTION validation = MSIX_VALIDATION_OPTION_SKIPSIGNATURE;
  //MSIX_PACKUNPACK_OPTION packUnpack = MSIX_PACKUNPACK_OPTION_UNPACKWITHFLATSTRUCTURE;
  //MSIX_PACKUNPACK_OPTION packUnpack = MSIX_PACKUNPACK_OPTION_NONE;
  MSIX_PACKUNPACK_OPTION packUnpack = MSIX_PACKUNPACK_OPTION_CREATEPACKAGESUBFOLDER;
  MSIX_APPLICABILITY_OPTIONS applicability = MSIX_APPLICABILITY_OPTION_FULL;

  HRESULT actual = UnpackBundle(packUnpack,
                                validation,
                                applicability,
                                const_cast<char*>(argv[1]),
                                const_cast<char*>(argv[2]));
    
  return actual;
}