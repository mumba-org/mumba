#pragma once

#if defined(COMPONENT_BUILD)
#if defined(WIN32)
#define XDRPP_EXPORT __declspec(dllexport)
#else // defined(WIN32)
#define XDRPP_EXPORT __attribute__((visibility("default")))
#endif
#else // defined(COMPONENT_BUILD)
#define XDRPP_EXPORT
#endif