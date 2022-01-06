#include "getprogname.h"
#include <string.h>

extern char *__progname;

const char *
getprogname(void)
{
  return __progname;
}