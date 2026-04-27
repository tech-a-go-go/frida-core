#include "frida-helper-backend.h"
#include "helpers/inject-context.h"

G_STATIC_ASSERT (sizeof (SundayHelperBootstrapContext) == sizeof (SundayBootstrapContext));
G_STATIC_ASSERT (sizeof (SundayHelperLoaderContext) == sizeof (SundayLoaderContext));
G_STATIC_ASSERT (sizeof (SundayHelperLibcApi) == sizeof (SundayLibcApi));
G_STATIC_ASSERT (sizeof (SundayHelperByeMessage) == sizeof (SundayByeMessage));
