#ifndef __SUNDAY_WINDOWS_ICON_HELPERS_H__
#define __SUNDAY_WINDOWS_ICON_HELPERS_H__

#include "frida-core.h"

#define VC_EXTRALEAN
#include <windows.h>
#undef VC_EXTRALEAN

typedef enum _SundayIconSize SundayIconSize;

enum _SundayIconSize
{
  SUNDAY_ICON_SMALL,
  SUNDAY_ICON_LARGE
};

GVariant * _sunday_icon_from_process_or_file (DWORD pid, WCHAR * filename, SundayIconSize size);

GVariant * _sunday_icon_from_process (DWORD pid, SundayIconSize size);
GVariant * _sunday_icon_from_file (WCHAR * filename, SundayIconSize size);
GVariant * _sunday_icon_from_resource_url (WCHAR * resource_url, SundayIconSize size);

GVariant * _sunday_icon_from_native_icon_handle (HICON icon, SundayIconSize size);

#endif
