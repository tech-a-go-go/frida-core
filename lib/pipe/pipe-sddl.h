#ifndef __SUNDAY_PIPE_SDDL_H__
#define __SUNDAY_PIPE_SDDL_H__

#define VC_EXTRALEAN
#include <windows.h>
#undef VC_EXTRALEAN

LPCWSTR sunday_pipe_get_sddl_string_for_pipe (void);

#endif
