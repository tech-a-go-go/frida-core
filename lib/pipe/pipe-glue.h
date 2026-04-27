#ifndef __SUNDAY_PIPE_GLUE_H__
#define __SUNDAY_PIPE_GLUE_H__

#include "frida-pipe.h"

#define SUNDAY_TYPE_WINDOWS_PIPE_INPUT_STREAM (sunday_windows_pipe_input_stream_get_type ())
#define SUNDAY_TYPE_WINDOWS_PIPE_OUTPUT_STREAM (sunday_windows_pipe_output_stream_get_type ())

G_DECLARE_FINAL_TYPE (SundayWindowsPipeInputStream, sunday_windows_pipe_input_stream, SUNDAY, WINDOWS_PIPE_INPUT_STREAM, GInputStream)
G_DECLARE_FINAL_TYPE (SundayWindowsPipeOutputStream, sunday_windows_pipe_output_stream, SUNDAY, WINDOWS_PIPE_OUTPUT_STREAM, GOutputStream)

#endif
