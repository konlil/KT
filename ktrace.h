#pragma once

#ifndef __KTRACE_H__
#define __KTRACE_H__
#include <stdint.h>
#include <string>

namespace ktrace
{

typedef void (*LogHandler)(int level, const char* format, ...);

void init_trace_timer();
bool Start(int32_t interval_ms, int32_t max_timespan_sec);
bool Stop(const std::string& outname);
void SetLogHandler(LogHandler log_handler);

} // namespace ktrace

#endif // __KTRACE_H__