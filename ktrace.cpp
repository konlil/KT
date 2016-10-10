#define UNW_LOCAL_ONLY
#include "libunwind.h"

#include "signal.h"
#include "ucontext.h"
#include <vector>
#include "sys/types.h"
#include "sys/stat.h"
#include "fcntl.h"
#include "unistd.h"
#include "ucontext.h"
#include "link.h"
#include "stdlib.h"
#include <stdio.h>
#include <string>
#include <vector>

#include "foundation.h"
#include "ktrace.h"

namespace ktrace{

LogHandler g_log;
//#define LOG(arg...) { if(g_log) g_log(arg); }

int recurcount = 0;

int g_sample_interval = 0;
int g_trace_cnt = 0;
unsigned char *g_buffer = 0;
unsigned int g_buffer_size = 20*1024*1024;
unsigned char *g_cursor = 0;

unsigned int g_so_address = 0;

size_t encodeVarint(int value, unsigned char* output)
{
    size_t outputSize = 0;
    while(value > 127) {
        output[outputSize] = ((unsigned char)(value & 127)) | 128;
        value >>= 7;
        outputSize ++;
    }
    output[outputSize++] = ((unsigned char)value)&127;
    return outputSize;
}

int decodeVarint(unsigned char* input, size_t inputSize)
{
    int ret = 0;
    for(size_t i=0; i<inputSize; ++i)
    {
        ret |= (input[i] & 127) << (7*i);
        if(!(input[i]&128)) {
            break;
        }
    }
    return ret;
}


void show_backtrace(void*);

void mySigAction(int iSignal, siginfo_t *psSigInfo, void* pvContext)
{
    if(recurcount > 0) return;
    recurcount += 1;

    show_backtrace(pvContext);

    recurcount -= 1;
}

#if 0
unsigned int get_so_addr()
{
    FILE *file = fopen("/proc/self/maps", "rt");
    if (file == NULL)
    {
        return 0;
    }
    unsigned int addr = 0;
    const char *libraryName = "libclient";
    int len_libname = strlen(libraryName);
    char buff[256];
    while (fgets(buff, sizeof(buff), file) != NULL)
    {
        nfd::Logger::TraceLine("----: %s\n", buff);
        if (strstr(buff, libraryName))
        {
            unsigned int start, end, offset;
            char flags[4];
            if (sscanf(buff, "%zx-%zx %c%c%c%c %zx", &start, &end, &flags[0], &flags[1], &flags[2], &flags[3], &offset) != 7)
            {
                continue;
            }

            if (flags[0] == 'r' && flags[1] == '-' && flags[2] == 'x')
            {
                addr = start - offset;
                break;
            }
        }

    } // while

    fclose(file);
    return addr;
}
#endif

void init_trace_timer()
{
    struct sigaction sSigAction;
    struct sigaction sOldSigAction;
    struct itimerval sTimerValue;
    struct itimerval sOldTimerValue;
    sSigAction.sa_flags = SA_SIGINFO;
    sSigAction.sa_sigaction = mySigAction;
    sigemptyset(&sSigAction.sa_mask);
    sigaction(SIGPROF, &sSigAction, &sOldSigAction);
    /*sTimerValue.it_value.tv_sec = 0;
    sTimerValue.it_value.tv_usec = 1000;
    sTimerValue.it_interval.tv_sec = 0;
    sTimerValue.it_interval.tv_usec = 50000;
    setitimer(ITIMER_PROF, &sTimerValue, &sOldTimerValue);
    */
}

void start_trace_timer(int32_t interval_ms, int32_t max_timespan_sec)
{
    struct itimerval sTimerValue;
    struct itimerval sOldTimerValue;

    g_sample_interval = interval_ms;

    sTimerValue.it_value.tv_sec = 1;
    sTimerValue.it_value.tv_usec = 0;
    sTimerValue.it_interval.tv_sec = 0;
    sTimerValue.it_interval.tv_usec = interval_ms*1000;
    setitimer(ITIMER_PROF, &sTimerValue, &sOldTimerValue);
}

void stop_trace_timer()
{
    struct itimerval sTimerValue;
    struct itimerval sOldTimerValue;
    memset(&sTimerValue, 0, sizeof(sTimerValue));
    setitimer(ITIMER_PROF, &sTimerValue, &sOldTimerValue);
}

void show_backtrace (void* pvContext)
{
    int collected = (int)(g_cursor-g_buffer);
    if(collected >= g_buffer_size)
        return;

    unw_cursor_t cursor; unw_context_t uc;
    unw_word_t ip, sp, offp;

    ucontext_t *context = (ucontext_t*)pvContext;
    unw_tdep_context_t *unw_ctx = (unw_tdep_context_t*)&uc;
    sigcontext* sig_ctx = &context->uc_mcontext;

    unw_ctx->regs[UNW_ARM_R0] = sig_ctx->arm_r0;
    unw_ctx->regs[UNW_ARM_R1] = sig_ctx->arm_r1;
    unw_ctx->regs[UNW_ARM_R2] = sig_ctx->arm_r2;
    unw_ctx->regs[UNW_ARM_R3] = sig_ctx->arm_r3;
    unw_ctx->regs[UNW_ARM_R4] = sig_ctx->arm_r4;
    unw_ctx->regs[UNW_ARM_R5] = sig_ctx->arm_r5;
    unw_ctx->regs[UNW_ARM_R6] = sig_ctx->arm_r6;
    unw_ctx->regs[UNW_ARM_R7] = sig_ctx->arm_r7;
    unw_ctx->regs[UNW_ARM_R8] = sig_ctx->arm_r8;
    unw_ctx->regs[UNW_ARM_R9] = sig_ctx->arm_r9;
    unw_ctx->regs[UNW_ARM_R10] = sig_ctx->arm_r10;
    unw_ctx->regs[UNW_ARM_R11] = sig_ctx->arm_fp;
    unw_ctx->regs[UNW_ARM_R12] = sig_ctx->arm_ip;
    unw_ctx->regs[UNW_ARM_R13] = sig_ctx->arm_sp;
    unw_ctx->regs[UNW_ARM_R14] = sig_ctx->arm_lr;
    unw_ctx->regs[UNW_ARM_R15] = sig_ctx->arm_pc;

    //nfd::Logger::TraceLine("base pc = %lx\n", (void*)sig_ctx->arm_pc);

    //unw_getcontext(&uc);
    int result = unw_init_local(&cursor, &uc);
    if(result != 0){
        return;
    }

    g_trace_cnt ++;

    void* depth_ptr = (void*)g_cursor;
    g_cursor += 4;
    int depth = 0;
    while (unw_step(&cursor) > 0)
    {
        //unw_get_proc_name(&cursor, name, 256, &offp);
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        //unw_get_reg(&cursor, UNW_REG_SP, &sp);

        *((long*)g_cursor) = (long)ip;
        depth ++;
        g_cursor += sizeof(long);
    }
    *((int*)depth_ptr) = depth;
}

bool dump_trace2(const std::string& outname)
{
    FILE* fout = fopen(outname.c_str(), "wb");
    if( fout == NULL )
        return false;

    fwrite(&g_sample_interval, sizeof(g_sample_interval), 1, fout);
    fwrite(&g_trace_cnt, sizeof(g_trace_cnt), 1, fout);
    fwrite(g_buffer, 1, (int)(g_cursor-g_buffer), fout);

    FILE* fin = fopen("/proc/self/maps", "rt");
    if (fin == NULL)
        return false;

    //7-bit encode file size
    int lSize = 0;
    char buff[256] = {0};
    while (fgets(buff, sizeof(buff), fin) != NULL)
    {
        lSize += strlen(buff);
        memset(buff, 0, 256);
    }
    rewind(fin);
    unsigned char eOut[8] = {0};
    size_t eSize = encodeVarint(lSize, eOut);
    fwrite(eOut, 1, eSize, fout);

    //cat file 
    memset(buff, 0, 256);
    while (fgets(buff, sizeof(buff), fin) != NULL)
    {
        fputs(buff, fout);
    }
    fclose(fin);
    fclose(fout);
    return true;
}

#if 0
bool dump_trace(const std::string& outname)
{
    int fd = open(outname.c_str(), O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
    if(fd == -1)
        return false;

    static char tmp[64] = {0};
    sprintf(tmp, "addr: %x", g_so_address);
    write(fd, tmp, strlen(tmp));
    write(fd, "\n", 1);
    for(int n=0; n<g_trace_cnt; ++n)
    {
        BackTrace& trace = g_traces[n];
        memset(tmp, 0, 64);
        sprintf(tmp, "%d ", trace.depth);
        write(fd, tmp, strlen(tmp));
        for(int i=0; i<trace.depth; ++i)
        {
            memset(tmp, 0, 64);
            sprintf(tmp, "%lx ", trace.callstack[i]);
            write(fd, tmp, strlen(tmp));
        }
        write(fd, "\n", 1);
    }

    fsync(fd);
    close(fd);

    g_trace_cnt = 0;
    delete[] g_traces;
    g_traces = 0;
    return true;
}
#endif

bool Start(int32_t interval_ms, int32_t max_timespan_sec)
{
    if(g_buffer == NULL && g_buffer_size > 0)
    {
        int i=5;
        while((i--)> 0){
            g_buffer = (unsigned char*)malloc(g_buffer_size);
            if(g_buffer)break; 
        }
    }

    if(g_buffer == NULL)
    {
        nfd::Logger::TraceLine("===Preallocate memory for ktrace failed !!!");
        return false;
    }

    memset(g_buffer, 0, g_buffer_size);
    g_cursor = g_buffer;
    g_trace_cnt = 0;
    
    start_trace_timer(interval_ms, max_timespan_sec);
    return true;
}

bool Stop(const std::string& outname)
{
    if(g_buffer == NULL)
        return false;

    stop_trace_timer();
    nfd::Logger::TraceLine("===Trace timer stopped.");
    nfd::Logger::TraceLine("===Dump trace(%d samples) to: %s\n", g_trace_cnt, outname.c_str());
    //bool rtn = dump_trace(outname);
    bool rtn = dump_trace2(outname);
    nfd::Logger::TraceLine("===Dump done.");
    return rtn;
}

void SetLogHandler(LogHandler log_handler)
{
}


}//namespace ktrace