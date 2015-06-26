#include "printer.h"

#include <stdio.h>
#include <stdarg.h>

#define START_PAD   "   "

#define P_ERROR     "E> "
#define P_WARNING   "W> "
#define P_INFO      "I> "
#define P_OUTPUT    "O> "

int write_level = 0;

int write_raise_level()
{
    return write_level++;
}

int write_lower_level()
{
    return write_level--;
}

int write_set_level(int level)
{
    int old = write_level;
    
    write_level = level;
    
    return old;
}

int write_get_level()
{
    return write_level;
}

void write_out(int type, const char* format, ...)
{
    FILE* out_stream;
    int i;
    const char* prefix = 0;
    
    va_list args;
    va_start(args, format);
    
    switch(type)
    {
        case PRINT_OUTPUT:
            prefix = P_OUTPUT;
            out_stream = stdout;
            break;
        case PRINT_ERROR:
            prefix = P_ERROR;
            out_stream = stderr;
            break;
        case PRINT_WARNING:
            out_stream = stderr;
            prefix = P_WARNING;
            break;
        case PRINT_INFO:
            out_stream = stderr;
            prefix = P_INFO;
            break;
        default:
            out_stream = stderr;
            prefix = P_INFO;
            break;
    }
    
    for (i = 0; i < write_level; ++i)
        fprintf(out_stream, START_PAD);
    
    fprintf(out_stream, "%s", prefix);
    vfprintf(out_stream, format, args);
    fprintf(out_stream, "\n");
    
    va_end(args);
}