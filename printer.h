#ifndef __PRINTER_H
#define __PRINTER_H

#define PRINT_INFO      0
#define PRINT_WARNING   1
#define PRINT_ERROR     2
#define PRINT_OUTPUT    3

void write_out(int type, const char* format, ...);

//returns previous level
int write_raise_level();
int write_lower_level();
int write_set_level(int level);
int write_get_level();

#endif
