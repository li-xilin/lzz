#ifndef LZZ_H
#define LZZ_H

#include <ax/uchar.h>
#include <stdbool.h>

int lzz_pack(const ax_uchar *const files[], const ax_uchar *zip_file);

int lzz_unpack(const ax_uchar *zip_file, const ax_uchar *path, bool test);

#endif
