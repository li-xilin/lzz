#ifndef LZZ_H
#define LZZ_H

#include <windef.h>

BOOL LZZ_Init(VOID);

VOID LZZ_Exit(VOID);

BOOL LZZ_Unpack(LPCWSTR pwzSourceFile, LPCWSTR pwzDestPath);

BOOL LZZ_Pack(LPCWSTR pwzSourceList[], LPCWSTR pwzDestFile);

#endif
