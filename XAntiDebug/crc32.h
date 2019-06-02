#if !defined(__crc32cr_table_h__)
#define __crc32cr_table_h__

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

//内存循环冗余校验
unsigned int crc32(const void *buffer, unsigned int len);
//读取循环冗余校验检测
BOOL CRC32File(LPCTSTR lpszFileName, unsigned char digest[16]);

#endif
