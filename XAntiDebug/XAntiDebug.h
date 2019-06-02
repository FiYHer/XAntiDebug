//Author:Xjun

#ifndef _XANTIDEBUG_H
#define _XANTIDEBUG_H

#define _CRT_SECURE_NO_WARNINGS

#include <vector>
#include <windows.h>
#include <ImageHlp.h>
#include <Shlwapi.h>
#include <Softpub.h>
#include <wintrust.h>
#include <tchar.h>

#include "ldasm.h"
#include "crc32.h"

//
// if it is a 64 bit program, this file does not need to include
// 64位程序不需要包含
#ifndef _WIN64
#include "wow64ext.h"
#endif 

#pragma comment(lib,"Shlwapi.lib")
#pragma comment(lib,"ImageHlp.lib")
#pragma comment(lib,"wintrust.lib")

//
// flags
//
#define FLAG_CHECKSUM_NTOSKRNL               (0x0001)
#define FLAG_CHECKSUM_CODESECTION            (0x0002)
#define FLAG_DETECT_DEBUGGER                 (0x0004)
#define FLAG_DETECT_HARDWAREBREAKPOINT       (0x0008)
#define FLAG_FULLON                          (FLAG_CHECKSUM_NTOSKRNL | FLAG_CHECKSUM_CODESECTION | \
                                              FLAG_DETECT_DEBUGGER | FLAG_DETECT_HARDWAREBREAKPOINT)
//
// error status【错误状态】
//
typedef enum _XAD_STATUS
{
	XAD_OK,//没有发生错误
	XAD_ERROR_OPENNTOS,//NtQueryInformationProcess操作失败
	XAD_ERROR_MODULEHANDLE,//内存模块读取错误,不是一个有效的PE文件
	XAD_ERROR_OPENNTDLL,
	XAD_ERROR_NTAPI,
	XAD_ERROR_ALLOCMEM,
	XAD_ERROR_FILEOFFSET
}XAD_STATUS;

//
// the system directly calls the function definition -> NtQueryInfomationProcess
//
typedef DWORD64(WINAPI* fn_SysCall64)(
	DWORD64 processHandle,
	DWORD64 processClass,
	PDWORD64 processInfo,
	DWORD64 length,
	PDWORD64 returnLength);

typedef DWORD(WINAPI* fn_SysCall32)(
	DWORD processHandle,
	DWORD processClass,
	PDWORD processInfo,
	DWORD length,
	PDWORD returnLength);

//
// code section checksum struct
// 代码段校验结构体
//
typedef struct _CODE_CRC32
{
	PVOID         m_va;
	DWORD         m_size;
	DWORD         m_crc32;
}CODE_CRC32;

//
// implement class
//
class XAntiDebug
{

public:
	//1.当前程序的实例句柄
	//2.模式标志位
	XAntiDebug(HMODULE moduleHandle, DWORD flags);
	~XAntiDebug();

	//
	// XAntiDebug initialize
	//
	XAD_STATUS XAD_Initialize();

	//
	// execute detect
	//
	BOOL XAD_ExecuteDetect();

	//
	//VEH need it
	//
	BOOL                     _isSetHWBP;
	BOOL                     _isLoadStrongOD;

private:

	HMODULE                  _moduleHandle;//当前程序的实例
	DWORD                    _flags;//当前保护模式

	BOOL                     _initialized;//是否完成初始化
	DWORD                    _major;//主系统版本号
	DWORD                    _minor;//次系统版本号
	BOOL                     _isArch64;//是否64位处理器
	BOOL                     _isWow64;
	BOOL                     _isWow64FsReDriectory;//是否在wow64目录下操作

	DWORD                    _pageSize;//当前系统内存页的大小，通常4kb
	PVOID                    _pagePtr;
	DWORD                    _pageCrc32;

	CHAR                     _ntosPath[MAX_PATH];
	std::vector<CODE_CRC32>  _codeCrc32;

	DWORD64                  _MyQueryInfomationProcess;
	DWORD                    _eax;
	fn_SysCall32             _pfnSyscall32;
	fn_SysCall64             _pfnSyscall64;
};

#endif