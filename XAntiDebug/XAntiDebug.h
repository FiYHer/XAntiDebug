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
// 64λ������Ҫ����
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
// error status������״̬��
//
typedef enum _XAD_STATUS
{
	XAD_OK,//û�з�������
	XAD_ERROR_OPENNTOS,//NtQueryInformationProcess����ʧ��
	XAD_ERROR_MODULEHANDLE,//�ڴ�ģ���ȡ����,����һ����Ч��PE�ļ�
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
// �����У��ṹ��
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
	//1.��ǰ�����ʵ�����
	//2.ģʽ��־λ
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

	HMODULE                  _moduleHandle;//��ǰ�����ʵ��
	DWORD                    _flags;//��ǰ����ģʽ

	BOOL                     _initialized;//�Ƿ���ɳ�ʼ��
	DWORD                    _major;//��ϵͳ�汾��
	DWORD                    _minor;//��ϵͳ�汾��
	BOOL                     _isArch64;//�Ƿ�64λ������
	BOOL                     _isWow64;
	BOOL                     _isWow64FsReDriectory;//�Ƿ���wow64Ŀ¼�²���

	DWORD                    _pageSize;//��ǰϵͳ�ڴ�ҳ�Ĵ�С��ͨ��4kb
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