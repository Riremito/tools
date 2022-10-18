#ifndef __SIMPLE__H__
#define __SIMPLE__H__

#ifndef SIMPLE_LIB
#ifndef _WIN64
#pragma comment(lib, "../Share/Simple/Simple.lib")
#else
#pragma comment(lib, "../Share/Simple/Simple64.lib")
#endif
#else
#endif

#include<Windows.h>
#include<commctrl.h>
#pragma comment(lib,"comctl32.lib")
#include<tlhelp32.h>
#include<string>
#include<vector>
#include<stdio.h>

#include"SimpleGUI.h"
#include"SimpleMemory.h"
#include"SimpleConfig.h"
#include"SimplePipe.h"
#include"SimpleInjector.h"

#define DEBUG(msg) \
{\
std::wstring wmsg = L"[Maple] ";\
wmsg += msg;\
OutputDebugStringW(wmsg.c_str());\
}

#ifdef _WIN64
#define SCANRES(msg) DEBUG(L""#msg" = " + QWORDtoString(msg))
#else
#define SCANRES(msg) DEBUG(L""#msg" = " + DWORDtoString(msg))
#endif

std::wstring BYTEtoString(BYTE b);
std::wstring WORDtoString(WORD w);
std::wstring DWORDtoString(DWORD dw);
std::wstring DatatoString(BYTE *b, ULONG_PTR Length, bool space = false);

#ifdef _WIN64
std::wstring QWORDtoString(ULONG_PTR u);
#else
#define QWORDtoString(u) DWORDtoString(u)
#endif

bool GetDir(std::wstring &wDir, std::wstring wDll = L"");

#endif