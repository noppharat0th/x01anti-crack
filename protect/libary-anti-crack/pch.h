#ifndef PCH_H
#define PCH_H

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#define VC_EXTRALEAN
#define _WIN32_WINNT  0x0601   // Windows 7 minimum
#define WINVER        0x0601
#include <windows.h>

#include <wininet.h>

#include <winreg.h>

#include <winioctl.h>

#include <comdef.h>
#include <wbemidl.h>

#include <intrin.h>
#include <immintrin.h>

#include <imagehlp.h>

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cassert>

#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")

#include "framework.h"

#endif // PCH_H
