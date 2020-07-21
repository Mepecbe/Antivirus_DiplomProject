#pragma once
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <winioctl.h>
#include <string.h>
#include <crtdbg.h>
#include <assert.h>
#include <fltuser.h>
#include <stdio.h>
#include <thread>
#include <conio.h>
#include <tchar.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "fltlib.lib")
//#pragma comment(lib, "fltmgr.lib")

using namespace System;

#pragma managed
[assembly:CLSCompliant(true)];

namespace MODULE__DRIVER_CONNECTOR {
	[CLSCompliant(true)]
	ref class Initializator
	{
		public : static byte EntryPoint() {
			return 0;
		}
	};

	
}

