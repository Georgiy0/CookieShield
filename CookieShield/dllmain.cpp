// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "CookieShield.h"

// This is the plugin entry point.
// Each plugin should implement this function.
// Plugin logic should be implemented in a class that implements
// IPlugin interface.
extern "C" __declspec (dllexport) IPlugin* GetPlugin()
{
	IPlugin* plugin = new AVCookieShield();
	return plugin;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

