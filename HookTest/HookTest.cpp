/*
Copyright (c) 2015, Nettitude
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
THE POSSIBILITY OF SUCH DAMAGE.
*/
#include <windows.h>
#include "HookEngine.h"

HOOKCONTEXT* g_pMessageABoxHook = NULL;

typedef int (WINAPI *fpUserMessageBoxA)(
                                        HWND hWnd,
                                        LPCSTR lpText,
                                        LPCSTR lpCaption,
                                        UINT uType
                                       );

int
WINAPI
UserMessageBoxA(
                 HWND hWnd,
                 LPCSTR lpText,
                 LPCSTR lpCaption,
                 UINT uType
               )
{

    static const LPCSTR pMyText = "All your message belong to us!";

    if (g_pMessageABoxHook)
    {
        //call function
        return ((fpUserMessageBoxA)(g_pMessageABoxHook->pTrampoline))(hWnd, pMyText, lpCaption, uType);
    }

    return 0;
}

int main(int argc, char** argv)
{
    LPVOID pTarget = &MessageBoxA;
    LPVOID pUser = &UserMessageBoxA;

    if (HOOK_SUCCESS == HookEngine_Init())
    {
        if (HOOK_SUCCESS == HookEngine_InstallHook(pTarget, pUser, &g_pMessageABoxHook))
        {
            ::MessageBoxA(NULL, "XXXXXXXXXX", "Hello!", MB_OK);

            if (HOOK_SUCCESS == HookEngine_RemoveHook(g_pMessageABoxHook))
            {
                ::MessageBoxA(NULL, "Not Hooked", "Hello!", MB_OK);
                g_pMessageABoxHook = NULL;
            }
        }

        HookEngine_Shutdown();
    }
    return 0;
}