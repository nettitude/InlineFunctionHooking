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
#ifndef __HOOKENGINE_H__
#define __HOOKENGINE_H__

#include <Windows.h>

#if defined(__cplusplus)
extern "C" {
#endif

    typedef HRESULT HOOKRESULT;


#define HOOK_SUCCESS                          ((HOOKRESULT)(S_OK))
#define HOOK_ERROR                            ((HOOKRESULT)(-1))     //General error
#define HOOK_ERROR_INVALID_PARAMETER          ((HOOKRESULT)(-2))     //Invalid parameter specified to function call
#define HOOK_ERROR_OUT_OF_MEMORY              ((HOOKRESULT)(-3))     //Could not allocate context memory
#define HOOK_ERROR_DISASSEMBLE                ((HOOKRESULT)(-4))     //Error disassembling function bytes
#define HOOK_ERROR_MEMORY_PROTECT             ((HOOKRESULT)(-5))     //Could not set memory protection flags on target
#define HOOK_ERROR_STILL_HOOKED               ((HOOKRESULT)(-6))     //Hook still remains, on shutdown
#define HOOK_ERROR_NOT_INITIALISED            ((HOOKRESULT)(-7))     //Hook engine not initialised
#define HOOK_ERROR_EXCEPTION_RAISED           ((HOOKRESULT)(-8))     //Exception was reaised

    /**
    * Install a hook at the target function location
    * the hook will call pUserFunctionAddress
    * it is up to the user to call the trampoline if required
    */
    typedef struct HOOKCONTEXT_TAG
    {
        LPVOID pTargetFunctionAddress;
        LPVOID pUserFunctionAddress;
        LPVOID pTrampoline;

        /* Opaque structure */

    }HOOKCONTEXT, *PHOOKCONTEXT;

    /**
    * HookEngine_Init
    *
    * Initialise the hooking engine.  A corresponding call to 
    * HookEngine_Shutdown must be made 
    */
    HOOKRESULT HookEngine_Init();

    /**
    * HookEngine_Shutdown
    *
    * Shutdown the hooking engine.  Installed hooks must still be 
    * manually removed first with HookEngine_RemoveHook
    */
    HOOKRESULT HookEngine_Shutdown();


    /**
    * Install a hook at the target function location
    * the hook will call pUserFunctionAddress and it is then
    * up to the user function to call the trampoline if required.
    *
    * ppHookCtx is allocated and is an opaque structure, in that it
    * may be larger than HOOKCONTEXT
    *
    * pTargetFunctionAddress    The target function to hook
    *
    * pUserFunctionAddress      Optional user callback address. 
    *                           If NULL is specified then a trampoline is built but the function is 
    *                           not hooked.  The trampoline can be used to call the function
    *                           if it is subsequently hooked elsewhere.
    *
    * ppHookCtx                 pointer to a context that contains information about the hook
    *                           HookEngine_RemoveHook must be called to release the context and
    *                           remove any hook
    */
    HOOKRESULT HookEngine_InstallHook
        (
            IN              LPVOID         pTargetFunctionAddress, 
            IN  OPTIONAL    LPVOID         pUserFunctionAddress,
            OUT             PHOOKCONTEXT*  ppHookCtx
        );


    /**
    * Remove hook and release memory allocated to pHookCtx
    * pHookCtx is not valid after this call
    */
    HOOKRESULT HookEngine_RemoveHook
        (
            IN              PHOOKCONTEXT pHookCtx
        );


#if defined(__cplusplus)
}
#endif


#endif //__HOOKENGINE_H__