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
#include "HookEngine.h"
#include "udis86.h"
#include <intrin.h>

#include "HookEngine.inl"

namespace nettitude
{
    //
    // CriticalSection wrapper
    //
    class CriticalSection
    {
    public:
        CriticalSection(){ InitializeCriticalSection(&m_CS); }
        ~CriticalSection(){ DeleteCriticalSection(&m_CS); }

        void Lock() { EnterCriticalSection(&m_CS); }
        void Unlock() { LeaveCriticalSection(&m_CS); }
    private:
        CriticalSection(const CriticalSection&);
        CriticalSection& operator=(const CriticalSection&);
    private:
        CRITICAL_SECTION m_CS;
    };

    //
    // Quick and dirty object to lock within scope
    //
    class ScopeLock
    {
    public:
        ScopeLock(CriticalSection& cs) : m_CS(cs){ m_CS.Lock(); }
        ~ScopeLock(){ m_CS.Unlock(); }
    private:
        ScopeLock(const ScopeLock&);
        ScopeLock& operator=(const ScopeLock&);
    private:
        CriticalSection& m_CS;
    };


    typedef LPVOID(WINAPI *fpVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI *fpVirtualFree)(LPVOID, SIZE_T, DWORD);
    typedef BOOL(WINAPI *fpVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    typedef SIZE_T(WINAPI *fpVirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);

    //
    // Number of trampolines we create during init to bounce into VirtualAlloc etc
    //
    const UINT64         InternalHookCount           = 4;

    //
    // HookEngine critical section to prevent shutdown on one thread 
    // while hooking on another
    //
    static CriticalSection g_CriticalSection;
                         
    static volatile BOOL g_Initialised               = FALSE;
    static volatile BOOL g_Initialising              = FALSE;
    static UINT64        g_HookCount                 = 0;
    static HOOKCONTEXT*  g_VirtualAllocTrampoline    = NULL;
    static HOOKCONTEXT*  g_VirtualQueryTrampoline    = NULL;
    static HOOKCONTEXT*  g_VirtualFreeTrampoline     = NULL;
    static HOOKCONTEXT*  g_VirtualProtectTrampoline  = NULL;

    //
    // pointers to VirtualAlloc etc
    // Which are set to our trampolines on init
    //
    fpVirtualAlloc       g_pVirtualAlloc = &VirtualAlloc;
    fpVirtualFree        g_pVirtualFree = &VirtualFree;
    fpVirtualProtect     g_pVirtualProtect = &VirtualProtect;
    fpVirtualQuery       g_pVirtualQuery = &VirtualQuery;


    /**
        HookEngine_SetupTargetMemProtection

        Set the target function memory to PAGE_EXECUTE_READWRITE
    */
    static BOOL HookEngine_SetupTargetMemProtection(LPVOID pTargetFunctionAddress, DWORD& oldProtection)
    {

        CONST SIZE_T                Page = 4096;
        BOOL                        result = FALSE;

        //adjust the protection to be RWE
        if (g_pVirtualProtect(pTargetFunctionAddress, Page, PAGE_EXECUTE_READWRITE, &oldProtection))
        {
            result = TRUE;
        }

        return result;
    }

    /**
        HookEngine_RestoreTargetMemProtection

        Restore the protection flags on the memory of the target function
    */
    static BOOL HookEngine_RestoreTargetMemProtection(LPVOID pTargetFunctionAddress, DWORD oldProtection)
    {
        CONST SIZE_T                Page = 4096;
        DWORD                       tmp = 0;
        BOOL                        result = FALSE;

        //adjust the protection to be RWE
        if (g_pVirtualProtect(pTargetFunctionAddress, Page, oldProtection, &tmp))
        {
            result = TRUE;
        }

        return result;
    }

    /**
        HookEngine_GetFuncionByteCount

        Obtain the minimum number of instruction bytes that need to be copied
        from the target function, in order to accomodate our jump instruction
    */
    static DWORD HookEngine_GetFuncionByteCount(DWORD cbRequired, LPVOID pTargetFunctionAddress)
    {
        CONST SIZE_T Page = 4096;

        ud_t ud_obj = { 0 };
        ud_init(&ud_obj);
#if defined(_M_IX86)
        ud_set_mode(&ud_obj, 32);
#elif defined(_M_X64)
        ud_set_mode(&ud_obj, 64);
#else
#error Unsuported platform 
#endif
        ud_set_pc(&ud_obj, uint64_t(pTargetFunctionAddress));
        ud_set_vendor(&ud_obj, UD_VENDOR_INTEL);
        ud_set_input_buffer(&ud_obj, (unsigned char*)pTargetFunctionAddress, Page);

        DWORD result = 0;
        DWORD instrlen = 0;

        do
        {
            instrlen = ud_disassemble(&ud_obj);
          
            if (instrlen)
            {
                //
                // Filter out any instructions that we simply 
                // cannot patch over with this version of the hooking
                // engine
                //
                switch (ud_obj.mnemonic)
                {
                case UD_Ija:
                case UD_Ijae:
                case UD_Ijb:
                case UD_Ijbe:
                case UD_Ijcxz:
                case UD_Ijecxz:
                case UD_Ijg:
                case UD_Ijge:
                case UD_Ijl:
                case UD_Ijle:
                case UD_Ijmp:
                case UD_Ijno:
                case UD_Ijnp:
                case UD_Ijns:
                case UD_Ijnz:
                case UD_Ijo:
                case UD_Ijp:
                case UD_Ijrcxz:
                case UD_Ijs:
                case UD_Ijz:
                {
                    //jump instruction cannot be patched
                    return INVALID_DISASSEMBLY;
                }
                break;
                case UD_Iint3:
                {
                    //don't bother patching an int3
                    return INVALID_DISASSEMBLY;
                }
                break;
                case UD_Iret:
                {
                    //function ends early
                    return INVALID_DISASSEMBLY;
                }
                break;
                default:
                break;
                }

            }

            
            
            result += instrlen;
        } while (result < cbRequired && instrlen != 0);

        if (result >= cbRequired)
        {
            return result;
        }

        return INVALID_DISASSEMBLY;
    }

    /**
        HookEngine_AllocateContextWithin2GB

        Try and allocate a context, within 2GB of the target function
        return NULL if the memory cannot be allocated.
    */
    static HOOKCONTEXT_INTERNAL* HookEngine_AllocateContextWithin2GB(DWORD contextSize, UINT_PTR pTargetFunction)
    {
        CONST UINT_PTR  twoGB = 0x7FFFFFFF;
        CONST SIZE_T   Page = 4096;
        UINT_PTR currentAddress = pTargetFunction + twoGB - Page;
        MEMORY_BASIC_INFORMATION memInfo = { 0 };
        HOOKCONTEXT_INTERNAL* pResult = NULL;

        //
        // Search infront of the terget function
        //
        do
        {
            if (g_pVirtualQuery((LPVOID)currentAddress, &memInfo, contextSize))
            {
                //if this is unallocated, then try and allocate it...
                if (memInfo.State == MEM_FREE)
                {
                    pResult = (HOOKCONTEXT_INTERNAL*)g_pVirtualAlloc((LPVOID)currentAddress, contextSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                    if (pResult)
                    {
                        //early out
                        return pResult;
                    }

                }
            }

            currentAddress -= Page;

        } while (pTargetFunction < currentAddress);

        currentAddress = pTargetFunction - twoGB + Page;

        //
        // Search behind of the terget function
        //
        do
        {
            if (g_pVirtualQuery((LPVOID)currentAddress, &memInfo, contextSize))
            {
                //if this is unallocated, then try and allocate it...
                if (memInfo.State == MEM_FREE)
                {
                    pResult = (HOOKCONTEXT_INTERNAL*)g_pVirtualAlloc((LPVOID)currentAddress, contextSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                    if (pResult)
                    {
                        //early out
                        return pResult;
                    }
                }
            }

            currentAddress += Page;

        } while (pTargetFunction > currentAddress);


        return pResult;
    }

    /**
    HookEngine_AllocateContext

    Allocates a context that can be anywhere in user space
    */
    static HOOKCONTEXT_INTERNAL* HookEngine_AllocateContext(DWORD contextSize)
    {
        CONST SIZE_T            Page    = 4096;
        HOOKCONTEXT_INTERNAL*   pResult = (HOOKCONTEXT_INTERNAL*)g_pVirtualAlloc(NULL, contextSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        return pResult;
    }

    /**
        HookEngine_Memcpy

        memcpy without calling memcpy
    */
    __forceinline void HookEngine_Memcpy(LPVOID dst, LPCVOID src, SIZE_T length)
    {
        if (dst && src && length)
        {
            __movsb((unsigned char*)dst, (const unsigned char*)src, length);
        }
    }

    /**
        HookEngine_Memset

        memset without calling memset
    */
    __forceinline void HookEngine_Memset(LPVOID dst, BYTE set, SIZE_T length)
    {
        if (dst && length)
        {
            __stosb((unsigned char*)dst, set, length);
        }
    }

    /**
        HookEngine_RelativeJumpOffset32

        calculate the relative jump offset from src function to dst function
    */
    __forceinline INT32 HookEngine_RelativeJumpOffset32(UINT_PTR src, UINT_PTR dst)
    {
        UINT_PTR ret = max(src, dst) - min(src, dst);

        if (src < dst)
        {
            return (INT32)ret - (INT32)sizeof(JMP_INSTR_86);
        }

        return -((INT32)ret - (INT32)sizeof(JMP_INSTR_86));
    }

    BOOL IsInitialised()
    {
        return g_Initialised;
    }

    BOOL IsInitialising()
    {
        return g_Initialising;
    }
}

using namespace nettitude;

/**************************************************************************
*
* HookEngine_Init
*
***************************************************************************/
extern "C" HOOKRESULT HookEngine_Init()
{
    ScopeLock lock(g_CriticalSection);
    
    if (g_Initialising)
    {
        return HOOK_ERROR;
    }

    if (g_Initialised)
    {
        return HOOK_SUCCESS;
    }

    g_Initialising = TRUE;

    if (HOOK_SUCCESS == HookEngine_InstallHook(&VirtualProtect, NULL, &g_VirtualProtectTrampoline))
    {
        if (HOOK_SUCCESS == HookEngine_InstallHook(&VirtualAlloc, NULL, &g_VirtualAllocTrampoline))
        {
            if (HOOK_SUCCESS == HookEngine_InstallHook(&VirtualQuery, NULL, &g_VirtualQueryTrampoline))
            {
                if (HOOK_SUCCESS == HookEngine_InstallHook(&VirtualFree, NULL, &g_VirtualFreeTrampoline))
                {
                    g_pVirtualAlloc = (fpVirtualAlloc)g_VirtualAllocTrampoline->pTrampoline;
                    g_pVirtualQuery = (fpVirtualQuery)g_VirtualQueryTrampoline->pTrampoline;
                    g_pVirtualFree = (fpVirtualFree)g_VirtualFreeTrampoline->pTrampoline;
                    g_pVirtualProtect = (fpVirtualProtect)g_VirtualProtectTrampoline->pTrampoline;

                    g_Initialised = TRUE;
                    g_Initialising = FALSE;
                    return HOOK_SUCCESS;
                }
            }
        }
    }

    //set the function pointers back to the original
    g_pVirtualAlloc = &VirtualAlloc;
    g_pVirtualQuery = &VirtualQuery;
    g_pVirtualFree = &VirtualFree;
    g_pVirtualProtect = &VirtualProtect;

    if (g_VirtualAllocTrampoline)
    {
        HookEngine_RemoveHook(g_VirtualAllocTrampoline);
    }

    if (g_VirtualQueryTrampoline)
    {
        HookEngine_RemoveHook(g_VirtualQueryTrampoline);
    }

    if (g_VirtualFreeTrampoline)
    {
        HookEngine_RemoveHook(g_VirtualFreeTrampoline);
    }

    if (g_VirtualProtectTrampoline)
    {
        HookEngine_RemoveHook(g_VirtualFreeTrampoline);
    }

    g_Initialised = FALSE;
    g_Initialising = FALSE;

    return HOOK_ERROR;
}


/**************************************************************************
*
* HookEngine_Shutdown
*
***************************************************************************/
extern "C" HOOKRESULT HookEngine_Shutdown()
{
    ScopeLock lock(g_CriticalSection);

    if (g_Initialising)
    {
        return HOOK_ERROR;
    }

    if (FALSE == g_Initialised)
    {
        return HOOK_SUCCESS;
    }

    if (g_HookCount == InternalHookCount)
    {
        //set the function pointers back to the original
        g_pVirtualAlloc = &VirtualAlloc;
        g_pVirtualQuery = &VirtualQuery;
        g_pVirtualFree = &VirtualFree;
        g_pVirtualProtect = &VirtualProtect;

        if (g_VirtualAllocTrampoline)
        {
            HookEngine_RemoveHook(g_VirtualAllocTrampoline);
        }

        if (g_VirtualQueryTrampoline)
        {
            HookEngine_RemoveHook(g_VirtualQueryTrampoline);
        }

        if (g_VirtualFreeTrampoline)
        {
            HookEngine_RemoveHook(g_VirtualFreeTrampoline);
        }

        if (g_VirtualProtectTrampoline)
        {
            HookEngine_RemoveHook(g_VirtualFreeTrampoline);
        }

        g_Initialised = FALSE;
        g_Initialising = FALSE;

        return HOOK_SUCCESS;
    }

    return HOOK_ERROR_STILL_HOOKED;
}

/**************************************************************************
*
* HookEngine_InstallHook
*
***************************************************************************/
extern "C" HOOKRESULT HookEngine_InstallHook
(
IN              LPVOID         pTargetFunctionAddress,
IN  OPTIONAL    LPVOID         pUserFunctionAddress,
OUT             PHOOKCONTEXT*  ppHookCtx
)
{

    //Critical sections can be recursivley locked on the same thread
    ScopeLock lock(g_CriticalSection);

#if defined(_M_IX86)
    JMP_INSTR_86            jmp         = { JMP_INSTRUCTION, 0 };
    JMP_TRAMPOLINE_INSTR_86 jmptramp    = { 0 };
    JMP_TRAMPOLINE_INSTR_86 jmpredir    = { 0 };
#elif defined(_M_X64)

    JMP_INSTR_64            jmp = { JMP_INSTRUCTION, 0 };
    JMP_TRAMPOLINE_INSTR_64 jmpredir = { 0 };
    JMP_TRAMPOLINE_INSTR_64 jmptramp = { 0 };
#else
#error Unsupported platform
#endif

    if (FALSE == IsInitialised() && FALSE == IsInitialising() )
    {
        return HOOK_ERROR_NOT_INITIALISED;
    }

    HOOKRESULT              result = HOOK_ERROR_INVALID_PARAMETER;
    SIZE_T                  contextSize = 0;
    HOOKCONTEXT_INTERNAL*   pCtx = NULL;

    if (
        pTargetFunctionAddress &&
        ppHookCtx
        )
    {
        DWORD oldTargetMemProtection = 0;

        if (HookEngine_SetupTargetMemProtection(pTargetFunctionAddress, oldTargetMemProtection))
        {
            //disassemble some of the function to locate some space for a jump location
            DWORD cbCopyFromTarget = HookEngine_GetFuncionByteCount((DWORD)sizeof(jmp), pTargetFunctionAddress);

            if (INVALID_DISASSEMBLY != cbCopyFromTarget)
            {
                //this number of bytes will be copied into the trampoline...
                contextSize = sizeof(HOOKCONTEXT_INTERNAL) +
                    (cbCopyFromTarget * 2) +
                    (STUB_PADDING_BYTES * 2) +
                    sizeof(jmptramp) +
                    sizeof(jmpredir);

                //if a user callback function was specified, we need to make the redirector address
                //within a 2GB window of the target function, otherwise any memory will do
                if (pUserFunctionAddress)
                {
                    pCtx = HookEngine_AllocateContextWithin2GB((DWORD)contextSize, (UINT_PTR)pTargetFunctionAddress);

                }
                else
                {
                    pCtx = HookEngine_AllocateContext((DWORD)contextSize);
                }

                if (pCtx)
                {
                    try
                    {
                        //clear struct with int3
                        HookEngine_Memset(pCtx, INT3_INSTRUCTION, contextSize);

                        //setup the context + trampoline
                        pCtx->cbSavedInstructions = cbCopyFromTarget;
                        pCtx->cbTrampoline = cbCopyFromTarget + sizeof(jmptramp);
                        pCtx->cbRedirect = sizeof(jmpredir);
                        pCtx->cbSize = (DWORD)contextSize;

                        //setup pointers
                        if (pUserFunctionAddress)
                        {
                            pCtx->pbSavedInstructions = (PBYTE)(pCtx + 1);
                            pCtx->pbRedirect = (PBYTE)(pCtx + 1) + pCtx->cbSavedInstructions + STUB_PADDING_BYTES;

                            //keep a full copy original bytes
                            HookEngine_Memcpy(pCtx->pbSavedInstructions, pTargetFunctionAddress, pCtx->cbSavedInstructions);
                        }
                        else
                        {
                            pCtx->pbSavedInstructions = NULL;
                            pCtx->pbRedirect = NULL;
                        }
                        
                        pCtx->pbTrampoline = (PBYTE)(pCtx + 1) +
                                             pCtx->cbSavedInstructions + 
                                             pCtx->cbRedirect + 
                                             (STUB_PADDING_BYTES * 2);

                        pCtx->Context.pTargetFunctionAddress = pTargetFunctionAddress;
                        pCtx->Context.pUserFunctionAddress = pUserFunctionAddress;
                        pCtx->Context.pTrampoline = pCtx->pbTrampoline;

                        //Copy instructions into the trampoline
                        HookEngine_Memcpy(pCtx->pbTrampoline, pTargetFunctionAddress, cbCopyFromTarget);

                        //setup the jump data

                        /**************************************************************************
                        *
                        * X86 
                        *
                        ***************************************************************************/
#if defined(_M_IX86)
                        //
                        // Setup redirect and target function jump, only if a user function was specified
                        //
                        if (pUserFunctionAddress)
                        {
                            //setup the redirector which jumps to the user function
                            HookEngine_Memcpy(&jmpredir, X86_TRAMPOLINE_INSTRUCTIONS, sizeof(X86_TRAMPOLINE_INSTRUCTIONS));
                            jmpredir.target = (UINT32)pUserFunctionAddress;
       
                            //setup the jmp instruction that jumps to the redirector
                            jmp.target = HookEngine_RelativeJumpOffset32((UINT_PTR)pTargetFunctionAddress, (UINT_PTR)pCtx->pbRedirect);
                        }

                        UINT_PTR pTarget = (UINT_PTR)pTargetFunctionAddress + (UINT_PTR)sizeof(jmp);

                        //setup the trampoline
                        HookEngine_Memcpy(&jmptramp, X86_TRAMPOLINE_INSTRUCTIONS, sizeof(X86_TRAMPOLINE_INSTRUCTIONS));
                        jmptramp.target = ((UINT32)pTarget);
       
#elif defined(_M_X64)
                        /**************************************************************************
                        *
                        * X64 
                        *
                        ***************************************************************************/

                        // Setup redirect and target function jump, only if a user function was specified
                        //
                        if (pUserFunctionAddress)
                        {
                            //setup the redirector which jumps to the user function
                            HookEngine_Memcpy(&jmpredir, X64_TRAMPOLINE_INSTRUCTIONS, sizeof(X64_TRAMPOLINE_INSTRUCTIONS));
                            jmpredir.hiaddr = (UINT32)((UINT_PTR)pUserFunctionAddress >> 32);
                            jmpredir.loaddr = (UINT32)((UINT_PTR)pUserFunctionAddress);

                            //setup the jmp instruction that jumps to the redirector
                            jmp.target = HookEngine_RelativeJumpOffset32((UINT_PTR)pTargetFunctionAddress, (UINT_PTR)pCtx->pbRedirect);
                        }

                        //setup the trampoline
                        UINT_PTR pTarget = (UINT_PTR)pTargetFunctionAddress + (UINT_PTR)sizeof(jmp);
                        HookEngine_Memcpy(&jmptramp, X64_TRAMPOLINE_INSTRUCTIONS, sizeof(X64_TRAMPOLINE_INSTRUCTIONS));
                        jmptramp.hiaddr = (UINT32)((UINT_PTR)pTarget >> 32);
                        jmptramp.loaddr = (UINT32)((UINT_PTR)pTarget);
#else
                        /**************************************************************************
                        *
                        * Platform unsupported 
                        *
                        ***************************************************************************/

                        #error Unsupported platform
#endif

                        //Copy the trampoline instructions into the trampoline area
                        HookEngine_Memcpy(&pCtx->pbTrampoline[cbCopyFromTarget], &jmptramp, sizeof(jmptramp));

                        //
                        // If a user function was specified then install the jmp in the target
                        //
                        if (pUserFunctionAddress)
                        {
                            //copy redirect
                            HookEngine_Memcpy(pCtx->pbRedirect, &jmpredir, sizeof(jmpredir));

                            //copy jump into the target function
                            HookEngine_Memcpy(pTargetFunctionAddress, &jmp, sizeof(jmp));

                            //any remaining instructions of the target should be nop's
                            DWORD remain = cbCopyFromTarget - sizeof(jmp);

                            if (remain)
                            {
                                HookEngine_Memset((((PBYTE)pTargetFunctionAddress) + sizeof(jmp)), NOP_INSTRUCTION, remain);
                            }
                        }

                        *ppHookCtx = &pCtx->Context;

                        ++g_HookCount;

                        result = HOOK_SUCCESS;

                    }
                    catch (...)
                    {
                        //
                        // It's conceivable that we've trashed the target function
                        // at this point, so we should perhaps do some better handling
                        // and copy the snatched function bytes back over the top of
                        // any jmp instruction we added.  That's currently a TODO
                        //
                        if (pCtx)
                        {
                            g_pVirtualFree(pCtx, pCtx->cbSize, MEM_RELEASE);
                        }

                        result = HOOK_ERROR_EXCEPTION_RAISED;
                    }

                }
                else
                {
                    result = HOOK_ERROR_OUT_OF_MEMORY;
                }
            }
            else
            {
                result = HOOK_ERROR_DISASSEMBLE;
            }

            //restore original protection
            HookEngine_RestoreTargetMemProtection(pTargetFunctionAddress, oldTargetMemProtection);
        }
        else
        {
            result = HOOK_ERROR_MEMORY_PROTECT;
        }

    }

    return result;
}

/**************************************************************************
*
* HookEngine_RemoveHook
*
***************************************************************************/
extern "C" HOOKRESULT HookEngine_RemoveHook
    (
    IN PHOOKCONTEXT pHookCtx
    )
{
    //Critical sections can be recursivley locked on the same thread
    ScopeLock lock(g_CriticalSection);

    CONST DWORD SensibleMax = 64;
    HOOKRESULT result = HOOK_ERROR_INVALID_PARAMETER;
    HOOKCONTEXT_INTERNAL* pInternal = (HOOKCONTEXT_INTERNAL*)pHookCtx;

    if (FALSE == IsInitialised() && FALSE == IsInitialising())
    {
        return HOOK_ERROR_NOT_INITIALISED;
    }

    if (pInternal)
    {
        //copy function bytes back over the top of the original function
        if (pInternal->Context.pTargetFunctionAddress &&
            pInternal->pbSavedInstructions &&
            pInternal->cbSavedInstructions &&
            pInternal->cbSavedInstructions < SensibleMax )
        {
            DWORD oldTargetMemProtection = 0;

            if (HookEngine_SetupTargetMemProtection(pInternal->Context.pTargetFunctionAddress, oldTargetMemProtection))
            {
                if (pInternal->pbRedirect && pInternal->pbSavedInstructions)
                {
                    HookEngine_Memcpy(pInternal->Context.pTargetFunctionAddress, pInternal->pbSavedInstructions, pInternal->cbSavedInstructions);
                }
                
                HookEngine_RestoreTargetMemProtection(pInternal->Context.pTargetFunctionAddress, oldTargetMemProtection);
                g_pVirtualFree(pInternal, pInternal->cbSize, MEM_RELEASE);
                --g_HookCount;
                result = HOOK_SUCCESS;
            }
            else
            {
                result = HOOK_ERROR_MEMORY_PROTECT;
            }
        }
    }
     
    return result;
}


