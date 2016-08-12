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
        HookEngine_Disassemble

        Obtain the minimum number of instruction bytes that need to be copied
        from the target function, in order to accomodate our jump instruction
    */
    static DWORD HookEngine_Disassemble(DWORD cbRequired, LPVOID pTargetFunctionAddress, DISASSEMBLY_DATA& DisassemblyData )
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

        DWORD instrlen = 0;

        DisassemblyData.Count = 0;
        DisassemblyData.Length = 0;

        HookEngine_Memset(DisassemblyData.Instructions, 0, sizeof(DisassemblyData.Instructions));
        HookEngine_Memset(DisassemblyData.InstuctionBuffer, 0, sizeof(DisassemblyData.InstuctionBuffer));
        HookEngine_Memset(DisassemblyData.InstructionLengths, 0, sizeof(DisassemblyData.InstructionLengths));

        do
        {
            instrlen = ud_disassemble(&ud_obj);
          
            if (instrlen)
            {
                if ((DisassemblyData.Length + instrlen) < MAX_INSTRUCTION_BUFFER)
                {
                    DisassemblyData.Instructions[DisassemblyData.Count] = ud_obj;
                    DisassemblyData.InstructionLengths[DisassemblyData.Count] = instrlen;
                    DisassemblyData.Count++;
                    HookEngine_Memcpy(&DisassemblyData.InstuctionBuffer[DisassemblyData.Length], ((BYTE*)pTargetFunctionAddress) + DisassemblyData.Length, instrlen);
                    DisassemblyData.Length += instrlen;
                }
            }

        } while (DisassemblyData.Length < cbRequired &&
                 DisassemblyData.Count < MAX_INSTRUCTIONS &&
                 instrlen != 0);

        return DisassemblyData.Length;
    }

    /**
        HookEngine_IsJump(ud_mnemonic_code)
    */
    BOOL HookEngine_IsJump(ud_mnemonic_code code)
    {
        switch (code)
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
                return TRUE;
        }

        return FALSE;
    }

    /**
    HookEngine_IsRet(ud_mnemonic_code)
    */
    BOOL HookEngine_IsRet(ud_mnemonic_code code)
    {
        switch (code)
        {
        case UD_Iret:
        case UD_Iretf:
            return TRUE;
        }

        return FALSE;
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
        UINT_PTR currentAddress = pTargetFunction;
        UINT_PTR maxAddress = pTargetFunction + twoGB - Page;
        UINT_PTR minAddress = pTargetFunction - twoGB + Page;
        MEMORY_BASIC_INFORMATION memInfo = { 0 };
        HOOKCONTEXT_INTERNAL* pResult = NULL;


        while (currentAddress<maxAddress)
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

                currentAddress += memInfo.RegionSize;
            }
            else
            {
                currentAddress += Page;
            }

        }

        currentAddress = pTargetFunction;

        //
        // Search behind of the terget function
        //
        while (currentAddress>minAddress)
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

                currentAddress -= memInfo.RegionSize;

            }
            else
            {
                currentAddress -= Page;
            }

        }


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
    HookEngine_AllocateContext

    Allocates a context that can be anywhere in user space
    */
    static VOID HookEngine_FreeContext(HOOKCONTEXT_INTERNAL* pContext)
    {
        HOOKCONTEXT_INTERNAL*   pResult = (HOOKCONTEXT_INTERNAL*)g_pVirtualFree(pContext, pContext->cbSize, MEM_RELEASE);
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

        return -((INT32)ret + (INT32)sizeof(JMP_INSTR_86));
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
            DISASSEMBLY_DATA DisasmData = { 0 };

            //disassemble some of the function to locate some space for a jump location
            CONST DWORD cbRequired = (DWORD)sizeof(jmp);
            DWORD cbLength = HookEngine_Disassemble((DWORD)sizeof(jmp), pTargetFunctionAddress, DisasmData);
            

            if (cbLength >= cbRequired)
            {
                //if it's a ret, abort
                if (HookEngine_IsRet(DisasmData.Instructions[0].mnemonic))
                {
                    result = HOOK_ERROR_DISASSEMBLE;
                }

                //this number of bytes will be copied into the trampoline...
                DWORD contextSize = sizeof(HOOKCONTEXT_INTERNAL)+
                    (DisasmData.Length * 2) +
                    (STUB_PADDING_BYTES * 2) +
                    sizeof(jmptramp)+
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
                        pCtx->cbSavedInstructions = DisasmData.Length;
                        pCtx->cbTrampoline = DisasmData.Length + sizeof(jmptramp);
                        pCtx->cbRedirect = sizeof(jmpredir);
                        pCtx->cbSize = (DWORD)contextSize;

                        //setup pointers
                        if (pUserFunctionAddress)
                        {
                            pCtx->pbSavedInstructions = (PBYTE)(pCtx + 1);
                            pCtx->pbRedirect = (PBYTE)(pCtx + 1) + DisasmData.Length + STUB_PADDING_BYTES;

                            //keep a full copy original bytes
                            HookEngine_Memcpy(pCtx->pbSavedInstructions, DisasmData.InstuctionBuffer, DisasmData.Length);
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



                        if (HookEngine_IsJump(DisasmData.Instructions[0].mnemonic) &&
                            DisasmData.InstructionLengths[0] >= cbRequired)
                        {
                            //get the relative offset of the jmp and create a trampoline that jumps to
                            //that address
                            const ud_operand& operand = DisasmData.Instructions[0].operand[0];
                            UINT_PTR address = 0;
                                                        
                            if (operand.type == UD_OP_JIMM)
                            {
                                switch (operand.size)
                                {
                                case  8:
                                    address = (UINT_PTR)pTargetFunctionAddress + (UINT_PTR)(DisasmData.Instructions[0].pc + operand.lval.sbyte) - DisasmData.InstructionLengths[0];
                                case 16:
                                    address = (UINT_PTR)pTargetFunctionAddress + (UINT_PTR)(DisasmData.Instructions[0].pc + operand.lval.sword) - DisasmData.InstructionLengths[0];
                                case 32:
                                    address = (UINT_PTR)pTargetFunctionAddress + (UINT_PTR)(DisasmData.Instructions[0].pc + operand.lval.sdword) - DisasmData.InstructionLengths[0];
                                }
                            }
                            else if (operand.type == UD_OP_MEM)
                            {
                                if (operand.base == UD_R_RIP && 
                                    operand.index == UD_NONE &&
                                    operand.scale == 0)
                                {
                                    UINT_PTR* pAddr = (UINT_PTR*)((BYTE*)DisasmData.Instructions[0].pc + operand.lval.sdword);
                                    address = *pAddr;
                                }
                                else if (operand.base == UD_NONE && 
                                         operand.index == UD_NONE &&
                                         operand.scale == 0)
                                {
                                    UINT_PTR* pAddr = (UINT_PTR*)(operand.lval.uqword);
                                    address = *pAddr;
                                }
                            }

                            if (address != 0)
                            {
                                //make a trampoline that jumps to the address
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
                                jmptramp.target = ((UINT32)address);

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
                                jmptramp.hiaddr = (UINT32)((UINT_PTR)address >> 32);
                                jmptramp.loaddr = (UINT32)((UINT_PTR)address);
#else
                                /**************************************************************************
                                *
                                * Platform unsupported
                                *
                                ***************************************************************************/

#error Unsupported platform
#endif   
                                //Copy the trampoline instructions into the trampoline area
                                HookEngine_Memcpy(&pCtx->pbTrampoline[0], &jmptramp, sizeof(jmptramp));

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
                                    DWORD remain = DisasmData.Length - sizeof(jmp);

                                    if (remain)
                                    {
                                        HookEngine_Memset((((PBYTE)pTargetFunctionAddress) + sizeof(jmp)), NOP_INSTRUCTION, remain);
                                    }
                                }

                                *ppHookCtx = &pCtx->Context;

                                ++g_HookCount;

                                result = HOOK_SUCCESS;
                            }
                            else
                            {
                                HookEngine_FreeContext(pCtx);
                                result = HOOK_ERROR_DISASSEMBLE;
                            }
                        }
                        else
                        {
                            //Copy instructions into the trampoline
                            HookEngine_Memcpy(pCtx->pbTrampoline, DisasmData.InstuctionBuffer, DisasmData.Length);

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
                            HookEngine_Memcpy(&pCtx->pbTrampoline[DisasmData.Length], &jmptramp, sizeof(jmptramp));

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
                                DWORD remain = DisasmData.Length - sizeof(jmp);

                                if (remain)
                                {
                                    HookEngine_Memset((((PBYTE)pTargetFunctionAddress) + sizeof(jmp)), NOP_INSTRUCTION, remain);
                                }
                            }

                            *ppHookCtx = &pCtx->Context;

                            ++g_HookCount;

                            result = HOOK_SUCCESS;

                        }

                    }//try
                    catch (...)
                    {
                        result = HOOK_ERROR_EXCEPTION_RAISED;
                    }

                }//if
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
                HookEngine_FreeContext( pInternal );
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


