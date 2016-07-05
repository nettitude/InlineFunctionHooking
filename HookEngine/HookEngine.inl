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
#ifndef __HOOKENGINEINL_H__
#define __HOOKENGINEINL_H__


namespace nettitude
{
    const DWORD MAX_THREADS         = 255;                  //arbitrary max thread count...
    const DWORD INVALID_DISASSEMBLY = 0xFFFFFFFF;
    const BYTE  NOP_INSTRUCTION     = 0x90;                 //nop
    const BYTE  JMP_INSTRUCTION     = 0xE9;                 //jmp
    const BYTE  INT3_INSTRUCTION    = 0xCC;
    const UINT32 STUB_PADDING_BYTES = 8;                    //size of area filled with int3

    //make sure that these structures are not padded.
#pragma pack(push,1)
    /**
        JMP_INSTR_86

        x86 Structure containing the instructions for a relative jump
    */
    struct JMP_INSTR_86
    {
        BYTE        jmp;
        INT32       target;                                 //relative target address 
    };

    /**
        JMP_TRAMPOLINE_INSTR_86

        x86 Structure containing the instructions for a direct jump
        used by the trampoline and the redirect stub
    */
    struct JMP_TRAMPOLINE_INSTR_86
    {
        BYTE        push;
        BYTE        mov;
        INT32       target;
        BYTE        xcgh[3];
        BYTE        ret;
    };

    
    const BYTE  X86_TRAMPOLINE_INSTRUCTIONS[] =
        { 0x50,                                             //push eax
          0xB8, 0xAA, 0xAA, 0xAA, 0xAA,                     //mov eax, 0xAAAAAAAA
          0x87, 0x04, 0x24,                                 //xchg eax, dword ptr[esp]
          0xC3 };                                           //ret


    /**
        JMP_INSTR_64

        x64 Structure containing the instructions for a relative jump
        used by the trampoline and the redirect stub
    */
    struct JMP_INSTR_64
    {
        BYTE        jmp;
        INT32       target;
    };

    /**
        JMP_TRAMPOLINE_INSTR_64

        x64 Structure containing the instructions for a direct jump
    */
    struct JMP_TRAMPOLINE_INSTR_64
    {
    
        BYTE        push;
        UINT32      loaddr;
        BYTE        mov[4];
        UINT32      hiaddr;
        BYTE        ret;
    };

        //asm instructions for direct jump
    const BYTE  X64_TRAMPOLINE_INSTRUCTIONS[] = 
        { 0x68, 0xAA, 0xAA, 0xAA, 0xAA,                     //push 0xAAAAAAAA
          0xC7, 0x44, 0x24, 0x04, 0xBB, 0xBB, 0xBB, 0xBB,   //mov dword ptr[ esp+4 ], 0xBBBBBBBB
          0xC3 };                                           //ret

#pragma pack(pop)

    /**
        HOOKCONTEXT_INTERNAL

        Internal information on the hook, this is returned to the user
        as a HOOKCONTEXT
    */
    struct HOOKCONTEXT_INTERNAL
    {
        HOOKCONTEXT     Context;
        DWORD           cbSize;                     //count of HOOKCONTEXT_INTERNAL total bytes
        DWORD           cbTrampoline;               //size of trampoline
        DWORD           cbSavedInstructions;        //count of saved instruction bytes
        DWORD           cbRedirect;                 //count of redirect instruction bytes
        PBYTE           pbSavedInstructions;        //original saved instructions
        PBYTE           pbRedirect;                 //original saved instructions
        PBYTE           pbTrampoline;               //pointer to trampoline stub

    };
    
}//namespace


#endif