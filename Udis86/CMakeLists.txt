# Copyright (c) 2015, Nettitude
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without modification, 
# are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, 
#    this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. Neither the name of the copyright holder nor the names of its contributors
#    may be used to endorse or promote products derived from this software without 
#    specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. 
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, 
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, 
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.

cmake_minimum_required (VERSION 2.6)

PROJECT(Udis86)

SET( SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libudis86 )

INCLUDE_DIRECTORIES( ${SRC_DIR} )

ADD_DEFINITIONS(-D_CRT_SECURE_NO_WARNINGS=1 -DHAVE_STRING_H=1)


SET( SOURCE udis86.h
            ${SRC_DIR}/itab.c
            ${SRC_DIR}/itab.h
            ${SRC_DIR}/decode.c
            ${SRC_DIR}/decode.h
            ${SRC_DIR}/extern.h
            ${SRC_DIR}/syn-att.c
            ${SRC_DIR}/syn-intel.c
            ${SRC_DIR}/syn.c
            ${SRC_DIR}/syn.h
            ${SRC_DIR}/types.h
            ${SRC_DIR}/udint.h
            ${SRC_DIR}/udis86.c )

ADD_LIBRARY( ${PROJECT_NAME} STATIC ${SOURCE} )

