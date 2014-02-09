/*
 * Copyright (c) 2013, Per Gantelius
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of the copyright holders.
 */

#ifndef SN_CRYPTOCALLBACKS_H
#define SN_CRYPTOCALLBACKS_H

/*! \file */

#include "errorcodes.h"
#include "websocket.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */
    
    /**
     * Generates a sequence of random bytes.
     * @param buffer     The buffer to fill with random values.
     * @param bufferSize The size of \c buffer.
     */
    typedef void (*snRandCallback)(uint8_t* buffer, uint32_t bufferSize);

    /**
     * Computes the SHA-1 hash of a buffer.
     * @param buffer     The buffer to store read data in.
     * @param bufferSize The size of \c buffer.
     */
    typedef void (*snShaCallback)(const uint8_t* buffer, uint32_t bufferSize, uint8_t* hash);

    /**
     * A set of callbacks representing operations related to cryptography.
     */
    typedef struct snCryptoCallbacks
    {
        /** */
        snRandCallback randCallback;
        /** */
        snShaCallback shaCallback;

    } snCryptoCallbacks;
    
    
    
#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /*SN_CRYPTOCALLBACKS_H*/



