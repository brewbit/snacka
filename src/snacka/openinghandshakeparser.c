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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "openinghandshakeparser.h"
#include "websocket.h"
#include "../external/base64/base64.h"


static const char* HTTP_ACCEPT_FIELD_NAME = "Sec-WebSocket-Accept";
static const char* HTTP_UPGRADE_FIELD_NAME = "Upgrade";
static const char* HTTP_CONNECTION_FIELD_NAME = "Connection";
static const char* HTTP_WS_PROTOCOL_NAME = "Sec-WebSocket-Protocol";
static const char* HTTP_WS_EXTENSIONS_NAME = "Sec-WebSocket-Extensions";

static int on_header_field(http_parser* p, const char *at, size_t length)
{
    (void)length;
    snOpeningHandshakeParser* parser = (snOpeningHandshakeParser*)p->data;
    
    parser->currentHeaderField = SN_UNRECOGNIZED_HTTP_FIELD;
    
    if (strncasecmp(at, HTTP_ACCEPT_FIELD_NAME, strlen(HTTP_ACCEPT_FIELD_NAME)) == 0)
    {
        parser->currentHeaderField = SN_HTTP_ACCEPT;
    }
    else if (strncasecmp(at, HTTP_UPGRADE_FIELD_NAME, strlen(HTTP_UPGRADE_FIELD_NAME)) == 0)
    {
        parser->currentHeaderField = SN_HTTP_UPGRADE;
    }
    else if (strncasecmp(at, HTTP_CONNECTION_FIELD_NAME, strlen(HTTP_CONNECTION_FIELD_NAME)) == 0)
    {
        parser->currentHeaderField = SN_HTTP_CONNECTION;
    }
    else if (strncasecmp(at, HTTP_WS_PROTOCOL_NAME, strlen(HTTP_WS_PROTOCOL_NAME)) == 0)
    {
        parser->currentHeaderField = SN_HTTP_WS_PROTOCOL;
    }
    else if (strncasecmp(at, HTTP_WS_EXTENSIONS_NAME, strlen(HTTP_WS_EXTENSIONS_NAME)) == 0)
    {
        parser->currentHeaderField = SN_HTTP_WS_EXTENSIONS;
    }
    
    return 0;
}

static int on_header_value(http_parser* p, const char *at, size_t length)
{
    snOpeningHandshakeParser* parser = (snOpeningHandshakeParser*)p->data;
    
    if (parser->currentHeaderField == SN_HTTP_ACCEPT)
    {
        snMutableString_appendBytes(&parser->acceptValue, at, length);
    }
    else if (parser->currentHeaderField == SN_HTTP_CONNECTION)
    {
        snMutableString_appendBytes(&parser->connectionValue, at, length);
    }
    else if (parser->currentHeaderField == SN_HTTP_UPGRADE)
    {
        snMutableString_appendBytes(&parser->upgradeValue, at, length);
    }
    else if (parser->currentHeaderField == SN_HTTP_WS_EXTENSIONS)
    {
        snMutableString_appendBytes(&parser->extensionsValue, at, length);
    }
    else if (parser->currentHeaderField == SN_HTTP_WS_PROTOCOL)
    {
        snMutableString_appendBytes(&parser->protocolValue, at, length);
    }
    
    return 0;
}

static int on_message_begin(http_parser* p)
{
    (void)p;
    //snOpeningHandshakeParser* parser = (snOpeningHandshakeParser*)p->data;
    //printf("-------------ON MESSAGE BEGIN----------\n");
    return 0;
}

static int on_message_complete(http_parser* p)
{
    (void)p;
    //snOpeningHandshakeParser* parser = (snOpeningHandshakeParser*)p->data;
    //c->response.bodySize = c->response.size - c->response.bodyStart;
    //printf("-----------ON MESSAGE COMPLETE---------\n");
    return 0;
}

static int on_headers_complete(http_parser* p)
{
    snOpeningHandshakeParser* parser = (snOpeningHandshakeParser*)p->data;
    if (p->status_code != 101)
    {
        /*
         http://tools.ietf.org/html/rfc6455#section-1.3
         Any status code other than 101 indicates that the WebSocket handshake
         has not completed and that the semantics of HTTP still apply.
         */
        parser->errorCode = SN_OPENING_HANDSHAKE_FAILED;
    }
    
    parser->reachedHeaderEnd = 1;
    
    return 0;
}

static void generateKey(snOpeningHandshakeParser* p, snMutableString* keyStr)
{
    uint8_t key[16];
    char keyEnc[Base64encode_len(16)];
    char acceptHashEnc[Base64encode_len(20)];

    /* Generate a random 16-byte nonce */
    p->cryptoCallbacks->randCallback(key, sizeof(key));

    /* Base-64 encode it */
    Base64encode(keyEnc, key, 16);

    /* Copy it to the key string */
    snMutableString_append(keyStr, keyEnc);

    /* Calculate expected 'Sec-WebSocket-Accept' header returned from server */
    snMutableString acceptKey;
    snMutableString_init(&acceptKey);
    snMutableString_append(&acceptKey, keyEnc);
    snMutableString_append(&acceptKey, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

    uint8_t acceptHash[20];
    const char* acceptKeyStr = snMutableString_getString(&acceptKey);
    p->cryptoCallbacks->shaCallback((uint8_t*)acceptKeyStr, strlen(acceptKeyStr), acceptHash);
    snMutableString_deinit(&acceptKey);

    /* Base-64 encode it */
    Base64encode(acceptHashEnc, acceptHash, 20);

    /* Store the expected accept header value to compare with the server's response */
    snMutableString_init(&p->expectedAcceptValue);
    snMutableString_append(&p->expectedAcceptValue, acceptHashEnc);
}

void snOpeningHandshakeParser_init(snOpeningHandshakeParser* p, snCryptoCallbacks* cryptoCallbacks, snHTTPHeader* extraHeaders, int numExtraHeaders)
{
    memset(p, 0, sizeof(snOpeningHandshakeParser));
    
    //set up http header parser
    memset(&p->httpParserSettings, 0, sizeof(http_parser_settings));
    
    p->httpParserSettings.on_headers_complete = on_headers_complete;
    p->httpParserSettings.on_message_begin = on_message_begin;
    p->httpParserSettings.on_message_complete = on_message_complete;
    p->httpParserSettings.on_header_field = on_header_field;
    p->httpParserSettings.on_header_value = on_header_value;
    http_parser_init(&p->httpParser, HTTP_RESPONSE);
    p->httpParser.data = p;
    
    p->currentHeaderField = SN_UNRECOGNIZED_HTTP_FIELD;

    p->extraHeaders = extraHeaders;
    p->numExtraHeaders = numExtraHeaders;

    p->cryptoCallbacks = cryptoCallbacks;

    snMutableString_init(&p->acceptValue);
    snMutableString_init(&p->connectionValue);
    snMutableString_init(&p->upgradeValue);
    snMutableString_init(&p->protocolValue);
    snMutableString_init(&p->extensionsValue);

    p->errorCode = SN_NO_ERROR;
}

void snOpeningHandshakeParser_deinit(snOpeningHandshakeParser* p)
{
    snMutableString_deinit(&p->acceptValue);
    snMutableString_deinit(&p->connectionValue);
    snMutableString_deinit(&p->upgradeValue);
    snMutableString_deinit(&p->protocolValue);
    snMutableString_deinit(&p->extensionsValue);
}

void snOpeningHandshakeParser_createOpeningHandshakeRequest(snOpeningHandshakeParser* parser,
                                                            const char* host,
                                                            int port,
                                                            const char* path,
                                                            const char* queryString,
                                                            snMutableString* request)
{
    int i;
    const int queryLength = strlen(queryString);
    
    //GET
    snMutableString_append(request, "GET /");
    snMutableString_append(request, path);
    if (queryLength > 0)
    {
        snMutableString_append(request, "?");
        snMutableString_append(request, queryString);
    }
    snMutableString_append(request, " HTTP/1.1\r\n");
    
    //Host
    snMutableString_append(request, "Host: ");
    snMutableString_append(request, host);
    snMutableString_append(request, ":");
    snMutableString_appendInt(request, port);
    snMutableString_append(request, "\r\n");
    
    //Upgrade
    snMutableString_append(request, "Upgrade: websocket\r\n");
    
    //Connection
    snMutableString_append(request, "Connection: Upgrade\r\n");
    
    //Key
    snMutableString_append(request, "Sec-WebSocket-Key:");
    
    snMutableString key;
    snMutableString_init(&key);
    generateKey(parser, &key);
    snMutableString_append(request, snMutableString_getString(&key));
    snMutableString_deinit(&key);
    
    snMutableString_append(request, "\r\n");
    
    //Version
    snMutableString_append(request, "Sec-WebSocket-Version: 13\r\n");

    //Extra Headers
    for (i = 0; i < parser->numExtraHeaders; ++i) {
      snMutableString_append(request, parser->extraHeaders[i].name);
      snMutableString_append(request, ":");
      snMutableString_append(request, parser->extraHeaders[i].value);
      snMutableString_append(request, "\r\n");
    }

    snMutableString_append(request, "\r\n");
}

static snError validateResponse(snOpeningHandshakeParser* p)
{
    int i;

    /*http://tools.ietf.org/html/rfc6455#section-4.1*/
    assert(p->reachedHeaderEnd);
    
    if (p->errorCode != SN_NO_ERROR)
    {
        return p->errorCode;
    }
        
    snError result = SN_NO_ERROR;
    
    /*
     If the response lacks an |Upgrade| header field or the |Upgrade|
     header field contains a value that is not an ASCII case-
     insensitive match for the value "websocket", the client MUST
     _Fail the WebSocket Connection_.
     */
    {
        const char* upgrVal = snMutableString_getString(&p->upgradeValue);
        if (strlen(upgrVal) == 0)
        {
            result = SN_OPENING_HANDSHAKE_FAILED;
        }
        else
        {
            const char* comp[2] = {"websocket", "WEBSOCKET"};
            if (strlen(upgrVal) != strlen(comp[0]))
            {
                result = SN_OPENING_HANDSHAKE_FAILED;
            }
            else
            {
                for (i = 0;  i < (int)strlen(upgrVal); i++)
                {
                    if (upgrVal[i] != comp[0][i] &&
                        upgrVal[i] != comp[1][i])
                    {
                        result = SN_OPENING_HANDSHAKE_FAILED;
                        break;
                    }
                }
            }
        }
    }
    
    /*
     If the response lacks a |Connection| header field or the
     |Connection| header field doesn't contain a token that is an
     ASCII case-insensitive match for the value "Upgrade", the client
     MUST _Fail the WebSocket Connection_.
     */
    {
        const char* connVal = snMutableString_getString(&p->connectionValue);
        if (strlen(connVal) == 0)
        {
            result = SN_OPENING_HANDSHAKE_FAILED;
        }
        else
        {
            const char* comp[2] = {"UPGRADE", "upgrade"};
            if (strlen(connVal) != strlen(comp[0]))
            {
                result = SN_OPENING_HANDSHAKE_FAILED;
            }
            else
            {
                for (i = 0;  i < (int)strlen(connVal); i++)
                {
                    if (connVal[i] != comp[0][i] &&
                        connVal[i] != comp[1][i])
                    {
                        result = SN_OPENING_HANDSHAKE_FAILED;
                        break;
                    }
                }
            }
        }
    }
    
    /*
     If the response lacks a |Sec-WebSocket-Accept| header field or
    the |Sec-WebSocket-Accept| contains a value other than the
    base64-encoded SHA-1 of the concatenation of the |Sec-WebSocket-
    Key| (as a string, not base64-decoded) with the string "258EAFA5-
    E914-47DA-95CA-C5AB0DC85B11" but ignoring any leading and
    trailing whitespace, the client MUST _Fail the WebSocket
    Connection_.
     */
    {
        if (strcmp(snMutableString_getString(&p->acceptValue),
                   snMutableString_getString(&p->expectedAcceptValue)) != 0)
          result = SN_OPENING_HANDSHAKE_FAILED;
    }
    
    /*
     If the response includes a |Sec-WebSocket-Extensions| header
     field and this header field indicates the use of an extension
     that was not present in the client's handshake (the server has
     indicated an extension not requested by the client), the client
     MUST _Fail the WebSocket Connection_.  (The parsing of this
     header field to determine which extensions are requested is
     discussed in Section 9.1.)
     */
    {
        /* No extensions were sent, so none should be received.*/
        if (strlen(snMutableString_getString(&p->extensionsValue)) != 0)
        {
            result = SN_OPENING_HANDSHAKE_FAILED;
        }
    }
    
    /*
     If the response includes a |Sec-WebSocket-Protocol| header field
     and this header field indicates the use of a subprotocol that was
     not present in the client's handshake (the server has indicated a
     subprotocol not requested by the client), the client MUST _Fail
     the WebSocket Connection_.
     */
    if (strlen(snMutableString_getString(&p->protocolValue)) != 0)
    {
        /* No protocols were sent, so none should be received.*/
        result = SN_OPENING_HANDSHAKE_FAILED;
    }
    
    return result;
}

snError snOpeningHandshakeParser_processBytes(snOpeningHandshakeParser* p,
                                              const char* bytes,
                                              int numBytes,
                                              int* numBytesProcessed,
                                              int* handshakeCompleted)
{
    assert(!p->reachedHeaderEnd);
    
    *numBytesProcessed = http_parser_execute(&p->httpParser,
                                             &p->httpParserSettings,
                                             bytes,
                                             numBytes);
    
    if (HTTP_PARSER_ERRNO(&p->httpParser) != HPE_OK)
    {
        //http response header parsing error
        return SN_OPENING_HANDSHAKE_FAILED;
    }
    
    if (p->reachedHeaderEnd)
    {
        p->errorCode = validateResponse(p);
    }
    
    *handshakeCompleted = p->reachedHeaderEnd;
    
    return p->errorCode;
}
