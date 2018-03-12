//
//  SSLContext.cpp
//  ssl-ios
//
//  Created by misora on 2018/3/9.
//  Copyright © 2018年 misora. All rights reserved.
//

#include "SSLContext.hpp"
#include <Foundation/Foundation.h>
#include <Security/Security.h>

static OSStatus _SSLRead(SSLConnectionRef connection, void *data, size_t *dataLength);
static OSStatus _SSLWrite(SSLConnectionRef connection, const void *data, size_t *dataLength);


SSLContext::SSLContext()
{
}

SSLContext::~SSLContext()
{
}

void SSLContext::SetHandler(SSLContext::Handler *handler)
{
}

void SSLContext::SetConnection(Stream *conn)
{
}

void SSLContext::Handshake()
{
    
}

void SSLContext::Send(const void *data, size_t length)
{
    
}

void SSLContext::Recv()
{
    
}

OSStatus _SSLRead(SSLConnectionRef connection, void *data, size_t *dataLength)
{
    return noErr;
}

OSStatus _SSLWrite(SSLConnectionRef connection, const void *data, size_t *dataLength)
{
    return noErr;
}


