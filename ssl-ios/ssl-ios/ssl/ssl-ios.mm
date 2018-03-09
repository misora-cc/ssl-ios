//
//  main.m
//  ssl-ios
//
//  Created by misora on 2018/3/7.
//  Copyright © 2018年 misora. All rights reserved.
//

#import "ssl-ios.hh"

SSLContext::SSLContext()
:_sslContext(nullptr)
{
    
}

bool SSLContext::init()
{
    _sslContext = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    if (!_sslContext) {
        return false;
    }
    
    OSStatus err;
    //SSLSetProtocolVersionMin(_sslContext, kTLSProtocol1);
    //SSLSetProtocolVersionMax(kTLSProtocol13);
    
    //both hostname check and SNI require SSLSetPeerDomainName
    //SSLSetPeerDomainName
    
    err = SSLSetIOFuncs(_sslContext, &self::_SSLReadCallback, &self::_SSLWriteCallback);
    if (err != noErr) {
        return false;
    }
    
    SSLSetConnection(_sslContext, (SSLConnectionRef)this);

    
    return true;
}

OSStatus SSLContext::_SSLReadCallback(SSLConnectionRef connection, void *data, size_t *dataLength)
{
    
    return noErr;
}

OSStatus SSLContext::_SSLWriteCallback(SSLConnectionRef connection, const void *data, size_t *dataLength)
{
    
    
    return noErr;
}

void SSLContext::beginRecv(void* data, size_t dataLen, RecvCallback cb)
{
    if (!_sslContext) {
        return;
    }
    
    size_t processed = 0;
    OSStatus err = SSLRead(_sslContext, data, dataLen, &processed);
    if (err == noErr) {
        cb (this, data, processed);
        return;
    }
    
    switch (err) {
        case errSSLWouldBlock:
            if (processed > 0) {
                cb (this, data, processed);
                return;
            }
            else {
                //we should async receive data from socket, and call SSLRead again
                
            }
            break;
        case errSSLClosedGraceful:  // server gracefully shut down the ssl session
        case errSSLClosedNoNotify:  // server hung up on us instead of sending a closure alert notice
            cb (this, NULL, 0);
            return;
        default:
            // other errors
            cb (this, NULL, -1);
            return;
    }
    
    
    
    
    
    return;
}

void SSLContext::beginSend(const void* data, size_t dataLen, SendCallback cb)
{
    
    return;
}
