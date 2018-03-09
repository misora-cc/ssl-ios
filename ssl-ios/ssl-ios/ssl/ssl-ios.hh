//
//  main.m
//  ssl-ios
//
//  Created by misora on 2018/3/7.
//  Copyright © 2018年 misora. All rights reserved.
//


#import <Foundation/Foundation.h>
#import <Security/Security.h>

class IOStream
{
public:
    void write();
    void read();
};


class SSLContext
{
    typedef SSLContext self;
    typedef void (*RecvCallback) (SSLContext* ctx, void* data, size_t dataLen);
    typedef void (*SendCallback) (SSLContext* ctx);
public:
    SSLContext();
    bool init();
    void beginRecv(void* data, size_t dataLen, RecvCallback cb);
    void beginSend(const void* data, size_t dataLen, SendCallback cb);
    
    bool HasDataToWrite();
    bool HasDataToRead();
    
    
    
    
private:
    static OSStatus _SSLReadCallback(SSLConnectionRef connection, void *data, size_t *dataLength);
    static OSStatus _SSLWriteCallback(SSLConnectionRef connection, const void *data, size_t *dataLength);
    
private:
    SSLContextRef _sslContext;
    
    void* _recvBufferRef;
    size_t _recvBufferSize;
    void* _sendBuffer;
    size_t _sendBufferSize;
};
