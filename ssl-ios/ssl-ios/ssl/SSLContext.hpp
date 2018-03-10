//
//  SSLContext.hpp
//  ssl-ios
//
//  Created by misora on 2018/3/9.
//  Copyright © 2018年 misora. All rights reserved.
//

#ifndef SSLContext_hpp
#define SSLContext_hpp

#include <stdio.h>
#include <stdlib.h>

// A connected connection provides method to asynchronous send/recv from network
class Stream
{
public:
    typedef void (*WriteCallback) (void* userdata, int err);
    typedef void (*ReadCallback) (void* userdata, const void* data, int length);
    
    virtual void Write(const void* data, size_t length, void* userdata, WriteCallback callback) = 0;
    virtual void Read(void* userdata, ReadCallback callback) = 0;
};

class SSLContext
{
public:
    class Handler {
    public:
        virtual void OnConnect(int err) = 0;
        virtual void OnSend(int err) = 0;
        virtual void OnRecv(int err, const void* data, size_t length) = 0;
    };

public:
    SSLContext();
    ~SSLContext();
    
public:
    void SetHandler(Handler* handler);
    void SetConnection(Stream* conn);
    
    void Handshake();
    void Send(const void* data, size_t length);
    void Recv();
    
private:
    class SSLContextImpl;
    SSLContextImpl *_impl;
};



#endif /* SSLContext_hpp */
