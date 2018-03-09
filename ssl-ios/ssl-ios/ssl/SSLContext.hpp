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
#include <Security/Security.h>



class Connection
{
public:
    typedef void (*SendCallback) (void* userdata, int err);
    typedef void (*RecvCallback) (void* userdata, const void* data, int length);
    
    virtual void Send(const void* data, size_t length, void* userdata, SendCallback callback) = 0;
    virtual void Recv(void* userdata, RecvCallback callback) = 0;
};

class SSLContext
{
public:
    class Handler {
    public:
        virtual void OnConnect(int err) = 0;
        virtual void OnSend(int err) = 0;
        virtual void OnRecv(const void* data, int length) = 0;
    }
public:
    SSLContext();
    ~SSLContext();
    
public:
    void Handshake(Connection *conn, Handler *handler);
    void Send();
    void Recv();
    
private:
    
    
private:
    Handler* _handler;
    Connection* _conn;
};



#endif /* SSLContext_hpp */
