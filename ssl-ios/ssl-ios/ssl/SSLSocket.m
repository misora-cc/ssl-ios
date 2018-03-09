//
//  SSLSocket.m
//  ssl-ios
//
//  Created by misora on 2018/3/8.
//  Copyright © 2018年 misora. All rights reserved.
//

#import "SSLSocket.h"
#include <sys/time.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <arpa/inet.h>


@interface SSLSocket ()

@property (assign) BOOL needRead;
@property (retain, readonly) NSMutableData* SSLWriteData;
@property (retain, readonly) NSMutableData* SSLReadData;

@end

@implementation SSLSocket
{
    NSString* _ip;
    int _port;
    int _sock;
    
    SSLContextRef _ssl;
    NSData* _sendData;
}

static OSStatus _SSLRead(SSLConnectionRef connection, void *data, size_t *dataLength);
static OSStatus _SSLWrite(SSLConnectionRef connection, const void *data, size_t *dataLength);

-(id) init
{
    self = [super init];
    if (self)
    {
        _sock = -1;
        
        _SSLWriteData = [[NSMutableData alloc] init];
        _SSLReadData = [[NSMutableData alloc] init];
    }
    return self;
}

-(void) connect:(NSString*)ip port:(int)port
{
    if (_sock != -1) {
        return;
    }
    
    _sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (_sock == -1) {
        NSLog(@"failed create socket, err=%d", errno);
        return;
    }
    //set sock to non-block
    int flags = fcntl(_sock, F_GETFL, 0);
    if (0 != fcntl(_sock, F_SETFL, flags|O_NONBLOCK)) {
        return;
    }
    
    _ip = ip;
    _port = port;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr([ip UTF8String]);
    addr.sin_port = htons((unsigned short)port);
    
    int ret = connect(_sock, (const struct sockaddr*)&addr, sizeof(addr));
    if (ret == 0) {
        return;
    }
    
    if (errno == EINPROGRESS) {
        [self select:_sock read:NO write:YES callback:^(int result) {
            [self onConnect:result];
        }];
        return;
    }
    return;
}

-(void) select:(int)sock read:(BOOL)read write:(BOOL)write callback:(void (^)(int result))cb
{
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        
        fd_set readSet;
        fd_set writeSet;
        fd_set exceptSet;
        
        if (read) {
            FD_ZERO(&readSet);
            FD_SET(sock, &readSet);
        }
        if (write) {
            FD_ZERO(&writeSet);
            FD_SET(sock, &writeSet);
        }
        FD_ZERO(&exceptSet);
        FD_SET(sock, &exceptSet);
        
        struct timeval timeout;
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        int ret = select(sock+1, read ? &readSet : NULL, write ? &writeSet : NULL, &exceptSet, &timeout);
        if (ret == 0) { //timeout
            cb(-1);
        }
        else if (ret < 0) { //handle error
            cb(errno);
        }
        else { //success
            if (FD_ISSET(sock, &readSet) || FD_ISSET(sock, &writeSet)) {
                cb(0);
            }
            else {
                cb(-1);
            }
        }
    });
}

-(void) asyncRead:(int)sock callback:(void (^)(int result, const void* data, size_t dataLen))cb
{
    [self select:sock read:YES write:NO callback:^(int result) {
       
        if (result != 0) {
            cb(result, NULL, 0);
        }
        else {
            char data[16*1024];
            ssize_t nread = recv(sock, data, sizeof(data), 0);
            if (nread > 0) {
                cb(0, data, nread);
            }
            else if (nread == 0) {
                cb(0, NULL, 0);
            }
            else {
                int err = errno;
                cb(err, NULL, 0);
            }
            return;
        }
    }];
}

-(void) asyncWrite:(const void*)data length:(size_t)length callback:(void (^)(int result))cb
{
    NSData* dataCopy = [NSData dataWithBytes:data length:length];
    [self asyncWriteData:_sock data:dataCopy offset:0 callback:cb];
}

-(void) asyncWriteData:(int)sock data:(NSData*)data offset:(size_t)offset callback:(void (^)(int result))cb
{
    [self select:sock read:NO write:YES callback:^(int result) {
        
        if (result) {   //error
            cb(result);
            return;
        }
        
        size_t length = data.length - offset;
        ssize_t nsend = send(sock, (const char*)data.bytes + offset, length, 0);
        if (nsend > 0) {
            if (nsend < length) { //partial send
                size_t newOffset = offset + nsend;
                [self asyncWriteData:sock data:data offset:newOffset callback:cb];
            }
            else {  //all send
                cb(0);
            }
            return;
        }
        else if (nsend == 0) {  // should not happen
            cb(-1);
            return;
        }
        else {
            int err = errno;
            if (err == EAGAIN || err == EWOULDBLOCK) { //should not happen
                if (offset < data.length){  //retry
                    [self asyncWriteData:sock data:data offset:offset callback:cb];
                }
                else { //all data is sent
                    cb(0);
                }
            }
            else { //notify error happened
                cb(err);
            }
        }
    }];
}

-(void) onConnect:(int)result
{
    if (result != 0) {
        NSLog(@"onConnect, result=%d", result);
        if (_delegate) {
            [_delegate onConnect:self result:result];
        }
        return;
    }
    
    [self initSSLContext];
    [self sslHandshake];
}

-(void) initSSLContext
{
    _ssl = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    
    SSLSetIOFuncs(_ssl, &_SSLRead, &_SSLWrite);
    SSLSetConnection(_ssl, (SSLConnectionRef)self);
}

-(void) sslHandshake
{
    OSStatus err = SSLHandshake(_ssl);
    if (err == noErr) { //success
        if (_delegate) {
            [_delegate onConnect:self result:0];
        }
        return;
    }
    else if (err == errSSLWouldBlock) {
        if (self.SSLWriteData.length > 0) {
            [self asyncWriteData:_sock data:self.SSLWriteData offset:0 callback:^(int result) {
                self.SSLWriteData.length = 0;
                if (result) {
                    NSLog(@"sslHandshake, asyncWriteData fail, result:%d", result);
                    if (_delegate) {
                        [_delegate onConnect:self result:result];
                    }
                    return;
                }
                [self sslHandshake];
            }];
            return;
        }
        else if (self.needRead) {
            [self asyncRead:_sock callback:^(int result, const void *data, size_t dataLen) {
                if (result) {
                    if (_delegate) {
                        [_delegate onConnect:self result:result];
                    }
                    return;
                }
                [self.SSLReadData appendBytes:data length:dataLen];
                [self sslHandshake];
            }];
            return;
        }
        else {
            // something is wrong
            if (_delegate) {
                [_delegate onConnect:self result:-1];
            }
        }
    }
    else {
        NSLog(@"sslHandshake, SSLHandshake fail, err=%d", err);
        // handshake failed
        if (_delegate) {
            [_delegate onConnect:self result:-1];
        }
    }
}

-(void) send:(const void*)data length:(size_t)length
{
    if (!data || !length) {
        return;
    }
    if (_sendData) {
        return; //in progress
    }
    
    _sendData = [NSData dataWithBytes:data length:length];
    [self _send:_sendData offset:0];
}

-(void) _send:(NSData*)data offset:(int)offset
{
    size_t processed = 0;
    size_t sendLength = data.length - offset;
    
    self.needRead = NO;
    NSAssert(self.SSLWriteData.length == 0, @"assert");
    
    OSStatus err = SSLWrite(_ssl, (const char*)data.bytes + offset, sendLength, &processed);
    if (err == noErr) {
        
        //todo: 处理processed和sendLength不相等的情况
        if (self.SSLWriteData.length > 0) {
            [self asyncWrite:self.SSLWriteData.bytes length:self.SSLWriteData.length callback:^(int result) {
                if (_delegate) {
                    [_delegate onSend:self result:result];
                }
            }];
        }
    }
    else if (err == errSSLWouldBlock) {
        
        if (self.SSLWriteData.length > 0) {
            [self asyncWriteData:_sock data:self.SSLWriteData offset:0 callback:^(int result) {
                self.SSLWriteData.length = 0;
                
                if (result != 0) {
                    if (_delegate) {
                        [_delegate onSend:self result:result];
                    }
                    return;
                }
                size_t processed = 0;
                OSStatus err = SSLWrite(_ssl, NULL, 0, &processed);
                if (err == noErr) {
                    //success
                    if (_delegate) {
                        [_delegate onSend:self result:0];
                    }
                }
                else {
                    //fail
                    NSLog(@"SSLWrite with 0 bytes fail, err=%d", err);
                    if (_delegate) {
                        [_delegate onSend:self result:0];
                    }
                }
            }];
        }
        else if (self.needRead) {
            [self asyncRead:_sock callback:^(int result, const void *data, size_t dataLen) {
                [self.SSLReadData appendBytes:data length:dataLen];
                
                if (dataLen < 0) {
                    if (_delegate) {
                        [_delegate onSend:self result:-1];
                    }
                }
                else if (dataLen == 0) {
                    if (_delegate) {
                        [_delegate onSend:self result:-1];
                    }
                }
                
                OSStatus err = SSLWrite(_ssl, NULL, 0, NULL);
                if (err == noErr) {
                    if (_delegate) {
                        [_delegate onSend:self result:0];
                    }
                }
                else {
                    if (_delegate) {
                        [_delegate onSend:self result:-1];
                    }
                }
            }];
        }
        else {
            // should not go here
            if (_delegate) {
                [_delegate onSend:self result:-1];
            }
            return;
        }
    }
    else { // other error
        if (_delegate) {
            [_delegate onSend:self result:-1];
        }
    }
    
}

-(void) recv
{
    char buf[16*1024];
    size_t processed = 0;
    OSStatus err = SSLRead(_ssl, buf, sizeof(buf), &processed);
    if (err == noErr) {
        if (_delegate) {
            [_delegate onRecv:self data:buf length:(int)processed];
        }
        return;
    }
    else if (err == errSSLWouldBlock) {
        [self asyncRead:_sock callback:^(int result, const void *data, size_t dataLen) {
            [self.SSLReadData appendBytes:data length:dataLen];
            [self recv];
        }];
        return;
    }
    else {
        if (_delegate) {
            [_delegate onRecv:self data:NULL length:-1];
        }
    }
}

@end

static OSStatus _SSLRead(SSLConnectionRef connection, void *data, size_t *dataLength)
{
    SSLSocket* _self = (__bridge SSLSocket*)connection;
    NSLog(@"_SSLRead, require-length=%lu, cache-length=%lu", *dataLength, _self.SSLReadData.length);
    
    if (*dataLength == 0) {
        return noErr;
    }
    else if (_self.SSLReadData.length > 0) {
        
        if (*dataLength > _self.SSLReadData.length) {
            memcpy(data, _self.SSLReadData.bytes, _self.SSLReadData.length);
            *dataLength = _self.SSLReadData.length;
            _self.SSLReadData.length = 0;
            return errSSLWouldBlock; //not enough data
        }
        else {
            memcpy(data, _self.SSLReadData.bytes, *dataLength);
            [_self.SSLReadData replaceBytesInRange:NSMakeRange(0, *dataLength) withBytes:NULL length:0];
            return noErr;
        }
    }
    else {
        _self.needRead = YES;
        *dataLength = 0;
        return errSSLWouldBlock;
    }
}

static OSStatus _SSLWrite(SSLConnectionRef connection, const void *data, size_t *dataLength)
{
    SSLSocket* _self = (__bridge SSLSocket*)connection;
    [_self.SSLWriteData appendBytes:data length:*dataLength];
    return errSSLWouldBlock;    //the data has not been sent yet
}

