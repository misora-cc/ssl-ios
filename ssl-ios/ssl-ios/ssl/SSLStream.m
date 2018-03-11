#import "SSLStream.h"
#include <sys/time.h>
#include <sys/select.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <fcntl.h>
#include <arpa/inet.h>


@interface SSLStream ()

@property (assign) BOOL needRead;
@property (retain, readonly) NSMutableData* SSLWriteData;
@property (retain, readonly) NSMutableData* SSLReadData;

@end

@implementation SSLStream
{
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
        _SSLWriteData = [[NSMutableData alloc] init];
        _SSLReadData = [[NSMutableData alloc] init];
    }
    return self;
}

-(BOOL) handshake
{
    if (!_connection || !_delegate) {
        return NO;
    }
    [self initSSLContext];
    [self sslHandshake];
    return YES;
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
            [_delegate onHandshake:self error:0];
        }
        return;
    }
    else if (err == errSSLWouldBlock) {
        if (self.SSLWriteData.length > 0) {
            [_connection send:self.SSLWriteData.bytes length:self.SSLWriteData.length callback:^(int err) {
                self.SSLWriteData.length = 0;
                if (err) {
                    NSLog(@"sslHandshake, send data fail, err:%d", err);
                    if (_delegate) {
                        [_delegate onHandshake:self error:err];
                    }
                    return;
                }
                [self sslHandshake];
            }];
            return;
        }
        else if (self.needRead) {
            [_connection recv:^(int err, const void *data, size_t length) {
                if (err || length == 0) {
                    NSLog(@"sslHandshake, recv fail, err=%d, length=%lu", err, length);
                    if (_delegate) {
                        [_delegate onHandshake:self error:err];
                    }
                    return;
                }
                [self.SSLReadData appendBytes:data length:length];
                [self sslHandshake];
            }];
            return;
        }
        else {
            // something is wrong
            if (_delegate) {
                [_delegate onHandshake:self error:-1];
            }
        }
    }
    else {
        NSLog(@"sslHandshake, SSLHandshake fail, err=%d", err);
        // handshake failed
        if (_delegate) {
            [_delegate onHandshake:self error:(int)err];
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
                    NSLog(@"SSLWrite with 0 bytes fail, err=%d", (int)err);
                    if (_delegate) {
                        [_delegate onSend:self result:0];
                    }
                }
            }];
        }
        else if (self.needRead) {
            [self asyncRead:_sock callback:^(int result, const void *data, size_t dataLen) {
                [self.SSLReadData appendBytes:data length:dataLen];
                
                if (result != 0) {
                    if (_delegate) {
                        [_delegate onSend:self result:result];
                    }
                }
                else if (dataLen == 0) {
                    if (_delegate) {
                        [_delegate onSend:self result:-1];
                    }
                }
                
                size_t processed = 0;
                OSStatus err = SSLWrite(_ssl, NULL, 0, &processed);
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
    else if (err == errSSLClosedGraceful) {
        if (_delegate) {
            [_delegate onRecv:self data:buf length:0];
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
    SSLStream* _self = (__bridge SSLStream*)connection;
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
    SSLStream* _self = (__bridge SSLStream*)connection;
    [_self.SSLWriteData appendBytes:data length:*dataLength];
    return errSSLWouldBlock;    //the data has not been sent yet
}

