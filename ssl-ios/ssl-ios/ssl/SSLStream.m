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
                self.needRead = NO; //reset the flag for reading
                
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
            NSLog(@"sslHandshake, errSSLWouldBlock but no read or write.");
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
        NSLog(@"send in progress, retry after onSend is invoked");
        return; //in progress
    }
    
    _sendData = [NSData dataWithBytes:data length:length];
    [self _send:_sendData offset:0];
}

-(void) _send:(NSData*)data offset:(size_t)offset
{
    NSAssert(self.needRead == NO && self.SSLWriteData.length == 0, @"invalid internal state");
    
    size_t processed = 0;
    size_t sendLength = !data ? 0 : data.length - offset;
    
    OSStatus err = SSLWrite(_ssl, data ? (const char*)data.bytes + offset : NULL, sendLength, &processed);
    if (err == noErr) {
        if (processed < sendLength) {
            NSAssert(false, @"i'm not sure this could happen");
            [self _send:data offset:offset + processed];    //try again with updated offset
        }
        else {  // all data is sent
            if (_delegate) {
                [_delegate onSend:self error:0];
            }
            return;
        }
    }
    else if (err == errSSLWouldBlock) {
        [self handlePendingIO:^(int error) {
            if (error) {
                if (_delegate) {
                    [_delegate onSend:self error:error];
                }
                return;
            }
            [self _send:nil offset:0];
        }];
    }
    else { // other error
        NSLog(@"SSLWrite return error, err=%d", err);
        if (_delegate) {
            [_delegate onSend:self error:(int)err];
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
            [_delegate onRecv:self error:0 data:buf length:processed];
        }
        return;
    }
    else if (err == errSSLClosedGraceful) {
        if (_delegate) {
            [_delegate onRecv:self error:0 data:NULL length:0];
        }
        return;
    }
    else if (err == errSSLWouldBlock) {
        [self handlePendingIO:^(int error) {
            if (error) {
                if (_delegate) {
                    [_delegate onRecv:self error:error data:NULL length:0];
                }
                return;
            }
            [self recv];
        }];
    }
    else {
        if (_delegate) {
            [_delegate onRecv:self error:(int)err data:NULL length:0];
        }
    }
}

-(void) handlePendingIO:(void (^)(int error))callback
{
    if (self.SSLWriteData.length > 0) {
        [_connection send:self.SSLWriteData.bytes length:self.SSLWriteData.length callback:^(int err) {
            self.SSLWriteData.length = 0;
            
            if (err) {
                NSLog(@"connection send fail, err=%d", err);
                callback(err);
                return;
            }
            callback(0);    // call SSLWrite/SSLRead again make sure previous data is successfully sent
        }];
    }
    else if (self.needRead) {
        [_connection recv:^(int err, const void *data, size_t length) {
            self.needRead = NO; //reset flag
            
            if (err) {
                NSLog(@"connection recv fail, err=%d", err);
                callback(err);
                return;
            }
            else if (length == 0) {
                NSLog(@"connection recv 0 byte");
                callback(-1);
                return;
            }
            [self.SSLReadData appendBytes:data length:length];
            callback(0);
        }];
    }
    else {
        NSAssert(false, @"we don't know we should read or write, maybe internal state is going wrong");
        callback(-1);
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

