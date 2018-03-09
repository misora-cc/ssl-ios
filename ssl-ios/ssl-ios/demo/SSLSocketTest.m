//
//  SSLSocketTest.m
//  ssl-ios
//
//  Created by misora on 2018/3/9.
//  Copyright © 2018年 misora. All rights reserved.
//

#import "SSLSocketTest.h"


@implementation SSLSocketTest
{
    SSLSocket* _socket;
    NSMutableData* _recvData;
}

-(void) start
{
    _socket = [[SSLSocket alloc] init];
    _socket.delegate = self;
    [_socket connect:@"101.227.143.56" port:443];
}

-(void) onConnect:(SSLSocket*)socket result:(int)result
{
    if (result) {
        NSLog(@"SSLSocketTest.onConnect, connect fail, result=%d", result);
        return;
    }
    NSLog(@"SSLSocketTest.onConnect, success");
    
    NSURL* url = [[NSURL alloc] initWithString:@"http://www.qq.com"];
    
    NSMutableString* req = [NSMutableString string];
    [req appendString:@"GET / HTTP/1.1\r\n"];
    [req appendFormat:@"Host: %@\r\n", url.host];
    [req appendString:@"User-Agent: SSL-Socket-Demo\r\n"];
    [req appendString:@"Connection: close\r\n"];
    [req appendString:@"\r\n"];
    
    const char* utf8Req = [req UTF8String];
    [_socket send:utf8Req length:strlen(utf8Req)];
}

-(void) onRecv:(SSLSocket*)socket data:(const void*)data length:(int)length
{
    if (length == 0) {
        NSLog(@"SSLSocketTest.onRecv, length==0, remote disconnected");
        return;
    }
    else if (length < 0) {
        NSLog(@"SSLSocketTest.onRecv, fail, result=%d", length);
        return;
    }
    NSLog(@"SSLSocketTest.onRecv, recv-length=%d", length);
    
    if (!_recvData) {
        _recvData = [[NSMutableData alloc] init];
    }
    [_recvData appendBytes:data length:length];
    [_socket recv]; //continue receiving
}

-(void) onSend:(SSLSocket*)socket result:(int)result
{
    if (result) {
        NSLog(@"SSLSocketTest.onSend, fail, result=%d", result);
        return;
    }
    NSLog(@"SSLSocketTest.onSend, success");
    [_socket recv];
}

@end
