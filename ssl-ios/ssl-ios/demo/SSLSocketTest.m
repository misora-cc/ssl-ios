//
//  SSLSocketTest.m
//  ssl-ios
//
//  Created by misora on 2018/3/9.
//  Copyright © 2018年 misora. All rights reserved.
//

#import "SSLSocketTest.h"
#import "SSLConnection.h"

@implementation SSLSocketTest
{
    NSURL* _url;
    SSLStream* _sslStream;
    SSLConnection* _connection;
    NSMutableData* _recvData;
}

-(void) start
{
    _url = [NSURL URLWithString:@"https://github.com"];
    _connection = [[SSLConnection alloc] init];
    [_connection connect:_url.host port:443 callback:^(int err) {
        
        if (err) {
            NSLog(@"connect fail, err=%d", err);
            return;
        }
        NSLog(@"connect success, start ssl handshake");
        _sslStream.delegate = self;
        _sslStream.connection = _connection;
        [_sslStream handshake];
    }];
}

-(void) onHandshake:(SSLStream*)stream error:(int)error
{
    if (error) {
        NSLog(@"handshake fail, err=%d", error);
        return;
    }
    NSLog(@"handshake success, start sending request");
    
    NSMutableString* req = [NSMutableString string];
    [req appendFormat:@"GET %@ HTTP/1.1\r\n", _url.path];
    [req appendFormat:@"Host: %@\r\n", _url.host];
    [req appendString:@"User-Agent: SSL-Socket-Demo\r\n"];
    [req appendString:@"Connection: close\r\n"];
    [req appendString:@"\r\n"];
    
    const char* utf8Req = [req UTF8String];
    [_sslStream send:utf8Req length:strlen(utf8Req)];
}

-(void) onSend:(SSLStream*)stream error:(int)error
{
    if (error) {
        NSLog(@"onSend, fail, err=%d", error);
        return;
    }
    NSLog(@"onSend, sucecss, start receiving response");
    
    [_sslStream recv];
}

-(void) onRecv:(SSLStream*)stream error:(int)error data:(const void*)data length:(size_t)length
{
    if (error) {
        NSLog(@"recv fail, err=%d", error);
        return;
    }
    else if (length == 0) {
        NSLog(@"onRecv, length==0, remote disconnected");
        NSLog(@"response:\n");
        if (!_recvData) {
            NSLog(@"(empty)");
        }
        else {
            NSString* content = [[NSString alloc] initWithData:_recvData encoding:NSUTF8StringEncoding];
            NSLog(@"%@", content);
        }
        return;
    }
    NSLog(@"onRecv, length=%lu", length);
    
    if (!_recvData) {
        _recvData = [[NSMutableData alloc] init];
    }
    [_recvData appendBytes:data length:length];
    [_sslStream recv]; // continue receiving
}

@end
