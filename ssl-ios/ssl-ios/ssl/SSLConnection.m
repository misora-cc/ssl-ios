//
//  SSLConnection.m
//  ssl-ios
//
//  Created by misora on 2018/3/10.
//  Copyright © 2018年 misora. All rights reserved.
//

#import "SSLConnection.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>

@implementation SSLConnection
{
    NSString *_host;
    int _port;
    int _sock;
}

-(void) connect:(NSString *)host port:(int)port callback:(void (^)(int))cb
{
    if (!host || !port) {
        return;
    }
    
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        
        struct sockaddr_in connectAddr;
        if ([self getIPByName:[host UTF8String]  addr:&connectAddr]) {
            cb(-1);
            return;
        }
        
        _sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (_sock == -1) {
            cb((int)errno);
            return;
        }
        
        int flag = fcntl(_sock, F_GETFL);
        fcntl(_sock, F_SETFL, flag | O_NONBLOCK);
        
        int ret = connect(_sock, (struct sockaddr*)&connectAddr, sizeof(connectAddr));
        if (ret == 0) {
            cb(0);
            return;
        }
        else
        {
            int err = (int)errno;
            if (err == EINPROGRESS) {
                // if the socket is writable, which indicates connection is established
                [self select:_sock read:NO write:YES callback:^(int result) {
                    cb(result);
                }];
                return;
            }
            else {
                cb(err);
                return;
            }
        }
    });
}

-(BOOL) getIPByName:(const char*)hostname addr:(struct sockaddr_in*)addr
{
    struct addrinfo hint;
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
    hint.ai_flags = AI_ADDRCONFIG;

    BOOL ret = NO;
    struct addrinfo* addrInfo = NULL;
    getaddrinfo(hostname, NULL, &hint, &addrInfo);
    if (addrInfo) {
        for (struct addrinfo* a = addrInfo; a != NULL; a = a->ai_next) {
            if (a->ai_family == AF_INET) {
                ret = YES;
                memcpy(addr, a->ai_addr, a->ai_addrlen);
                break;
            }
        }
        freeaddrinfo(addrInfo);
    }
    return ret;
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
            if (FD_ISSET(sock, &exceptSet)) {
                cb(-1);
            }
            else if (FD_ISSET(sock, &readSet) || FD_ISSET(sock, &writeSet)) {
                cb(0);
            }
            else {
                cb(-1);
            }
        }
    });
}


@end
