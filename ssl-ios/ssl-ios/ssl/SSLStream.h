//
//  SSLSocket.h
//  ssl-ios
//
//  Created by misora on 2018/3/8.
//  Copyright © 2018年 misora. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@class SSLStream;

@protocol ConnectionDelegate
@required
//send and recv method should have default timeout interval, or we may hung up when server never return any data
-(void) recv:(void (^)(int err, const void* data, size_t length))cb;
-(void) send:(const void*)data length:(size_t)length callback:(void (^)(int err))cb;
@end

@protocol SSLSocketDelegate
@required
-(void) onHandshake:(SSLStream*)stream error:(int)error;
-(void) onRecv:(SSLStream*)stream error:(int)error data:(const void*)data length:(size_t)length;
-(void) onSend:(SSLStream*)stream error:(int)error;
@end
         
@interface SSLStream : NSObject

@property (weak) id<SSLSocketDelegate> delegate;
@property (retain) id<ConnectionDelegate> connection;

// begin SSL handshake
-(BOOL) handshake:(NSString*)host;

// begin send data to remote
-(void) send:(const void*)data length:(size_t)length;

// begin receive data from remote
-(void) recv;

@end
