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
-(void) recv:(void (^)(int err, const void* data, int length))cb;
-(void) send:(const void*)data length:(size_t)length callback:(void (^)(int err))cb;
@end

@protocol SSLSocketDelegate
@required
-(void) onHandshake:(SSLStream*)stream error:(int)error;
-(void) onRecv:(SSLStream*)stream data:(const void*)data length:(int)length;
-(void) onSend:(SSLStream*)stream result:(int)result;
@end
         
@interface SSLStream : NSObject

@property (weak) id<SSLSocketDelegate> delegate;
@property (retain) id<ConnectionDelegate> connection;

// begin SSL handshake
-(void) handshake;

// begin send data to remote
-(void) send:(const void*)data length:(size_t)length;

// begin receive data from remote
-(void) recv;

@end
