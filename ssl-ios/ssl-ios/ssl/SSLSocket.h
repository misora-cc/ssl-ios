//
//  SSLSocket.h
//  ssl-ios
//
//  Created by misora on 2018/3/8.
//  Copyright © 2018年 misora. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@class SSLSocket;



@protocol SSLSocketDelegate
@required
-(void) onConnect:(SSLSocket*)socket result:(int)result;
-(void) onRecv:(SSLSocket*)socket data:(const void*)data length:(int)length;
-(void) onSend:(SSLSocket*)socket result:(int)result;
@end
         
@interface SSLSocket : NSObject

@property (weak) id<SSLSocketDelegate> delegate;

-(void) connect:(NSString*)ip port:(int)port;

-(void) send:(const void*)data length:(size_t)length;

-(void) recv;

@end
