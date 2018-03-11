//
//  SSLSocketTest.h
//  ssl-ios
//
//  Created by misora on 2018/3/9.
//  Copyright © 2018年 misora. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SSLStream.h"

@interface SSLSocketTest : NSObject <SSLSocketDelegate>

-(void) start;

-(void) onHandshake:(SSLStream*)stream error:(int)error;
-(void) onRecv:(SSLStream*)stream error:(int)error data:(const void*)data length:(size_t)length;
-(void) onSend:(SSLStream*)stream error:(int)error;

@end
