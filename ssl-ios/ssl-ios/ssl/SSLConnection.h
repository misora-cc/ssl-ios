//
//  SSLConnection.h
//  ssl-ios
//
//  Created by misora on 2018/3/10.
//  Copyright © 2018年 misora. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "SSLStream.h"

@interface SSLConnection : NSObject <ConnectionDelegate>

-(void) connect:(NSString*)host port:(int)port callback:(void (^)(int err))cb;

-(void) recv:(void (^)(int err, const void* data, size_t length))cb;

-(void) send:(const void*)data length:(size_t)length callback:(void (^)(int err))cb;


@end
