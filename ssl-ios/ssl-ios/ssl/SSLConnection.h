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



@end
