//
//  main.m
//  ssl-ios
//
//  Created by misora on 2018/3/7.
//  Copyright © 2018年 misora. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>



class SSLContext
{
public:
    SSLContext();
    bool init();
    
private:
    SSLContextRef _sslContext;
};
