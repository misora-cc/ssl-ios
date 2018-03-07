//
//  main.m
//  ssl-ios
//
//  Created by misora on 2018/3/7.
//  Copyright © 2018年 misora. All rights reserved.
//

#import "ssl-ios.h"

SSLContext::SSLContext()
:_sslContext(nullptr)
{
    
}

bool SSLContext::init()
{
    
    SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    
    return true;
}
