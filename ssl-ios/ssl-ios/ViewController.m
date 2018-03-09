//
//  ViewController.m
//  ssl-ios
//
//  Created by misora on 2018/3/7.
//  Copyright © 2018年 misora. All rights reserved.
//

#import "ViewController.h"
#import "ssl/ssl-ios.hh"
#import "SSLSocketTest.h"

@interface ViewController ()
{
    SSLSocketTest* _socketTest;
}


@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    _socketTest = [[SSLSocketTest alloc] init];
    [_socketTest start];
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
