//
//  ViewController.m
//  ssl-ios
//
//  Created by misora on 2018/3/7.
//  Copyright © 2018年 misora. All rights reserved.
//

#import "ViewController.h"
#import "SSLSocketTest.h"

@interface ViewController ()
{
    SSLSocketTest* _socketTest;
    __weak IBOutlet UITextField *_textURL;
    __weak IBOutlet UITextView *_textResponse;
}

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (IBAction)onGet:(id)sender {
    
    if (!_textURL.text || _textURL.text.length == 0) {
        _textResponse.text = @"invalid url";
        return;
    }
    
    _socketTest = [[SSLSocketTest alloc] init];
    [_socketTest start:_textURL.text callback:^(NSString *response) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (response) {
                _textResponse.text = response;
            }
            else {
                _textResponse.text = @"request failed";
            }
            _socketTest = nil;
        });
    }];
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
