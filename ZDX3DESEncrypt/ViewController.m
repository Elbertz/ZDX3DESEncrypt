//
//  ViewController.m
//  ZDX3DESEncrypt
//
//  Created by Elbert on 17/2/14.
//  Copyright © 2017年 Elbert. All rights reserved.
//

#import "ViewController.h"
#import "enc3DESEngine.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
      NSString *result =  [[enc3DESEngine sharedInstance] encryptByZDX3DESWithStr:[NSString stringWithFormat:@"hello World!" ] andKey:nil];
    
    NSString *result2 = [[enc3DESEngine sharedInstance]decEncryptBy3DESWithStr:result];
    
    NSLog(@"加密后：%@\n解密后：%@",result,result2);
    
    
}


- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
