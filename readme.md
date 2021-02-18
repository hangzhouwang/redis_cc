# redis  cc 攻击防护
redis cc攻击防护


## 使用方法

```php

//下载文件放入到网站目录，本例为:bootstrap目录，index.php 引入

require __DIR__.'/../bootstrap/cc_guard.php';
```



## 参数配置

```php
 
   // 根据机器实际配置，调整参数
    define('REDIS_HOST', '127.0.0.1');
    define('REDIS_PORT', 6379);
    define('REDIS_PASS', '');  //密码
    define('REDIS_DB', 10);  //redis db
    define('HASH_KEY', '90VXOu1KT8+aVNw30RUsVgogg4V');

    ...
    //CC攻击停止后会尽快解除验证码，回到正常状态
    //防CC配置
    $IPmax = 120; //开启验证码条件 值>=php最大进程数，适当设置更大会降低验证码触发条件，但会增大502错误几率（php挂起）
    $IPfor = 60; //周期 这个值基本不用动 过期时间60秒
    $IPban = 60; //扔入黑名单 60秒内访问超过60次即拉黑IP
    $banTime = 3600 * 24; //黑名单时长 扔小黑屋时长，24小时
```

## 防护截图

![](https://hzwstore.oss-cn-hangzhou.aliyuncs.com/cc01.png)

![](https://hzwstore.oss-cn-hangzhou.aliyuncs.com/cc02.png)