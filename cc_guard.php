<?php

define('CC_GUARD', true);

if (CC_GUARD) {
    //REDIS连接参数
    define('REDIS_HOST', 'r-bp16xs6nhgihugsvih.redis.rds.aliyuncs.com');
    define('REDIS_PORT', 6379);
    define('REDIS_PASS', 'Hzw123456');
    define('REDIS_DB', 10);

    define('HASH_KEY', '90VXOu1KT8+aVNw30RUsVgogg4V');
    define('PASS_KEY', 'pass_');
    define('BAN_KEY', 'ban_');

    //CC攻击停止后会尽快解除验证码，回到正常状态
    //防CC配置
    $IPmax = 120; //开启验证码条件 值>=php最大进程数，适当设置更大会降低验证码触发条件，但会增大502错误几率（php挂起）
    $IPfor = 60; //周期 这个值基本不用动 过期时间60秒
    $IPban = 60; //扔入黑名单 60秒内访问超过60次即拉黑IP
    $banTime = 3600 * 24; //黑名单时长 扔小黑屋时长，24小时
    $ip = ip();
    //连接本地的 Redis 服务
    $redis = new Redis();
    $redis->connect(REDIS_HOST, REDIS_PORT);
    if(REDIS_PASS) {
        $redis->auth(REDIS_PASS);
    }
    $redis->select(REDIS_DB);

    //拦截黑名单
    if (!$ip || $redis->exists(BAN_KEY . $ip)) {
        forbiddenHtml($ip);
        exit();
    }
    //扔黑名单检测
    if ($redis->get(PASS_KEY . $ip) >= $IPban) {
        $redis->setex(BAN_KEY . $ip, $banTime, '1');
    }
    if ($redis->exists(PASS_KEY . $ip)) {
        //记录IP 自增1
        $redis->incrby(PASS_KEY . $ip, 1);
    } else {
        $redis->setex(PASS_KEY . $ip, $IPfor, 1);
    }

    //按需开启防CC 小黑屋IP不会触发该条件，所以当 $IPfor 时间过期后就会解除验证码。
    if (count($redis->keys(PASS_KEY . "*")) > $IPmax) {
        //拦截代码
        if (!$_COOKIE['key'] || !$_COOKIE['code'] || $_COOKIE['key'] != md5($ip . $_COOKIE['code'] . HASH_KEY)) {
            if ($_GET['code']) {
                $key = md5($ip . $_GET['code'] . HASH_KEY);
                setcookie("key", $key);
                $_COOKIE['key'] = $key;
                Header("HTTP/1.1 303 See Other");
                Header("Location: /");
            } else {
                $code = rand(10000, 99999);
                setcookie("code", $code);
                renderCodeHtml($code);
            }
            exit();
        }
    }

}

/**
 * @param $ip
 *
 */
function forbiddenHtml($ip)
{
    echo <<<EOF
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="filetype" content="1"/>
<meta name="publishedtype" content="1"/>
<meta name="pagetype" content="2"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>禁止访问</title>
<style>
*{margin:0;padding:0;color:#444;}
body{font-size:14px;font-family:"宋体"}
.main{width:600px;margin:10% auto;}
.title{background: #20a53a;color: #fff;font-size: 16px;height: 40px;line-height: 40px;padding-left: 20px;}
.content{background-color:#f3f7f9; height:260px;border:1px dashed #c6d9b6;padding:20px}
.t1{border-bottom: 1px dashed #c6d9b6;color: #ff4000;font-weight: bold; margin: 0 0 20px; padding-bottom: 18px;}
.t2{margin-bottom:8px; font-weight:bold;color:#666}
ol{margin:0 0 20px 22px;padding:0;}
ol li{line-height:30px;}
@media screen and (max-width: 480px) {
 .main{width:90%;margin:10% auto;}
}
</style>
</head>

<body>
	<div class="main">
		<div class="title">禁止访问</div>
		<div class="content">
				<p class="t1">您的请求被禁止！IP:$ip</p>
			<p class="t2">可能原因：</p>
			<ol>
				<li>请求过于频繁!</li>
				<li>Ip地址非法!</li>
			</ol>
			<p class="t2">如何解决：</p>
			<ol>
				<li>拨号上网请重新拨号尝试</li>
				<li>请联系网站管理员</li>
			</ol>
		</div>
	</div>
</body>
</html>
EOF;
}

/**
 * @param $cc
 */
function renderCodeHtml($cc)
{
    echo <<<EOF
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="filetype" content="1"/>
<meta name="publishedtype" content="1"/>
<meta name="pagetype" content="2"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no">
<title>请输入验证码</title>
<style>
*{margin:0;padding:0;color:#444;}
body{font-size:14px;font-family:"宋体"}
.main{width:600px;margin:10% auto;}
.title{background: #20a53a;color: #fff;font-size: 16px;height: 40px;line-height: 40px;padding-left: 20px;}
.content{background-color:#f3f7f9; height:150px;border:1px dashed #c6d9b6;padding:20px}
.t1{border-bottom: 1px dashed #c6d9b6;color: #ff4000;font-weight: bold; margin: 0 0 20px; padding-bottom: 18px;}
.t2{margin-bottom:8px; font-weight:bold;color:#666}
ol{margin:0 0 20px 0px;padding:0;list-style:none}
ol li{line-height:30px;padding-bottom:10px}
ol li  input {border:1px #dedede solid;height:30px;outline:none;padding:0 10px;}
button {border:1px #dedede solid;padding:5px 10px;cursor: pointer}

@media screen and (max-width: 480px) {
 .main{width:90%;margin:10% auto;}
}

</style>
</head>

<body>
	<div class="main">
		<div class="title">请输入验证码</div>
		<div class="content">
			<p class="t1">服务器访问出现异常，您需要输入验证码才能继续！</p>
			<p class="t2">验证码：$cc</p>
			<form action="">
		     <ol>
		        <li><input type="text" name="code" value="" ></li>
		        <li><button type="submit">继续访问</button></li>
		     </ol>
		    </form>
		</div>
	</div>
</body>
</html>
EOF;
}

/**
 * @return mixed|string
 * 获取ip
 */
function ip()
{
    if (getenv('HTTP_CLIENT_IP') && strcasecmp(getenv('HTTP_CLIENT_IP'), 'unknown')) {
        $ip = getenv('HTTP_CLIENT_IP');
    } elseif (getenv('HTTP_X_FORWARDED_FOR') && strcasecmp(getenv('HTTP_X_FORWARDED_FOR'), 'unknown')) {
        $ip = getenv('HTTP_X_FORWARDED_FOR');
    } elseif (getenv('REMOTE_ADDR') && strcasecmp(getenv('REMOTE_ADDR'), 'unknown')) {
        $ip = getenv('REMOTE_ADDR');
    } elseif (isset($_SERVER['REMOTE_ADDR']) && $_SERVER['REMOTE_ADDR'] && strcasecmp($_SERVER['REMOTE_ADDR'], 'unknown')) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    return preg_match('/[\d\.]{7,15}/', $ip, $matches) ? $matches [0] : '';
}
