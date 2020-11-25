<?php
/*
* 凌风认证计费出品，允许自由使用
* 个人使用和商用都可以，官网 http://www.lflflf.net
* 发布日期 2019-11-08
*/

error_reporting(0); // 抑制所有错误信息
header("content-Type: text/html; charset=gbk"); // 编码
date_default_timezone_set("Asia/Shanghai"); //时区

//过滤POST值
foreach ($_POST as $key => $value) {
    $_POST[$key] = trim($_POST[$key]);
    $_POST[$key] = addslashes($_POST[$key]);
    $_POST[$key] = htmlspecialchars($_POST[$key], ENT_QUOTES, 'ISO-8859-1');
}

//读配置文件设置值
$config = parse_ini_file("portal.ini", 1);

$l['basip'] = $config['portal']['basip'];
$l['secret'] = $config['portal']['secret'];
$l['success'] = $config['portal']['success'];
$l['fail'] = $config['portal']['fail'];
$l['clear'] = $config['portal']['clear'];
//取Portal版本设置
$l['version'] = $config['portal']['version'];
$l['papchap'] = $config['portal']['papchap'];

//取提交参数
$l['usrname'] = $_POST['usrname'];
$l['passwd'] = $_POST['passwd'];
$l['usrmac'] = $_POST['usrmac'];
$l['usrip'] = $_POST['usrip'];

if (empty($l['usrname']) || empty($l['passwd']) || empty($l['usrmac']) || empty($l['usrip'])) {
    lf_no("提交值不完整！");
}

if (portal_standard($l, $p = 2000, $t = $l['papchap'], $v = (int)$l['version'])) {
    header("location: " . $l['success']);
} else {
    header("location: " . $l['fail']);
}

/*
* 凌风认证计费开源版
* 华为标准portal协议，$l 参数, $p 端口 ,$t 类型pap/chap，$v版本号
*/
function portal_standard($l, $p = 2000, $t = "chap", $v = 2)
{
    $user = $l['usrname'];
    $pass = $l['passwd'];
    $user_ip = $l['usrip'];
    //$user_mac = $l['usrmac'];
    $server_ip = $l['basip'];

    $port = $p;
    $secret = $l['secret'];
    $type = $t;

    $seed = time();
    mt_srand($seed);
    $serialno = mt_rand(1, 65534);
    $reqid = 0;


    if ($type == "pap") {
        //REQ_AUTH
        $buf = pack("C4", $v, 3, 1, 0) . pack("n2", $serialno, $reqid) . pack("N1", ip2long($user_ip)) . pack("n1", 0) . pack("C2", 0, 2);
    } else {
        $buf = pack("C4", $v, 1, 0, 0) . pack("n2", $serialno, $reqid) . pack("N1", ip2long($user_ip)) . pack("n1", 0) . pack("C2", 0, 0);
        $authenticator = lf_bin2hex_md5(md5($buf . pack("C16", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) . pack("H*", bin2hex($secret))));
        $buf = $buf . $authenticator;
        //REQ_CHALLENG 请求的CHALLENG就是Authenticator，v1,v2版本通用，回复的ACK_CHALLENG里面就有区分v1,v2的Authenticator
        //REQ_CHALLENG 发送有错误服务器不回复请求，这样直接serialno失败。
        $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        socket_sendto($sock, $buf, 32, 0, $server_ip, $port);

        //QCK_CHALLENG 5秒内未收到，超时
        $name = "";
        $mybuf = "";
        $timeout = array('sec' => 5, 'usec' => 0);
        socket_set_option($sock, SOL_SOCKET, SO_RCVTIMEO, $timeout);
        socket_set_option($sock, SOL_SOCKET, SO_SNDTIMEO, $timeout);
        socket_recvfrom($sock, $mybuf, 128, 0, $name, $port);
        socket_close($sock); //关闭了，后面还要用重新建立

        if (!$name) lf_no($user_ip . "取serialno失败，[" . $server_ip . "]未回复消息，超时！");
        $redata = unpack("C32", $mybuf);

        // 取得的值继续传
        $re_serialno = hexdec(bin2hex(substr($mybuf, 4, 2)));
        if ($serialno !== $re_serialno) lf_no("serialno值{$serialno}错误,回复值为{$re_serialno}！");

        // 如果没有错误值
        if ($redata[2] === 2 && $redata[16] === 1 && !$redata[15] && $mybuf) {
            $re_authenticator = substr($mybuf, -16); //取回复的CHALLENGE，也就是倒数的16字节
        } else {
            return false;
        }

        //REQ_AUTH
        $buf = pack("C4", $v, 3, 0, 0) . pack("n1", $serialno) . substr($mybuf, 6, 2) . pack("N1", ip2long($user_ip)) . pack("n1", 0) . pack("C2", 0, 3);
    }

    $value = ""; // 有三个attr值
    // 用户名
    $value = $value . pack("C2", 1, strlen($user) + 2) . pack("H*", bin2hex($user));
    if ($type == "pap") {
        // pap密码
        $value = $value . pack("C2", 2, strlen($pass) + 2) . pack("H*", bin2hex($pass));
    } else {
        // chap密码 chap password=md5(chapid+password+callenge)
        $chapid = substr($mybuf, 7, 1);
        $callenge = $re_authenticator;
        $chap_password = lf_bin2hex_md5(md5($chapid . $pass . $callenge));
        // callenge密码3
        $value = $value . pack("C2", 3, 16 + 2) . $callenge;
        // chap_password密码4
        $value = $value . pack("C2", 4, 16 + 2) . $chap_password;
    }

    $authenticator = lf_bin2hex_md5(md5($buf . pack("C16", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) . $value . pack("H*", bin2hex($secret))));

    if ($v == 2) {
        $buf = $buf . $authenticator . $value;
    } else {
        $buf = $buf . $value;
    }


    $sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
    socket_sendto($sock, $buf, strlen($buf), 0, $server_ip, $port);
    // 5秒内未收到，超时
    $name = "";
    $mybuf = "";
    $timeout = array('sec' => 5, 'usec' => 0);
    socket_set_option($sock, SOL_SOCKET, SO_RCVTIMEO, $timeout);
    socket_set_option($sock, SOL_SOCKET, SO_SNDTIMEO, $timeout);
    socket_recvfrom($sock, $mybuf, 128, 0, $name, $port);
    if (!$name) {
        socket_close($sock);
        lf_no("[" . $server_ip . "]未回复消息，超时！");
    }
    $redata = unpack("C16", $mybuf);

    /*
     * 当Type值为 4 时
     *  ErrCode＝0，表示AC设备告诉Portal Server此用户认证成功；
        ErrCode＝1，表示AC设备告诉Portal Server此用户认证请求被拒绝；
        ErrCode＝2，表示AC设备告诉Portal Server此链接已建立；
        ErrCode＝3，表示AC设备告诉Portal Server有一个用户正在认证过程中，请稍后再试；
        ErrCode＝4 ，表示AC设备告诉Portal Server此用户认证失败（发生错误）；
     */
    if ($redata[2] == 4) {
        while (true) {
            if ($redata[15] == 1 || $redata[15] == 4) {  //Radius服务器拒绝
                socket_close($sock);
                lf_no("认证失败");
            }
            if (!$redata[15]) break; //0表示认证成功

            if ($redata[15] == 2 || $redata[15] == 3) {  //2和3表示还在忙
                // 5秒内未收到，超时
                $name = "";
                $mybuf = "";
                $timeout = array('sec' => 5, 'usec' => 0);
                socket_set_option($sock, SOL_SOCKET, SO_RCVTIMEO, $timeout);
                socket_set_option($sock, SOL_SOCKET, SO_SNDTIMEO, $timeout);
                socket_recvfrom($sock, $mybuf, 128, 0, $name, $port);
                if (!$name) {
                    socket_close($sock);
                    lf_no("[" . $server_ip . "]未回复消息，超时！");
                }
                $redata = unpack("C16", $mybuf);
            } else {
                socket_close($sock);
                lf_no("ErrCode值为" . $redata[15] . "，不清楚这是什么意思！");
            }
        }
    }

    // 如果没有错误值15是ErrCode，为0表示没有错误。
    if (!$redata[15] && $mybuf) {
        //确认收到认证成功消息，锐捷不发这个就3分钟后离线了，华为ME60不下发则30秒后就离线
        //取ACK_AUTH的ReqID
        $reqid = hexdec(bin2hex(substr($mybuf, 6, 2)));

        if ($type == "pap") {
            //AFF_ACK_AUTH
            $buf = pack("C4", $v, 7, 1, 0) . pack("n2", $serialno, $reqid) . pack("N1", ip2long($user_ip)) . pack("n1", 0) . pack("C2", 0, 0);
        } else {
            $buf = pack("C4", $v, 7, 0, 0) . pack("n2", $serialno, $reqid) . pack("N1", ip2long($user_ip)) . pack("n1", 0) . pack("C2", 0, 0);
        }
        $authenticator = lf_bin2hex_md5(md5($buf . pack("C16", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) . pack("H*", bin2hex($secret))));
        if ($v == 2) $buf = $buf . $authenticator;
        socket_sendto($sock, $buf, strlen($buf), 0, $server_ip, $port);
        socket_close($sock);
        return true;
    } else {
        socket_close($sock);
        return false;
    }

}

/*
*计算MD5
*/
function lf_bin2hex_md5($md5)
{
    $buf = "";
    $ii = 0;
    $authex = "";
    for ($i = 0; $i < 16; $i++) {
        $authex .= "\$buf=\$buf.pack(\"c1\",0x" . $md5 [$ii] . $md5 [$ii + 1] . ");";
        $ii = $ii + 2;
    }
    eval ($authex);
    return $buf;
}

/*
 * 失败跳转提示
 */


function lf_no($str = "", $retry = 0)
{
    $serverhttp = "http://";
    if (preg_match("/MQQbrowser/i", $_SERVER['HTTP_USER_AGENT']) && $_SERVER['HTTPS']) $serverhttp = "https://";

    echo lf_infohtml();


    echo "<iframe id=\"re\" name=\"re\" style=\"display:none\" src=\"\"></iframe>";

    if (!$retry) {
        $re = "document.getElementById(\\\"re\\\").src=\\\"" . $_POST['clear'] . "\\\"";
    } else {
        $re = "window.open(\\\"" . $serverhttp . "www.qq.com/?time=" . time() . "\\\",\\\"_top\\\")";
        $str .= " 稍等自动重试！";
    }

    echo "<script type='text/javascript'>portal_func('$str')</script>";

    echo "<script type='text/javascript'>num('$re');setInterval(\"num('$re')\", 1000);</script>";
    echo "</body></html>";
    die;

}

function lf_infohtml()
{
    return "<html>
<head>
    <meta http-equiv=\"content-type\" content=\"text/html;charset=gbk\"/>
    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>
</head>
<body style=\"margin:0 auto\">
<style type=\"text/css\">
    body {
        font-family: \"微软雅黑\", \"宋体\", \"黑体\", Helvetica, Arial, sans-serif;
        font-size: 12px;
    }
</style>
<script type=\"text/javascript\">
    if (document.body.scrollWidth > 800) {
        document.body.style.width = \"800px\";
    } else {
        document.body.style.width = \"100%\";
    }
    var portal_layer = document.createElement(\"div\");
    portal_layer.id = \"portal_layer\";
    var mydata = \"\";
    var myrun = \"\";

    function portal_func(data) {
        mydata = data;
        var style =
            {
                background: \"#ffeccc\",
                zIndex: 10,
                marginTop: 100,
                width: (parseInt(document.body.style.width) - 200) + \"px\",
                display: \"block\",
                padding: \"5px 5px 5px 5px\",
                border: \"5px solid #e8b04d\",
                borderRadius: \"10px\",
                paddingBottom: \"5px\"
            }
        for (var i in style)
            portal_layer.style[i] = style[i];
        if (document.getElementById(\"portal_layer\") == null) {
            document.body.appendChild(portal_layer);
            portal_layer.innerHTML = data;
            portal_layer.style.textAlign = \"center\";
            portal_layer.style.lineHeight = \"25px\";
            portal_layer.onclick = function () {
                if (myrun != \"\") eval(myrun);
            }
        }

    }

    var n = 5;

    function num(run) {
        myrun = run;
        if (n == 0) {
            if (run != \"\") eval(run);
            window.history.back();
        } else {
            portal_layer.innerHTML = mydata + \"<br>在\" + n + \" 秒后自动跳转！\";
            n--;
        }
    }

</script>
";
}
