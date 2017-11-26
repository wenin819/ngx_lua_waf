## ngx_lua_waf

ngx_lua_waf是我刚入职趣游时候开发的一个基于ngx_lua的web应用防火墙。

代码很简单，开发初衷主要是使用简单，高性能和轻量级。

现在开源出来，遵从MIT许可协议。其中包含我们的过滤规则。如果大家有什么建议和想fa，欢迎和我一起完善。

### 用途：
    	
	防止sql注入，本地包含，部分溢出，fuzzing测试，xss，SSRF等web攻击
	防止svn/备份之类文件泄漏
	防止ApacheBench之类压力测试工具的攻击
	屏蔽常见的扫描黑客工具，扫描器
	屏蔽异常的网络请求
	屏蔽图片附件类目录php执行权限
	防止webshell上传

### 推荐安装:

推荐使用lujit2.1做lua支持

ngx_lua如果是0.9.2以上版本，建议正则过滤函数改为ngx.re.find，匹配效率会提高三倍左右。


### 使用说明：

nginx安装路径假设为:/usr/local/nginx/conf/

把ngx_lua_waf下载到/usr/local/nginx/lua/目录下，解压命名为waf

在nginx.conf的http段添加

        include /usr/local/nginx/lua/waf/include/auth_init.conf;

配置config.lua里的waf规则目录(一般在waf/wafconf/目录下)

        RulePath = "/usr/local/nginx/lua/waf/wafconf/"

绝对路径如有变动，需对应修改

然后重启nginx即可


### 配置文件详细说明：

详见config.lua的注释

#### URL鉴权

1. 配置人机验证页面：/auth；如果走默认方式，在luosimao.com中请申请对应的site key，在auth.html中进行替换。
2. 在authurl中配置受保护资源入口，入口页面验证不通过，会跳转到/auth页面。配置行加前缀即可“->:”。
3. 在authurl中配置普通受保护资源，直接配置，验证不通过，直接返回503。

核心原理

通过一个入口，人机验证页面，进行人机识别，识别成功后，通过设置两个cookie做为认证标识，一个为随机数，一个为签名。
当cookie中没有认证标识，或认证标识签名不对，则说明是异常请求，跳到认证页面进行认证。
通过对认证页面进行限流，以及对认证签名进行限流，进而达到防CC攻击的效果。

备注：此功能核心原理参见博文：﻿[﻿通过nginx配置文件抵御攻击，防御CC攻击的经典思路！](http://www.92csz.com/30/1255.html)

### 检查规则是否生效

部署完毕可以尝试如下命令：        
  
        curl http://xxxx/test.php?id=../etc/passwd
        返回"Please go away~~"字样，说明规则生效。

注意:默认，本机在白名单不过滤，可自行调整config.lua配置


### 效果图如下：

![sec](http://i.imgur.com/wTgOcm2.png)

![sec](http://i.imgur.com/DqU30au.png)

### 规则更新：

考虑到正则的缓存问题，动态规则会影响性能，所以暂没用共享内存字典和redis之类东西做动态管理。

规则更新可以把规则文件放置到其他服务器，通过crontab任务定时下载来更新规则，nginx reload即可生效。以保障ngx lua waf的高性能。

只记录过滤日志，不开启过滤，在代码里在check前面加上--注释即可，如果需要过滤，反之

### 一些说明：

	过滤规则在wafconf下，可根据需求自行调整，每条规则需换行，或者用|分割
	
		args里面的规则get参数进行过滤的
		url是只在get请求url过滤的规则
		post是只在post请求过滤的规则
		whitelist是白名单，里面的url匹配到不做过滤		
		user-agent是对user-agent的过滤规则
	

	默认开启了get和post过滤，需要开启cookie过滤的，编辑waf.lua取消部分--注释即可
	
	日志文件名称格式如下:虚拟主机名_sec.log


## Copyright

<table>
  <tr>
    <td>Weibo</td><td>神奇的魔法师</td>
  </tr>
  <tr>
    <td>Forum</td><td>http://bbs.linuxtone.org/</td>
  </tr>
  <tr>
    <td>Copyright</td><td>Copyright (c) 2013- loveshell</td>
  </tr>
  <tr>
    <td>License</td><td>MIT License</td>
  </tr>
</table>
	
感谢ngx_lua模块的开发者[@agentzh](https://github.com/agentzh/)，春哥是我所接触过开源精神最好的人
