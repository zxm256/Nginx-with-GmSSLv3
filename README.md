# Nginx-with-GmSSLv3

[![CI](https://github.com/zhaoxiaomeng/Nginx-with-GmSSLv3/actions/workflows/CI.yml/badge.svg)](https://github.com/zhaoxiaomeng/Nginx-with-GmSSLv3/actions/workflows/CI.yml)
[![Push To Dockerhub](https://github.com/zhaoxiaomeng/Nginx-with-GmSSLv3/actions/workflows/docker-image.yml/badge.svg)](https://github.com/zhaoxiaomeng/Nginx-with-GmSSLv3/actions/workflows/docker-image.yml)

## 介绍

GmSSL 3.0是GmSSL的一个大版本更新，采用了新设计的架构和API，因此无法像之前的版本兼容那些依赖OpenSSL API的应用。为了验证和证明GmSSL 3.0的可用性，有必要让GmSSL 3.0可以兼容最重要的应用类型，即HTTPS服务器。我们选择在Nginx上添加对GmSSL 3.0的支持。因此这个项目对于GmSSL 3.0有非常重要的作用。


## 简单上手

本项目可通过Docker直接使用

doker启动的命令如下：

```
docker run -v $PATH_TO_CERTS:/certs -p 4443:443 -d zhaoxiaomeng/nginx_with_gmsslv3
```

注意，
* Nginx-with-GmSSLv3默认使用的私钥名为signkey.pem 默认使用的证书名为certs.pem

如果没有证书和私钥的话，可以通过以下步骤生成：

* [编译安装GmSSL3.0](#compile_gmssl) 
* 使用tools/reqsign_ext.sh脚本生成所需CA证书、私钥等，参见[这里](#certs) 。


## 编译安装


<p id="compile_gmssl"></p> 

### 编译安装GmSSL3.0

本项目依赖GmSSL3.0，首先需要编译安装GmSSL3.0

```
gmssl@ubuntu:~/nginx_doc$ git clone https://github.com/guanzhi/GmSSL.git
gmssl@ubuntu:~/nginx_doc$ cd GmSSL/
gmssl@ubuntu:~/nginx_doc/GmSSL$ mkdir build
gmssl@ubuntu:~/nginx_doc/GmSSL$ cd build/
gmssl@ubuntu:~/nginx_doc/GmSSL/build$ cmake ..
gmssl@ubuntu:~/nginx_doc/GmSSL/build$ make
gmssl@ubuntu:~/nginx_doc/GmSSL/build$ sudo make install
```

### 编译安装Nginx-with-GmSSLv3

下载源代码
```
gmssl@ubuntu:~/nginx_doc$ git clone https://github.com/zhaoxiaomeng/Nginx-with-GmSSLv3.git
gmssl@ubuntu:~/nginx_doc$ cd Nginx-with-GmSSLv3/
gmssl@ubuntu:~/nginx_doc/Nginx-with-GmSSLv3$ cp auto/configure .
gmssl@ubuntu:~/nginx_doc/Nginx-with-GmSSLv3$ ./configure --with-http_ssl_module --without-http_upstream_zone_module --with-debug
gmssl@ubuntu:~/nginx_doc/Nginx-with-GmSSLv3$ make
gmssl@ubuntu:~/nginx_doc/Nginx-with-GmSSLv3$ sudo make install
```

Nginx会默认安装到`usr/local/nginx`

注意，编译过程中可能存在以下几个问题

1. 提示没有pcre

   ```sudo apt-get install libpcre3 libpcre3-dev```

2. 提示没有gzip

   ``` sudo apt-get install zlib1g zlib1g-dev```

### 配置与运行


<p id="certs"></p> 

#### 数字证书的生成与配置

为了使用国密ssl协议，需要使用GmSSL3.0生成国密数字证书，我们将相关证书生成程序放在了tools目录下，可以运行以下脚本生成证书和私钥

```
gmssl@ubuntu:~/nginx_doc/Nginx-with-GmSSLv3$ cd tools/
gmssl@ubuntu:~/nginx_doc/Nginx-with-GmSSLv3/tools$ ./reqsign_ext.sh 

```
以上命令将会在tools目录下生成一系列文件，包括：
* 根CA私钥 rootcakey.pem
* 根CA证书 rootcacert.pem
* CA私钥 cakey.pem
* CA证书请求 careq.pem
* CA证书 cacert.pem
* 签名私钥 signkey.pem
* 签名证书请求 signreq.pem
* 签名证书 signcert.pem
* 服务端证书 certs.pem
* 客户端私钥 enckey.pem
* 客户端书请求 encreq.pem
* 客户端证书 enccert.pem

#### Nginx配置文件修改

修改配置文件`/usr/local/nginx/conf/nginx.conf`，取消HTTPS Server的注释，并修改ssl_certificat和ssl_certificate_key为上一部分生成的签名证书和签名私钥，如下所示：

```bash
    server {
        listen       443 ssl;
        server_name  localhost;

        ssl_certificate      /home/gmssl/nginx_doc/Nginx-with-GmSSLv3/tools/certs.pem;
        ssl_certificate_key  /home/gmssl/nginx_doc/Nginx-with-GmSSLv3/tools/signkey.pem;

        ssl_session_cache    shared:SSL:1m;
        ssl_session_timeout  5m;

        ssl_ciphers  HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers  on;

        location / {
            root   html;
            index  index.html index.htm;
        }
    }
```

在HTTPS server部分可以增加 `ssl_verify_client off;`来显式的避免客户端证书验证，如下所示：

```bash
    server {
        listen       443 ssl;
        server_name  localhost;

        ssl_certificate      /home/gmssl/nginx_doc/Nginx-with-GmSSLv3/tools/certs.pem;
        ssl_certificate_key  /home/gmssl/nginx_doc/Nginx-with-GmSSLv3/tools/signkey.pem;
        ssl_verify_client off;
        ssl_session_cache    shared:SSL:1m;
        ssl_session_timeout  5m;

        ssl_ciphers  HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers  on;

        location / {
            root   html;
            index  index.html index.htm;
        }
    }
```


#### 运行 Nginx-with-GmSSLv3


```bash
gmssl@ubuntu:~/nginx_doc/Nginx-with-GmSSLv3$ sudo /usr/local/nginx/sbin/nginx
```

在执行以上命令时有可能报错，提示端口已经被占用了，因此需要修改`/usr/local/nginx/conf/nginx.conf`中的配置端口号。

#### 测试Nginx

GmSSL3.0安装后有测试国密SSL协议的功能，在命令行中执行以下命令：

```
gmssl@ubuntu:~/nginx_doc/Nginx-with-GmSSLv3/tools$ gmssl tls13_client -host 127.0.0.1 -port 443
```

其中cacert.pem为上面生成的CA证书的位置。

如果命令执行成功，表明Nginx安装配置成功。


### 调试与输出

#### 调试Nginx

为了让Ngnix更容易调试，在`/usr/local/nginx/conf/nginx.conf` 中增加

```
daemon off;
master_process off;
```

这样nginx总是在前台以独立进程启动。否则nginx会启动多个进程，如果杀进程的时候没有先杀root进程，那么还会生成新的子进程。


#### 查看输出

虽然部分初始化阶段的stderr输出直接输出到屏幕上，但是随着Nginx彻底启动之后，错误信息被输出到Nginx的错误日志上了，也就是

```bash
/usr/local/nginx/logs/error.log
```

有可能随着安装的不同而不同。在调试中可以通过error.log查看错误信息。
