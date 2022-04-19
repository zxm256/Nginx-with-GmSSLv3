# Nginx-with-GmSSLv3

[TOC]



## 介绍

GmSSL 3.0是GmSSL的一个大版本更新，采用了新设计的架构和API，因此无法像之前的版本兼容那些依赖OpenSSL API的应用。为了验证和证明GmSSL 3.0的可用性，有必要让GmSSL 3.0可以兼容最重要的应用类型，即HTTPS服务器。我们选择在Nginx上添加对GmSSL 3.0的支持。因此这个项目对于GmSSL 3.0有非常重要的作用。

## 编译与安装

将`auto/configure`拷贝到根目录，然后执行

```bash
./configure --with-http_ssl_module --without-http_upstream_zone_module --with-debug
make
sudo make install
```

Nginx会默认安装到`usr/local/nginx`

注意，在执行`sudo /usr/local/nginx/sbin/nginx`时有可能报错，端口已经被占用了，因为我们可能装了IPFS等客户端，确实有可能被占用了，因此需要更换一下`conf/nginx.cong`中的配置端口号。

和openssl有关的编译文件在`auto/lib/openssl`下面，其中`conf`是默认的编译文件，其他几个文件都是针对Windows或者bcc、msvc的编译器的，在Mac下测试删除了make, makefile 几个文件还是能够正常配置编译的。

当前的修改只是初步修改了openssl的部分，应该将其中的openssl, OPENSSL等命名都修改为gmssl, GMSSL。这个版本没有必要再同时支持OpenSSL了。

## 配置Nginx

首先为了让Ngnix更容易调试，在`/usr/local/nginx/conf/nginx.conf` 中增加

```
daemon off;
master_process off;
```

这样nginx总是在前台以独立进程启动。否则nginx会启动多个进程，如果杀进程的时候没有先杀root进程，那么还会生成新的子进程。

在HTTPS server部分可以增加 `ssl_verify_client off;`来显式的避免客户端证书验证。

注意，Nginx的很多配置信息会导致对SSL模块(src/event/ngx_event_openssl.c)的调用，因此SSL模块需要能够正确解析并应对异常情况。

## 查看输出

虽然部分初始化阶段的stderr输出直接输出到屏幕上，但是随着Nginx彻底启动之后，错误信息被输出到Nginx的错误日志上了，也就是

```bash
/usr/local/nginx/logs/error.log
```

有可能随着安装的不同而不同。在调试中可以通过error.log查看错误信息。

## 存在的一些问题

目前GmSSL 3.0缺少一些特性，其中有些特性有可能不会支持。需要处理Nginx对这些特性的调用，并测试哪些特性对Nginx是可选的，不支持不会引发问题。

* 非阻塞模式。目前GmSSL仅实现了阻塞模式，如果要支持非阻塞模式，需要对结构做比较大的调整，因此暂时可能不会支持这个功能。我们采取的办法是对Nginx传入的socket进行修改，将其从非阻塞模式改为阻塞模式，但是是否会对Nginx造成某些不良影响，或者是否可以直接配置Nginx为阻塞模式呢？
* SESSION：GmSSL目前不支持SESSION。SESSION主要是优化了浏览器断续访问场景的握手延迟，对于长链接时间、高吞吐量的传输没有效果。支持SESSION需要增加SESSION存储的管理工作，GmSSL可能短时间之内不会支持SESSON，主要取决于是否有真实需求（比如集成在浏览器中）。
* 握手重协商：不确定，可能没有必要。
* Session Ticket，Ticket是对SESSION的效率的进一步优化，也降低了服务器的管理难度。但是安全性更低。似乎没有支持Ticket的必要。
* 一些和安全有关的TLSEXT，这些功能是应该增加的。



## 修改笔记

下面的内容可以忽略



SSL_ERROR_WANT_READ 这类错误需要支持

 应该仔细看一下  rec_layer_s3.c ， 了解一下状态机的逻辑



SSL_READ_EARLY_DATA_SUCCESS

这部分功能应该局限在handshake中，没有什么影响。

因此被SSL_READ_EARLY_DATA_SUCCESS包裹中的内容都可以被删除









SSL_OP_NO_RENEGOTIATION

我们不支持





ngx_ssl_rsa512_key_callback

这个函数大概是设定一个默认的RSA密钥，并且是一个static对象。设定了RSA的密钥长度



我们不支持RSA因此没有这个必要







SESSION Ticket

`ngx_ssl_session_ticket_keys`是一个公开的系统函数

如果支持Session Ticket，那个有一个宏 SSL_CTRL_SET_TLSEXT_TICKET_KEY_CB

来对待实现，否则这个函数只是简单的打印错误





ngx_ssl_get_curves

大概是通过TLSEXT获得客户端支持的曲线，不知道这个函数到底对实现有什么用，大概是对配置系统有意义吧。因为我们可以反馈这个信息，前提是在API上要有支持。但是现在我们的实现里面是不支持解析TLSEXT的。













ngx_event_openssl_stapling.c

这里面所有的代码都是被包装起来的。

\#if (!defined OPENSSL_NO_OCSP && defined SSL_CTRL_SET_TLSEXT_STATUS_REQ_CB)







**src/http/ngx_http_request.c**

这个文件中引用了X509的功能。

还有SSL_get_verify_result

函数`ngx_http_process_request`处理客户端请求，如果当前的请求要求是SSL但是仅是HTTP，那么返回错误。如果服务器的SSL配置要求客户端证书验证，但是没有配置客户端证书，那么也返回错误。

**src/http/ngx_http_variables.c**

这个引用了RAND_bytes

这个是通过NGX_OPENSSL包裹的，因此如果我们将OPENSSL的标识改为GMSSL，就可以避免这个问题。这块的代码是冗余的。

这个问题是解决了。



**src/http/ngx_http_upstream.c**

rc = SSL_get_verify_result(c->ssl->connection);

这个通过增加对应的函数解决了。

**src/http/ngx_http_upstream_round_robin.c**

ssl_session = d2i_SSL_SESSION(NULL, &p, len);

总体上说，这个模块可以取消掉。

```
./configure --with-http_ssl_module --without-http_upstream_zone_module
```



这个文件还引用了 ngx_ssl_free_session

看来这个函数还是应该保留的。





GmSSL可以实现一个SESSION，但是在协议中不支持SESSION。





我觉得总的来说还是仿照OpenSSL的接口比较好，这样在迁移上会比较容易。



看起来差不多，基本上都需要设定一个socket，也就是说，socket是由调用方设定的。



### 重要的数据类型





### ngx_ssl_t

这个类型实际上就是SSL_CTX，一些公用的数据放在这里，比如服务器的证书和私钥，对于每个连接来说都是一样的。

### ngx_connection_t

这是Nginx的一个通用的数据结构，可以看做是抽象的链接。这个结构中有一个属性是`ssl`，实际上相当于是`ssl_connection`，SSL对象的实例就放在这里面，在Nginx中，这个对象的类型就是`ngx_ssl_connection_t`。

在Nginx的大部分公开API中，只能看到`ngx_connection_t`这个类型。

### ngx_ssl_conn_t

这个类型在Nginx的默认实现中就是OpenSSL的SSL类型的typedef/define

很奇怪为什么需要格外定义这个类型，我觉得是没有必要的。

### ngx_ssl_connection_t

这个类型封装了SSL, 也包含SSL_CTX, SESSION等信息，还包括一些状态信息和Buffer。这个类型最后被放置到ngx_connection_t中

### ngx_conf_t

基本上是用不到的。



### ngx_session_t









