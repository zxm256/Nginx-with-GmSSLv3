FROM buildpack-deps:stable as buildpack

LABEL org.opencontainers.image.authors="zhaopku09@gmail.com"

RUN apt-get update \
    && apt-get install -y cmake

WORKDIR /tmp/build

# Build GmSSL lib
COPY GmSSL /tmp/build/GmSSL

RUN cmake ./GmSSL/. \
    && make install \
    && ldconfig

# Build nginx
COPY . /tmp/build/nginx

RUN cd nginx \
    && cp auto/configure . \
    && ./configure \
    --sbin-path=/usr/local/sbin/nginx \
    --conf-path=/etc/nginx/nginx.conf \
    --error-log-path=/var/log/nginx/error.log \
    --pid-path=/var/run/nginx/nginx.pid \
    --lock-path=/var/lock/nginx/nginx.lock \
    --http-log-path=/var/log/nginx/access.log \
    --http-client-body-temp-path=/tmp/nginx-client-body \
    --with-http_ssl_module \
    --without-http_upstream_zone_module \
    --with-debug \
    && make -j $(getconf _NPROCESSORS_ONLN) \
    && make install \
    && mkdir /var/lock/nginx \
    && rm -rf /tmp/build


## Export to end-images
FROM debian:stable-slim

ENV TZ=Asia/Shanghai

RUN ln -fs /usr/share/zoneinfo/${TZ} /etc/localtime \
    && echo ${TZ} > /etc/timezone

COPY --from=buildpack /usr/local/lib/libgmssl.* /usr/local/lib/
RUN ldconfig

COPY --from=buildpack /etc/nginx /etc/nginx
COPY --from=buildpack /usr/local/sbin/nginx /usr/local/sbin/nginx
COPY --from=buildpack /usr/local/nginx /usr/local/nginx

# Reload lib cache & make nginx run directories
RUN ldconfig \
    && mkdir -p /var/lock/nginx \
    && mkdir -p /var/log/nginx \
    mkdir -p /var/run/nginx

# Forward logs to Docker
RUN ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log

# Set up config file
COPY conf/nginx_ssl.conf /etc/nginx/conf/nginx.conf

EXPOSE 443/tcp
EXPOSE 80/tcp

CMD ["nginx", "-g", "daemon off;"]
