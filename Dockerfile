FROM openresty/openresty:1.25.3.1-0-centos

RUN luarocks install lua-resty-jwt

COPY scripts/jwt_validation.lua /usr/src/jwt_validation.lua
COPY config/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
