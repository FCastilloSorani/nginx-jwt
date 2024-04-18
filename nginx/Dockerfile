FROM openresty/openresty:1.25.3.1-0-centos

RUN luarocks install lua-resty-jwt
RUN luarocks show lua-resty-jwt

COPY jwt_validation.lua /usr/src/jwt_validation.lua
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf