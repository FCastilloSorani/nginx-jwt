-- Importar la biblioteca Lua JWT
local jwt = require "resty.jwt"
local ngx_time = ngx.time()

local jwt_secret = "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"

-- Obtener el token JWT del encabezado de autorización
local jwt_token = ngx.var.http_authorization

if not jwt_token then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Acceso denegado. No se envió un token de acceso.")
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Extraer el token del encabezado "Bearer"
local _, _, token = string.find(jwt_token, "Bearer%s+(.+)")
if not token then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Acceso denegado. Formato de token inválido.")
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Verificar el token JWT con una clave secreta
local jwt_obj = jwt:verify(jwt_secret, token)
if not jwt_obj.verified then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Acceso denegado. Token de acceso inválido.")
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Verificar si el token está expirado
if jwt_obj.payload.exp and jwt_obj.payload.exp < ngx_time then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("Acceso denegado. Token de acceso expirado.")
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- El token es válido y no está expirado, redirigir la solicitud
ngx.req.set_uri("/api" .. ngx.var.uri)
