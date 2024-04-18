-- Importar la biblioteca Lua JWT
local cjson = require "cjson"
local jwt = require "resty.jwt"
local validators = require "resty.jwt-validators"

local ngx_time = ngx.time()

local jwt_secret = "532eaabd9574880dbf76b9b8cc00832c20a6ec113d682299550d7a6e0f345e25"

-- Obtener el token JWT del encabezado de autorización
local jwt_token = ngx.var.http_authorization

if not jwt_token then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header.content_type = "application/json"

    local response = {
        code = 401,
        status = "Error",
        message = "Acceso denegado. No se envió un token de acceso."
    }

    ngx.say(cjson.encode(response))
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end


-- Verificar que el token venga de la forma Bearer token
local _, _, token = string.find(jwt_token, "Bearer%s+(.+)")

if not token then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header.content_type = "application/json"

    local response = {
        code = 401,
        status = "Error",
        message = "Acceso denegado. Token de acceso inválido."
    }

    ngx.say(cjson.encode(response))
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Verificar el token JWT con una clave secreta
local jwt_obj = jwt:verify(jwt_secret, token)

if not jwt_obj.verified then
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header.content_type = "application/json"

    local response = {
        code = 401,
        status = "Error",
        message = "Acceso denegado. Token de acceso inválido."
    }

    ngx.say(cjson.encode(response))
    ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

-- Verificar si el token está expirado
if jwt_obj.payload.exp == nil then
    ngx.status = ngx.HTTP_FORBIDDEN
    ngx.header.content_type = "application/json"

    local response = {
        code = 403,
        status = "Error",
        message = "Acceso denegado. Token de acceso inválido o expirado."
    }

    ngx.say(cjson.encode(response))
    ngx.exit(ngx.HTTP_FORBIDDEN)
end

-- El token es válido y no está expirado, redirigir la solicitud
ngx.req.set_uri("/")
