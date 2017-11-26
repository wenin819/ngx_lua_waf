local wr = math.random(99999)
local wtoa = wr
wt, rip, _ = gentoken(wr)

local limit = ngx.shared.auth_limit_lua
local req, _ = limit:get(rip)
if req then
    if req > AuthUrlCount then
        wtoa = req
    else
        limit:incr(rip, 1)
    end
else
    limit:set(rip, 1, AuthUrlSeconds)
    req = 0;
end
if (ngx.var.cookie_wt ~= wt) then
    ngx.header["Set-Cookie"] = { "wto=" .. wt .. wr, "wtoa=" .. wtoa, "wrc=" .. req }
end

