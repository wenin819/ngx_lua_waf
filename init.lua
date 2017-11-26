require 'config'
local iputils = require("resty.iputils")
iputils.enable_lrucache()

local match = string.match
local ngxmatch = ngx.re.match
local unescape = ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function(options) return options == "on" and true or false end
logpath = logdir
rulepath = RulePath
UrlDeny = optionIsOn(UrlDeny)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(cookieMatch)
WhiteCheck = optionIsOn(whiteModule)
PathInfoFix = optionIsOn(PathInfoFix)
attacklog = optionIsOn(attacklog)
CCDeny = optionIsOn(CCDeny)
Redirect = optionIsOn(Redirect)
allowProxy = optionIsOn(allowProxy)
AuthUrlDeny = optionIsOn(AuthUrlDeny)

CCcount = tonumber(string.match(CCrate, '(.*)/'))
CCseconds = tonumber(string.match(CCrate, '/(.*)'))
AuthUrlCount = tonumber(string.match(AuthUrlRate, '(.*)/'))
AuthUrlSeconds = tonumber(string.match(AuthUrlRate, '/(.*)'))

local proxyWhitelist = nil;
if next(ipWhitelist) ~= nil then
    proxyWhitelist = iputils.parse_cidrs(allowProxyWhitelist)
end

local whiteList = nil;
if next(ipWhitelist) ~= nil then
    whiteList = iputils.parse_cidrs(ipWhitelist)
end
local blockList = nil;
if next(ipBlocklist) ~= nil then
    blockList = iputils.parse_cidrs(ipBlocklist)
end

function getClientIp()
    IP = nil;
    if allowProxy then
        if proxyWhitelist ~= nil then
            IP = ngx.var.remote_addr
            if iputils.ip_in_cidrs(IP, proxyWhitelist) then
                IP = ngx.req.get_headers()["X-Real-IP"]
            end
        else
            IP = ngx.req.get_headers()["X-Real-IP"]
        end
    end
    if IP == nil then
        IP = ngx.var.remote_addr
    end
    if IP == nil then
        IP = "unknown"
    end
    return IP
end

function write(logfile, msg)
    local fd = io.open(logfile, "ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end

function sendmail(line)
    if next(alarmMaillist) ~= nil then
        local cmd = 'echo "' .. line .. '" | mail -s "$(echo -e "web firewall alarm message\nContent-Type: text/html;charset=utf-8")" '
        for _, mailer in pairs(alarmMaillist) do
            os.execute(cmd .. mailer);
        end
    end
    return false
end

function log(method, url, data, ruletag)
    if attacklog then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername = ngx.var.server_name
        local time = ngx.localtime()
        if ua then
            line = realIp .. "#[" .. time .. "]#" .. method .. "#" .. servername .. url .. "#" .. data .. "#" .. ua .. "#" .. ruletag .. "\"\n"
        else
            line = realIp .. "#[" .. time .. "]#" .. method .. "#" .. servername .. url .. "#" .. data .. "#" .. ruletag .. "\"\n"
        end
        local filename = logpath .. '/' .. servername .. "_" .. ngx.today() .. "_sec.log"

        local mailHtml = '<style>table{width:50%;}td{text-align: center;border:1px solid #6bb3f6;}</style>'
        mailHtml = mailHtml .. "<table  border='0' cellspacing='0' cellpadding='0'><tr><td colspan='4'>WEB防火墙邮件报警通知</td></tr><tr><td>请求IP</td><td>" .. realIp .. "</td><td>请求时间</td><td>" .. time .. "</td></tr>"
        mailHtml = mailHtml .. "<tr><td>请求method</td><td>" .. method .. "</td><td>请求url</td><td>" .. servername .. url .. "</td></tr>"
        mailHtml = mailHtml .. "<tr><td>请求数据</td><td>" .. data .. "</td><td>触发规则</td><td>" .. ruletag .. "</td></tr></table>"
        sendmail(mailHtml)

        write(filename, line)
    end
end

------------------------------------ 规则读取函数-------------------------------------------------------------------
function read_rule(var)
    file = io.open(rulepath .. '/' .. var, "r")
    if file == nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t, line)
    end
    file:close()
    return (t)
end

urlrules = read_rule('url')
authurlrules = read_rule('authurl')
argsrules = read_rule('args')
uarules = read_rule('user-agent')
wturlrules = read_rule('whiteurl')
postrules = read_rule('post')
ckrules = read_rule('cookie')


function say_html()
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(html)
        ngx.exit(ngx.status)
    end
end

function whiteurl()
    if WhiteCheck then
        if wturlrules ~= nil then
            for _, rule in pairs(wturlrules) do
                if ngxmatch(ngx.var.uri, rule, "isjo") then
                    return true
                end
            end
        end
    end
    return false
end

function fileExtCheck(ext)
    local items = Set(black_fileExt)
    ext = string.lower(ext)
    if ext then
        for rule in pairs(items) do
            if ngx.re.match(ext, rule, "isjo") then
                log('POST', ngx.var.request_uri, "-", "file attack with ext " .. ext)
                say_html()
            end
        end
    end
    return false
end

function Set(list)
    local set = {}
    for _, l in ipairs(list) do set[l] = true end
    return set
end

function args()
    for _, rule in pairs(argsrules) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val) == 'table' then
                local t = {}
                for k, v in pairs(val) do
                    if v == true then
                        v = ""
                    end
                    table.insert(t, v)
                end
                data = table.concat(t, " ")
            else
                data = val
            end
            if data and type(data) ~= "boolean" and rule ~= "" and ngxmatch(unescape(data), rule, "isjo") then
                log('GET', ngx.var.request_uri, "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end


function url()
    if UrlDeny then
        for _, rule in pairs(urlrules) do
            if rule ~= "" and ngxmatch(ngx.var.request_uri, rule, "isjo") then
                log('GET', ngx.var.request_uri, "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
        for _, rule in pairs(uarules) do
            if rule ~= "" and ngxmatch(ua, rule, "isjo") then
                log('UA', ngx.var.request_uri, "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function body(data)
    for _, rule in pairs(postrules) do
        if rule ~= "" and data ~= "" and ngxmatch(unescape(data), rule, "isjo") then
            log('POST', ngx.var.request_uri, data, rule)
            say_html()
            return true
        end
    end
    return false
end

function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _, rule in pairs(ckrules) do
            if rule ~= "" and ngxmatch(ck, rule, "isjo") then
                log('Cookie', ngx.var.request_uri, "-", rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function denycc()
    if CCDeny then
        local uri = ngx.var.uri
        local token = getClientIp() .. uri
        local limit = ngx.shared.limit
        local req, _ = limit:get(token)
        if req then
            if req > CCcount then
                ngx.exit(503)
                return true
            else
                limit:incr(token, 1)
            end
        else
            limit:set(token, 1, CCseconds)
        end
    end
    return false
end

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end

function whiteip()
    if whiteList ~= nil then
        if iputils.ip_in_cidrs(getClientIp(), whiteList) then
            return true
        else
        end
    end
    return false
end

function blockip()
    if blockList ~= nil then
        if iputils.ip_in_cidrs(getClientIp(), blockList) then
            ngx.exit(403)
            return true
        end
    end
    return false
end

function gentoken(wr)
    local rip = getClientIp()
    local wt = ngx.md5(ngx.md5(AuthUrlSecretKey .. rip .. wr))
    return wt, rip, wr
end
function authurl()
    if not AuthUrlDeny or authurlrules == nil then
        return false;
    end
    for _, rule in pairs(authurlrules) do
        local isEntry = string.sub(rule, 0, 3) == "->:"
        if isEntry then
            rule = string.sub(rule, 4, -1)
        end
        if ngxmatch(ngx.var.uri, rule, "isjo") then
--            ngx.log(ngx.ERR, "auth valid: uri=", ngx.var.uri, ", rule=", rule, ", matched.");
            wr = ngx.var.cookie_wr
            if wr == nil then
                if isEntry then
                    return ngx.redirect("/auth?url=" .. ngx.var.request_uri, 302)
                else
                    ngx.exit(403)
                    return true
                end
            end
            wt, rip, _ = gentoken(wr)
            if (ngx.var.cookie_wt ~= wt) then
--                ngx.log(ngx.ERR, "auth valid: uri=", ngx.var.uri, ", cookie_wr=", ngx.var.cookie_wr,
--                   ", cookie_wt=", ngx.var.cookie_wt, ", wt=", wt, ", isValid=", ngx.var.cookie_wt == wt);
                if isEntry then
                    return ngx.redirect("/auth?url=" .. ngx.var.request_uri, 302)
                else
                    ngx.exit(403)
                    return true
                end
            end
        else
--            ngx.log(ngx.ERR, "auth valid: uri=", ngx.var.uri, ", rule=", rule, ", not matched.");
        end
    end
    return false;
end