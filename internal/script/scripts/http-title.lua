-- Fetch HTTP title from port
local host = portex.host
local port_num = portex.port
local conn = portex.connect(host, port_num)
if conn then
    portex.send(conn, "GET / HTTP/1.0\r\nHost: " .. host .. "\r\n\r\n")
    local resp = portex.recv(conn, 4096, 3000)
    portex.close(conn)
    if resp then
        local title = string.match(resp, "<[Tt][Ii][Tt][Ll][Ee]>([^<]+)<")
        if title then
            portex.setresult("title", title)
        end
    end
end
