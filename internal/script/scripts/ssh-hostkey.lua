-- SSH host key fingerprint
local host = portex.host
local port_num = portex.port
local conn = portex.connect(host, port_num)
if conn then
    local banner = portex.recv(conn, 256, 2000)
    portex.close(conn)
    if banner then
        portex.setresult("ssh-banner", banner)
    end
end
