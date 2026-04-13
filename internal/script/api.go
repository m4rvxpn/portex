package script

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	lua "github.com/yuin/gopher-lua"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// LuaAPI exposes Go functions to the portex.* Lua namespace.
type LuaAPI struct {
	result  *scanner.PortResult   // current port context
	output  map[string]string     // script output (key=script name, val=output)
	conns   map[int]net.Conn      // active connections
	nextID  atomic.Int64          // connection ID counter
	mu      sync.Mutex            // protects conns
	timeout time.Duration         // default connect/read timeout
	ctx     context.Context       // request context
}

// newLuaAPI creates a new LuaAPI for the given port result.
func newLuaAPI(ctx context.Context, result *scanner.PortResult) *LuaAPI {
	return &LuaAPI{
		result:  result,
		output:  make(map[string]string),
		conns:   make(map[int]net.Conn),
		timeout: 5 * time.Second,
		ctx:     ctx,
	}
}

// Register registers all portex.* functions into the Lua state.
func (a *LuaAPI) Register(L *lua.LState) {
	portexTable := L.NewTable()

	// Set host and port as table fields
	if a.result != nil {
		L.SetField(portexTable, "host", lua.LString(a.result.Target))
		L.SetField(portexTable, "port", lua.LNumber(a.result.Port))
		L.SetField(portexTable, "proto", lua.LString(a.result.Protocol))
		if a.result.Service != nil {
			L.SetField(portexTable, "service", lua.LString(a.result.Service.Service))
		}
	}

	// portex.connect(host, port) → connection_id
	L.SetField(portexTable, "connect", L.NewFunction(a.luaConnect))
	// portex.send(conn_id, data) → bytes_sent
	L.SetField(portexTable, "send", L.NewFunction(a.luaSend))
	// portex.recv(conn_id, n, timeout_ms) → data_string
	L.SetField(portexTable, "recv", L.NewFunction(a.luaRecv))
	// portex.close(conn_id)
	L.SetField(portexTable, "close", L.NewFunction(a.luaClose))
	// portex.banner(host, port) → banner_string
	L.SetField(portexTable, "banner", L.NewFunction(a.luaBanner))
	// portex.setresult(key, value)
	L.SetField(portexTable, "setresult", L.NewFunction(a.luaSetResult))
	// portex.getresult(key) → value
	L.SetField(portexTable, "getresult", L.NewFunction(a.luaGetResult))
	// portex.log(message)
	L.SetField(portexTable, "log", L.NewFunction(a.luaLog))

	L.SetGlobal("portex", portexTable)
}

// luaConnect implements portex.connect(host, port) → conn_id
func (a *LuaAPI) luaConnect(L *lua.LState) int {
	host := L.CheckString(1)
	port := L.CheckInt(2)

	addr := fmt.Sprintf("%s:%d", host, port)

	dialCtx, cancel := context.WithTimeout(a.ctx, a.timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}

	id := int(a.nextID.Add(1))
	a.mu.Lock()
	a.conns[id] = conn
	a.mu.Unlock()

	L.Push(lua.LNumber(id))
	return 1
}

// luaSend implements portex.send(conn_id, data) → bytes_sent
func (a *LuaAPI) luaSend(L *lua.LState) int {
	id := L.CheckInt(1)
	data := L.CheckString(2)

	a.mu.Lock()
	conn, ok := a.conns[id]
	a.mu.Unlock()

	if !ok {
		L.Push(lua.LNumber(0))
		return 1
	}

	n, err := io.WriteString(conn, data)
	if err != nil {
		L.Push(lua.LNumber(0))
		return 1
	}

	L.Push(lua.LNumber(n))
	return 1
}

// luaRecv implements portex.recv(conn_id, n, timeout_ms) → data_string
func (a *LuaAPI) luaRecv(L *lua.LState) int {
	id := L.CheckInt(1)
	maxBytes := L.CheckInt(2)
	timeoutMS := L.CheckInt(3)

	a.mu.Lock()
	conn, ok := a.conns[id]
	a.mu.Unlock()

	if !ok {
		L.Push(lua.LNil)
		return 1
	}

	timeout := time.Duration(timeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = a.timeout
	}

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		L.Push(lua.LNil)
		return 1
	}
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	if maxBytes <= 0 || maxBytes > 65536 {
		maxBytes = 4096
	}

	buf := make([]byte, maxBytes)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		L.Push(lua.LNil)
		return 1
	}

	L.Push(lua.LString(buf[:n]))
	return 1
}

// luaClose implements portex.close(conn_id)
func (a *LuaAPI) luaClose(L *lua.LState) int {
	id := L.CheckInt(1)

	a.mu.Lock()
	conn, ok := a.conns[id]
	if ok {
		delete(a.conns, id)
	}
	a.mu.Unlock()

	if ok {
		conn.Close() //nolint:errcheck
	}
	return 0
}

// luaBanner implements portex.banner(host, port) → banner_string
func (a *LuaAPI) luaBanner(L *lua.LState) int {
	host := L.CheckString(1)
	port := L.CheckInt(2)

	addr := fmt.Sprintf("%s:%d", host, port)

	dialCtx, cancel := context.WithTimeout(a.ctx, a.timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		L.Push(lua.LNil)
		return 1
	}
	defer conn.Close()

	if err := conn.SetReadDeadline(time.Now().Add(a.timeout)); err != nil {
		L.Push(lua.LNil)
		return 1
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		L.Push(lua.LNil)
		return 1
	}

	L.Push(lua.LString(buf[:n]))
	return 1
}

// luaSetResult implements portex.setresult(key, value)
func (a *LuaAPI) luaSetResult(L *lua.LState) int {
	key := L.CheckString(1)
	value := L.CheckString(2)
	a.output[key] = value
	return 0
}

// luaGetResult implements portex.getresult(key) → value
func (a *LuaAPI) luaGetResult(L *lua.LState) int {
	key := L.CheckString(1)
	if val, ok := a.output[key]; ok {
		L.Push(lua.LString(val))
	} else {
		L.Push(lua.LNil)
	}
	return 1
}

// luaLog implements portex.log(message)
func (a *LuaAPI) luaLog(L *lua.LState) int {
	msg := L.CheckString(1)
	// In production this would go to the structured logger;
	// for now just discard (scripts can still call it without error)
	_ = msg
	return 0
}

// closeAll closes all open connections.
func (a *LuaAPI) closeAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for id, conn := range a.conns {
		conn.Close() //nolint:errcheck
		delete(a.conns, id)
	}
}
