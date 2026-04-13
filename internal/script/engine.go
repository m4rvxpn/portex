package script

import (
	"context"
	"fmt"
	"sync"

	lua "github.com/yuin/gopher-lua"

	"github.com/m4rvxpn/portex/internal/scanner"
)

// Engine manages a pool of Lua VMs and runs scripts against port results.
type Engine struct {
	scripts map[string]string // script name → lua source code
	mu      sync.RWMutex
	vmPool  sync.Pool
}

// NewEngine creates a new script engine.
func NewEngine() *Engine {
	e := &Engine{
		scripts: make(map[string]string),
	}
	e.vmPool = sync.Pool{
		New: func() interface{} {
			return e.newVM()
		},
	}
	return e
}

// LoadScript adds a named script to the engine.
// Validates syntax by doing a trial compile.
func (e *Engine) LoadScript(name, source string) error {
	// Validate syntax using a temporary VM
	L := e.newVM()
	defer L.Close()

	_, err := L.LoadString(source)
	if err != nil {
		return fmt.Errorf("script %q: %w", name, err)
	}

	e.mu.Lock()
	e.scripts[name] = source
	e.mu.Unlock()
	return nil
}

// RunScript executes the named script against the given port result.
// Returns the combined output from portex.setresult calls, or an error.
func (e *Engine) RunScript(ctx context.Context, name string, port scanner.PortResult) (string, error) {
	e.mu.RLock()
	source, ok := e.scripts[name]
	e.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("script %q not found", name)
	}

	L := e.vmPool.Get().(*lua.LState)
	vmOk := false
	defer func() {
		if vmOk {
			e.vmPool.Put(L)
		} else {
			L.Close()
			e.vmPool.Put(e.newVM()) // put a fresh VM back so pool size stays stable
		}
	}()

	// Create a fresh API context for this run
	api := newLuaAPI(ctx, &port)
	defer api.closeAll()

	// Register portex.* into this VM
	api.Register(L)

	type result struct {
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				resCh <- result{err: fmt.Errorf("script panic: %v", r)}
			}
		}()
		err := L.DoString(source)
		resCh <- result{err: err}
	}()

	select {
	case <-ctx.Done():
		vmOk = false
		return "", ctx.Err()
	case res := <-resCh:
		if res.err != nil {
			vmOk = false
			return "", fmt.Errorf("script %q: %w", name, res.err)
		}
	}

	vmOk = true

	// Collect output: concatenate all setresult values
	output := ""
	for k, v := range api.output {
		if output != "" {
			output += "\n"
		}
		output += k + ": " + v
	}

	return output, nil
}

// RunAll runs all loaded scripts and returns a map of name→output.
func (e *Engine) RunAll(ctx context.Context, port scanner.PortResult) (map[string]string, error) {
	e.mu.RLock()
	names := make([]string, 0, len(e.scripts))
	for name := range e.scripts {
		names = append(names, name)
	}
	e.mu.RUnlock()

	results := make(map[string]string, len(names))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, name := range names {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			out, err := e.RunScript(ctx, n, port)
			mu.Lock()
			if err != nil {
				results[n] = fmt.Sprintf("ERROR: %v", err)
			} else {
				results[n] = out
			}
			mu.Unlock()
		}(name)
	}

	wg.Wait()
	return results, nil
}

// newVM creates a fresh sandboxed Lua VM.
// Only safe libraries are loaded: base, table, string, math.
// io, os, debug, package are never opened.
func (e *Engine) newVM() *lua.LState {
	L := lua.NewState(lua.Options{
		SkipOpenLibs: true,
	})

	// Open only safe libraries — package/require are intentionally excluded
	for _, pair := range []struct {
		name string
		fn   lua.LGFunction
	}{
		{lua.BaseLibName, lua.OpenBase},
		{lua.TabLibName, lua.OpenTable},
		{lua.StringLibName, lua.OpenString},
		{lua.MathLibName, lua.OpenMath},
	} {
		L.Push(L.NewFunction(pair.fn))
		L.Push(lua.LString(pair.name))
		L.Call(1, 0)
	}

	// Remove dangerous globals that base lib exposes
	L.SetGlobal("load", lua.LNil)
	L.SetGlobal("loadfile", lua.LNil)
	L.SetGlobal("dofile", lua.LNil)

	return L
}
