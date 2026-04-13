package script

import (
	"embed"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

//go:embed scripts/*.lua
var builtinScripts embed.FS

// LoadBuiltins loads all embedded .lua scripts into the given engine.
func LoadBuiltins(e *Engine) error {
	entries, err := fs.ReadDir(builtinScripts, "scripts")
	if err != nil {
		return fmt.Errorf("read embedded scripts dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if filepath.Ext(entry.Name()) != ".lua" {
			continue
		}

		path := "scripts/" + entry.Name()
		data, err := builtinScripts.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read embedded script %q: %w", path, err)
		}

		name := strings.TrimSuffix(entry.Name(), ".lua")
		if err := e.LoadScript(name, string(data)); err != nil {
			return fmt.Errorf("load builtin script %q: %w", name, err)
		}
	}

	return nil
}
