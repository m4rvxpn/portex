//go:build tools

package tools

import (
	_ "github.com/go-chi/chi/v5"
	_ "github.com/google/gopacket"
	_ "github.com/google/uuid"
	_ "github.com/miekg/dns"
	_ "github.com/prometheus/client_golang/prometheus"
	_ "github.com/rs/zerolog"
	_ "github.com/spf13/cobra"
	_ "github.com/spf13/viper"
	_ "github.com/stretchr/testify/assert"
	_ "github.com/yuin/gopher-lua"
	_ "golang.org/x/net/proxy"
	_ "golang.org/x/sync/errgroup"
)
