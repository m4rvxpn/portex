// Package data embeds the nmap probe/OS databases and the RL policy model
// so Portex ships as a single self-contained binary.
package data

import _ "embed"

// NmapServiceProbes is the embedded nmap-service-probes file used for
// service/version detection. The real file is downloaded from:
// https://github.com/nmap/nmap/blob/master/nmap-service-probes
//
//go:embed nmap-service-probes
var NmapServiceProbes []byte

// NmapOSDB is the embedded nmap-os-db file used for OS fingerprinting.
// The real file is downloaded from:
// https://github.com/nmap/nmap/blob/master/nmap-os-db
//
//go:embed nmap-os-db
var NmapOSDB []byte

// RLPolicyONNX is the embedded RL policy ONNX model binary.
// Replace with a trained model for production use.
//
//go:embed rl_policy.onnx
var RLPolicyONNX []byte
