// Package config defines the Portex configuration model and loading utilities.
package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// ScanMode identifies the packet-craft strategy used for probing.
type ScanMode string

const (
	// ModeSYN performs a half-open TCP SYN scan (requires raw-socket privileges).
	ModeSYN ScanMode = "syn"
	// ModeACK probes with TCP ACK packets to map firewall rules.
	ModeACK ScanMode = "ack"
	// ModeFIN sends TCP FIN packets to elicit RSTs from closed ports.
	ModeFIN ScanMode = "fin"
	// ModeXMAS sets FIN, PSH and URG flags (the "Christmas tree" probe).
	ModeXMAS ScanMode = "xmas"
	// ModeNULL sends TCP packets with no flags set.
	ModeNULL ScanMode = "null"
	// ModeWindow is similar to ModeACK but examines the TCP window field.
	ModeWindow ScanMode = "window"
	// ModeMaimon is a FIN/ACK probe described by Uriel Maimon.
	ModeMaimon ScanMode = "maimon"
	// ModeUDP sends UDP probes to discover UDP services.
	ModeUDP ScanMode = "udp"
	// ModeSCTP sends SCTP INIT chunks.
	ModeSCTP ScanMode = "sctp"
	// ModeIPProto iterates over IP protocol numbers to find supported protocols.
	ModeIPProto ScanMode = "ipproto"
	// ModeIdle performs an idle (zombie) scan using a spoofed source IP.
	ModeIdle ScanMode = "idle"
	// ModeFTP performs an FTP bounce scan via a relay host.
	ModeFTP ScanMode = "ftp"
	// ModeConnect uses a full TCP connect() system call (no raw sockets needed).
	ModeConnect ScanMode = "connect"
	// ModeStealth is an alias for SYN scan with all AI evasion layers enabled.
	ModeStealth ScanMode = "stealth"
)

// TimingProfile mirrors nmap's -T0 through -T5 timing templates.
type TimingProfile int

const (
	T0 TimingProfile = iota // paranoid   – extremely slow, one probe at a time
	T1                      // sneaky     – slow, suitable for IDS evasion
	T2                      // polite     – reduces load on the network
	T3                      // normal     – default balanced profile
	T4                      // aggressive – faster, assumes reliable network
	T5                      // insane     – maximum speed, sacrifices accuracy
)

// Config holds all runtime parameters for a Portex scan session.
type Config struct {
	// Target specification
	Targets      []string // hosts, CIDRs, or ranges to scan
	Ports        string   // "80,443", "1-1024", "top100", "top1000", "all"
	ExcludePorts []int    // ports to skip even if in Ports spec

	// Scan mode & timing
	Mode       ScanMode
	Timing     TimingProfile
	MaxRetries int
	MaxRTT     time.Duration

	// Concurrency controls
	Goroutines int
	BatchSize  int

	// Network interface override (empty = auto-select)
	Interface string

	// AI evasion layers
	EnableRL             bool   // reinforcement-learning probe adaptation
	EnableMutator        bool   // packet-level mutation engine
	EnableProtocolMatrix bool   // multi-protocol fingerprint matrix
	EnableMimicry        bool   // traffic mimicry (browser/app emulation)
	EnableLLM            bool   // LLM-based enrichment & strategy
	LLMProvider          string // "claude" | "ollama"
	LLMModel             string // model identifier
	OllamaURL            string // base URL for local Ollama instance
	ClaudeAPIKey         string // Anthropic API key

	// Reinforcement-learning / ONNX sidecar
	ONNXModelPath string // path to .onnx model file
	RLSidecarAddr string // gRPC address of RL sidecar

	// Service & OS detection
	ServiceDetect bool
	OSDetect      bool
	ScriptScan    bool
	ScriptArgs    map[string]string // key=value pairs passed to scripts
	Scripts       []string          // script names/paths to run

	// Output formatting
	OutputFormat []string // "json", "bbot", "xml", "csv", "nuclei-yaml"
	OutputFile   string   // write output to this file (empty = stdout)
	Verbose      bool

	// Proxy routing
	ProxyAddr string
	UseProxy  bool

	// REST API server
	APIBind string // bind address, e.g. "127.0.0.1:8080"
	APIKey  string // bearer token for API authentication

	// Phantom EASM pipeline integration
	PhantomSessionID string
	PhantomScanID    string

	// Zombie (idle) scan parameters
	ZombieHost string
	ZombiePort int

	// FTP bounce scan parameters
	FTPHost string
	FTPPort int
}

// Defaults returns a Config populated with sensible production defaults.
func Defaults() *Config {
	return &Config{
		Ports:      "top1000",
		Mode:       ModeSYN,
		Timing:     T3,
		MaxRetries: 6,
		MaxRTT:     10 * time.Second,
		Goroutines: 5000,
		BatchSize:  256,
		ScriptArgs: make(map[string]string),
	}
}

// Load reads configuration from the YAML/TOML/JSON file at path.
// If path is empty only the built-in defaults are returned.
func Load(path string) (*Config, error) {
	cfg := Defaults()

	if path == "" {
		return cfg, nil
	}

	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("config file not found: %w", err)
	}

	v := viper.New()
	v.SetConfigFile(path)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	// targets
	if v.IsSet("targets") {
		cfg.Targets = v.GetStringSlice("targets")
	}
	if v.IsSet("ports") {
		cfg.Ports = v.GetString("ports")
	}
	if v.IsSet("exclude_ports") {
		cfg.ExcludePorts = v.GetIntSlice("exclude_ports")
	}

	// scan mode & timing
	if v.IsSet("mode") {
		cfg.Mode = ScanMode(v.GetString("mode"))
	}
	if v.IsSet("timing") {
		cfg.Timing = TimingProfile(v.GetInt("timing"))
	}
	if v.IsSet("max_retries") {
		cfg.MaxRetries = v.GetInt("max_retries")
	}
	if v.IsSet("max_rtt") {
		d, err := time.ParseDuration(v.GetString("max_rtt"))
		if err == nil {
			cfg.MaxRTT = d
		}
	}

	// concurrency
	if v.IsSet("goroutines") {
		cfg.Goroutines = v.GetInt("goroutines")
	}
	if v.IsSet("batch_size") {
		cfg.BatchSize = v.GetInt("batch_size")
	}

	// network
	if v.IsSet("interface") {
		cfg.Interface = v.GetString("interface")
	}

	// AI layers
	cfg.EnableRL = v.GetBool("enable_rl")
	cfg.EnableMutator = v.GetBool("enable_mutator")
	cfg.EnableProtocolMatrix = v.GetBool("enable_protocol_matrix")
	cfg.EnableMimicry = v.GetBool("enable_mimicry")
	cfg.EnableLLM = v.GetBool("enable_llm")
	if v.IsSet("llm_provider") {
		cfg.LLMProvider = v.GetString("llm_provider")
	}
	if v.IsSet("llm_model") {
		cfg.LLMModel = v.GetString("llm_model")
	}
	if v.IsSet("ollama_url") {
		cfg.OllamaURL = v.GetString("ollama_url")
	}
	if v.IsSet("claude_api_key") {
		cfg.ClaudeAPIKey = v.GetString("claude_api_key")
	}

	// RL / ONNX
	if v.IsSet("onnx_model_path") {
		cfg.ONNXModelPath = v.GetString("onnx_model_path")
	}
	if v.IsSet("rl_sidecar_addr") {
		cfg.RLSidecarAddr = v.GetString("rl_sidecar_addr")
	}

	// detection
	cfg.ServiceDetect = v.GetBool("service_detect")
	cfg.OSDetect = v.GetBool("os_detect")
	cfg.ScriptScan = v.GetBool("script_scan")
	if v.IsSet("scripts") {
		cfg.Scripts = v.GetStringSlice("scripts")
	}
	if v.IsSet("script_args") {
		raw := v.GetStringMapString("script_args")
		cfg.ScriptArgs = raw
	}

	// output
	if v.IsSet("output_format") {
		cfg.OutputFormat = v.GetStringSlice("output_format")
	}
	if v.IsSet("output_file") {
		cfg.OutputFile = v.GetString("output_file")
	}
	cfg.Verbose = v.GetBool("verbose")

	// proxy
	if v.IsSet("proxy_addr") {
		cfg.ProxyAddr = v.GetString("proxy_addr")
		cfg.UseProxy = true
	}
	if v.IsSet("use_proxy") {
		cfg.UseProxy = v.GetBool("use_proxy")
	}

	// REST API
	if v.IsSet("api_bind") {
		cfg.APIBind = v.GetString("api_bind")
	}
	if v.IsSet("api_key") {
		cfg.APIKey = v.GetString("api_key")
	}

	// Phantom
	if v.IsSet("phantom_session_id") {
		cfg.PhantomSessionID = v.GetString("phantom_session_id")
	}
	if v.IsSet("phantom_scan_id") {
		cfg.PhantomScanID = v.GetString("phantom_scan_id")
	}

	// Zombie / FTP
	if v.IsSet("zombie_host") {
		cfg.ZombieHost = v.GetString("zombie_host")
	}
	if v.IsSet("zombie_port") {
		cfg.ZombiePort = v.GetInt("zombie_port")
	}
	if v.IsSet("ftp_host") {
		cfg.FTPHost = v.GetString("ftp_host")
	}
	if v.IsSet("ftp_port") {
		cfg.FTPPort = v.GetInt("ftp_port")
	}

	return cfg, cfg.Validate()
}

// Validate checks that the Config contains self-consistent values.
func (c *Config) Validate() error {
	if c.Timing < T0 || c.Timing > T5 {
		return fmt.Errorf("timing profile %d out of range [0,5]", c.Timing)
	}
	if c.MaxRetries < 0 {
		return fmt.Errorf("max_retries must be >= 0")
	}
	if c.Goroutines <= 0 {
		return fmt.Errorf("goroutines must be > 0")
	}
	if c.BatchSize <= 0 {
		return fmt.Errorf("batch_size must be > 0")
	}
	if c.Mode == ModeIdle && c.ZombieHost == "" {
		return fmt.Errorf("idle scan requires zombie_host")
	}
	if c.Mode == ModeFTP && c.FTPHost == "" {
		return fmt.Errorf("ftp bounce scan requires ftp_host")
	}
	if c.EnableLLM {
		switch c.LLMProvider {
		case "claude", "ollama", "":
			// ok
		default:
			return fmt.Errorf("unknown llm_provider %q: must be \"claude\" or \"ollama\"", c.LLMProvider)
		}
	}
	return nil
}

// ParsePortSpec converts a port specification string into a sorted, unique slice
// of port numbers. Supported specs:
//
//   - Comma-separated values:  "80,443,8080"
//   - Range:                   "1-1024"
//   - Mixed:                   "22,80,100-200,443"
//   - Named sets:              "top100", "top1000", "all"
func (c *Config) ParsePortSpec(spec string) ([]int, error) {
	if spec == "" {
		spec = c.Ports
	}

	var ports []int

	switch strings.ToLower(strings.TrimSpace(spec)) {
	case "top100":
		ports = append(ports, top100Ports...)
	case "top1000":
		ports = append(ports, top1000Ports...)
	case "all":
		ports = make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
	default:
		// parse comma-separated tokens that may include ranges
		tokens := strings.Split(spec, ",")
		for _, tok := range tokens {
			tok = strings.TrimSpace(tok)
			if tok == "" {
				continue
			}
			if strings.Contains(tok, "-") {
				parts := strings.SplitN(tok, "-", 2)
				lo, err := strconv.Atoi(parts[0])
				if err != nil {
					return nil, fmt.Errorf("invalid port range %q: %w", tok, err)
				}
				hi, err := strconv.Atoi(parts[1])
				if err != nil {
					return nil, fmt.Errorf("invalid port range %q: %w", tok, err)
				}
				if lo > hi {
					return nil, fmt.Errorf("invalid port range %q: low > high", tok)
				}
				if lo < 1 || hi > 65535 {
					return nil, fmt.Errorf("port range %q out of bounds [1,65535]", tok)
				}
				for p := lo; p <= hi; p++ {
					ports = append(ports, p)
				}
			} else {
				p, err := strconv.Atoi(tok)
				if err != nil {
					return nil, fmt.Errorf("invalid port %q: %w", tok, err)
				}
				if p < 1 || p > 65535 {
					return nil, fmt.Errorf("port %d out of bounds [1,65535]", p)
				}
				ports = append(ports, p)
			}
		}
	}

	// apply exclusions
	exclude := make(map[int]struct{}, len(c.ExcludePorts))
	for _, p := range c.ExcludePorts {
		exclude[p] = struct{}{}
	}

	// deduplicate and sort
	seen := make(map[int]struct{}, len(ports))
	result := ports[:0]
	for _, p := range ports {
		if _, ex := exclude[p]; ex {
			continue
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		result = append(result, p)
	}
	sort.Ints(result)
	return result, nil
}

// ---------------------------------------------------------------------------
// nmap top-N port lists (TCP)
// ---------------------------------------------------------------------------

// top100Ports is nmap's list of the 100 most commonly open TCP ports.
var top100Ports = []int{
	7, 9, 13, 21, 22, 23, 25, 26, 37, 53,
	79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
	139, 143, 144, 179, 199, 389, 427, 443, 444, 445,
	465, 513, 514, 515, 543, 544, 548, 554, 587, 631,
	646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
	1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121,
	2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
	5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
	6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888,
	9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
}

// top1000Ports is nmap's list of the 1000 most commonly open TCP ports.
var top1000Ports = []int{
	1, 3, 4, 6, 7, 9, 13, 17, 19, 20,
	21, 22, 23, 24, 25, 26, 30, 32, 33, 37,
	42, 43, 49, 53, 70, 79, 80, 81, 82, 83,
	84, 85, 88, 89, 90, 99, 100, 106, 109, 110,
	111, 113, 119, 125, 135, 139, 143, 144, 146, 161,
	163, 179, 199, 211, 212, 222, 254, 255, 256, 259,
	264, 280, 301, 306, 311, 340, 366, 389, 406, 407,
	416, 417, 425, 427, 443, 444, 445, 458, 464, 465,
	481, 497, 500, 512, 513, 514, 515, 524, 541, 543,
	544, 545, 548, 554, 555, 563, 587, 593, 616, 617,
	625, 631, 636, 646, 648, 666, 667, 668, 683, 687,
	691, 700, 705, 711, 714, 720, 722, 726, 749, 765,
	777, 783, 787, 800, 801, 808, 843, 873, 880, 888,
	898, 900, 901, 902, 903, 911, 912, 981, 987, 990,
	992, 993, 995, 999, 1000, 1001, 1002, 1007, 1009, 1010,
	1011, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029,
	1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039,
	1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049,
	1050, 1051, 1052, 1053, 1054, 1055, 1056, 1057, 1058, 1059,
	1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068, 1069,
	1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079,
	1080, 1081, 1082, 1083, 1084, 1085, 1086, 1087, 1088, 1089,
	1090, 1091, 1092, 1093, 1094, 1095, 1096, 1097, 1098, 1099,
	1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112,
	1113, 1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130,
	1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148, 1149, 1151,
	1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183,
	1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217,
	1218, 1233, 1234, 1236, 1244, 1247, 1248, 1259, 1271, 1272,
	1277, 1287, 1296, 1300, 1301, 1309, 1310, 1311, 1322, 1328,
	1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500,
	1501, 1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600,
	1641, 1658, 1666, 1687, 1688, 1700, 1717, 1718, 1719, 1720,
	1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812, 1839,
	1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971,
	1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004,
	2005, 2006, 2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022,
	2030, 2033, 2034, 2035, 2038, 2040, 2041, 2042, 2043, 2045,
	2046, 2047, 2048, 2049, 2065, 2068, 2099, 2100, 2103, 2105,
	2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161,
	2170, 2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288,
	2301, 2323, 2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401,
	2492, 2500, 2522, 2525, 2557, 2601, 2602, 2604, 2605, 2607,
	2608, 2638, 2701, 2702, 2710, 2717, 2718, 2725, 2800, 2809,
	2811, 2869, 2875, 2909, 2910, 2920, 2967, 2968, 2998, 3000,
	3001, 3003, 3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031,
	3052, 3071, 3077, 3128, 3168, 3211, 3221, 3260, 3261, 3268,
	3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324, 3325, 3333,
	3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476,
	3493, 3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703,
	3737, 3766, 3784, 3800, 3801, 3809, 3814, 3826, 3827, 3828,
	3851, 3869, 3871, 3878, 3880, 3889, 3905, 3914, 3918, 3920,
	3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004,
	4005, 4006, 4045, 4111, 4125, 4126, 4129, 4224, 4242, 4279,
	4321, 4343, 4443, 4444, 4445, 4446, 4449, 4550, 4567, 4662,
	4848, 4899, 4900, 4998, 5000, 5001, 5002, 5003, 5004, 5009,
	5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100,
	5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226,
	5269, 5280, 5298, 5357, 5405, 5414, 5431, 5432, 5440, 5500,
	5510, 5544, 5550, 5555, 5560, 5566, 5631, 5633, 5666, 5678,
	5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815, 5822,
	5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904,
	5906, 5907, 5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959,
	5960, 5961, 5962, 5963, 5987, 5988, 5989, 5998, 5999, 6000,
	6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009, 6025, 6059,
	6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502,
	6510, 6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667,
	6668, 6669, 6689, 6692, 6699, 6779, 6788, 6789, 6792, 6839,
	6881, 6901, 6969, 7000, 7001, 7002, 7004, 7007, 7019, 7025,
	7070, 7100, 7103, 7106, 7200, 7201, 7402, 7435, 7443, 7496,
	7512, 7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920,
	7921, 7937, 7938, 7999, 8000, 8001, 8002, 8007, 8008, 8009,
	8010, 8011, 8021, 8022, 8031, 8042, 8045, 8080, 8081, 8082,
	8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099,
	8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290,
	8291, 8292, 8300, 8333, 8383, 8400, 8402, 8443, 8500, 8600,
	8649, 8651, 8652, 8654, 8701, 8800, 8873, 8888, 8899, 8994,
	9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071,
	9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110,
	9111, 9200, 9207, 9220, 9290, 9415, 9418, 9485, 9500, 9502,
	9503, 9535, 9575, 9593, 9594, 9595, 9618, 9666, 9876, 9877,
	9878, 9898, 9900, 9917, 9929, 9943, 9944, 9968, 9998, 9999,
	10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012, 10024, 10025,
	10082, 10180, 10215, 10243, 10566, 10616, 10617, 10621, 10626, 10628,
	10629, 10778, 11110, 11111, 11967, 12000, 12174, 12265, 12345, 13456,
	13722, 13782, 13783, 14000, 14238, 14441, 14442, 15000, 15002, 15003,
	15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018, 16080, 16113,
	16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283, 19315,
	19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828,
	21571, 22939, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352,
	27353, 27355, 27356, 27715, 28201, 30000, 30718, 30951, 31038, 31337,
	32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777,
	32778, 32779, 32780, 32781, 32782, 32783, 32784, 32785, 33354, 33899,
	34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511, 42510, 44176,
	44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155, 49156,
	49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49175, 49176,
	49400, 49999, 50000, 50001, 50002, 50003, 50006, 50300, 50389, 50500,
	50636, 50800, 51103, 51493, 52673, 52822, 52848, 52869, 54045, 54328,
	55055, 55056, 55555, 55600, 56737, 56738, 57294, 57797, 58080, 60020,
	60443, 61532, 61900, 62078, 63331, 64623, 64680, 65000, 65129, 65389,
}
