package service

// Match is the result of service/version detection on a port.
type Match struct {
	Service string
	Version string
	Product string
	OS      string
	CPE     string
	Banner  string
	Probe   string // which probe triggered the match
	Conf    int    // 1-10 confidence
}
