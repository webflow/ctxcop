package rules

import "github.com/betterleaks/betterleaks/config"

// upstreamDefaultTOML returns the raw bundled TOML. NewDetectorDefaultConfig
// only gives a finished Detector; we need the bytes to merge with other
// sources via viper.
func upstreamDefaultTOML() []byte {
	return []byte(config.DefaultConfig)
}
