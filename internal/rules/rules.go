package rules

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/spf13/viper"
	"github.com/webflow/ctxcop/internal/audit"
)

//go:embed embedded/ctxcop.toml
var embeddedTOML []byte

type Source string

const (
	SrcUpstream Source = "upstream-default"
	SrcEmbedded Source = "ctxcop-embedded"
	SrcUser     Source = "user-file"
	SrcProject  Source = "project-file"
	SrcEnv      Source = "env-file"
)

type RuleInfo struct {
	ID          string
	Description string
	Source      Source
	SourcePath  string
	Disabled    bool
	// Overridden is true when a higher-priority source redefined this ID.
	// Source/SourcePath then hold the *effective* (winning) definition, and
	// OverriddenFrom names the source that was shadowed. This is what lets
	// `rules list` report effective state instead of the pre-override lie.
	Overridden     bool
	OverriddenFrom Source
}

var (
	once     sync.Once
	detector *detect.Detector
	loadErr  error
	rules    []RuleInfo
)

// LoadDetector composes upstream + embedded + ~/.ctxcop/*.toml +
// $CTXCOP_RULES, applies $CTXCOP_DISABLE_RULES, caches.
//
// Panic recovery: a single bad rule (regex compile, etc.) must never
// crash a hook handler. On panic we fall back to upstream defaults.
func LoadDetector() (*detect.Detector, error) {
	once.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "ctxcop: rules loader panicked (%v); falling back to upstream defaults\n", r)
				d, err := detect.NewDetectorDefaultConfig()
				detector = d
				loadErr = err
				rules = nil
			}
		}()
		load()
	})
	return detector, loadErr
}

// List returns every rule with provenance. Used by `ctxcop rules list`.
func List() ([]RuleInfo, error) {
	if _, err := LoadDetector(); err != nil {
		return nil, err
	}
	out := make([]RuleInfo, len(rules))
	copy(out, rules)
	return out, nil
}

// Reset clears the cache. Tests only. Also resets project-config discovery
// so a test can point the cwd-walk at a fresh temp dir.
func Reset() {
	once = sync.Once{}
	detector = nil
	loadErr = nil
	rules = nil
	projectOnce = sync.Once{}
	projectPath = ""
	projectCfg = projectConfig{}
}

func load() {
	cfg, err := parseTOML(upstreamDefaultTOML(), SrcUpstream, "")
	if err != nil {
		loadErr = fmt.Errorf("rules: load upstream defaults: %w", err)
		return
	}
	recordRules(cfg.Rules, SrcUpstream, "")

	extraSources := []struct {
		data []byte
		src  Source
		path string
	}{
		{embeddedTOML, SrcEmbedded, "<embedded>"},
	}
	for _, p := range userRuleFiles() {
		data, err := os.ReadFile(p)
		if err == nil {
			extraSources = append(extraSources, struct {
				data []byte
				src  Source
				path string
			}{data, SrcUser, p})
		}
	}
	if p := ProjectConfigPath(); p != "" {
		data, err := os.ReadFile(p)
		if err == nil {
			extraSources = append(extraSources, struct {
				data []byte
				src  Source
				path string
			}{data, SrcProject, p})
		}
	}
	if envPath := os.Getenv("CTXCOP_RULES"); envPath != "" {
		data, err := os.ReadFile(envPath)
		if err == nil {
			extraSources = append(extraSources, struct {
				data []byte
				src  Source
				path string
			}{data, SrcEnv, envPath})
		} else {
			fmt.Fprintf(os.Stderr, "ctxcop: CTXCOP_RULES=%q unreadable: %v\n", envPath, err)
		}
	}

	for _, s := range extraSources {
		extra, err := parseTOML(s.data, s.src, s.path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ctxcop: skipping rules from %s: %v\n", s.path, err)
			continue
		}
		// Only PROJECT-scope discovery (the cwd-walk) is untrusted. User-scope
		// (~/.ctxcop, $CTXCOP_RULES) and the env source are operator-controlled,
		// so they override silently; a hostile project file must not.
		if s.src == SrcProject {
			warnProjectOverrides(&cfg, extra, s.path)
		}
		mergeRules(&cfg, extra)
		recordRules(extra.Rules, s.src, s.path)
	}

	for _, id := range disabledRules() {
		if _, ok := cfg.Rules[id]; ok {
			delete(cfg.Rules, id)
			for i, r := range cfg.OrderedRules {
				if r == id {
					cfg.OrderedRules = append(cfg.OrderedRules[:i], cfg.OrderedRules[i+1:]...)
					break
				}
			}
		}
		for i := range rules {
			if rules[i].ID == id {
				rules[i].Disabled = true
			}
		}
	}

	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Source != rules[j].Source {
			return sourceOrder(rules[i].Source) < sourceOrder(rules[j].Source)
		}
		return rules[i].ID < rules[j].ID
	})

	// Rebuild the Aho-Corasick keyword index — merging rules manually
	// doesn't update Config.KeywordToRules, so prefilter would route our
	// custom rules' keywords to nothing.
	cfg.KeywordToRules = make(map[string][]string)
	cfg.NoKeywordRules = nil
	for ruleID, rule := range cfg.Rules {
		if len(rule.Keywords) == 0 {
			cfg.NoKeywordRules = append(cfg.NoKeywordRules, ruleID)
			continue
		}
		for _, k := range rule.Keywords {
			cfg.KeywordToRules[k] = append(cfg.KeywordToRules[k], ruleID)
		}
	}

	d := detect.NewDetectorContext(context.Background(), &cfg, detect.ValidationOptions{})
	// MaxDecodeDepth=8 matches betterleaks' CLI default. Default of 0 = no
	// codec decoding, which would let base64/hex/percent/unicode-wrapped
	// credentials slip through.
	d.MaxDecodeDepth = 8
	detector = d
}

func sourceOrder(s Source) int {
	switch s {
	case SrcUpstream:
		return 0
	case SrcEmbedded:
		return 1
	case SrcUser:
		return 2
	case SrcProject:
		return 3
	case SrcEnv:
		return 4
	}
	return 9
}

// parseTOML drives betterleaks' viper+Translate path on raw bytes.
func parseTOML(data []byte, _ Source, _ string) (config.Config, error) {
	v := viper.New()
	v.SetConfigType("toml")
	if err := v.ReadConfig(strings.NewReader(string(data))); err != nil {
		return config.Config{}, err
	}
	var vc config.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return config.Config{}, err
	}
	cfg, err := vc.Translate()
	if err != nil {
		return config.Config{}, err
	}
	return *cfg, nil
}

// mergeRules: gitleaks [extend] semantics — extra overrides base on ID collision.
func mergeRules(base *config.Config, extra config.Config) {
	if base.Rules == nil {
		base.Rules = map[string]config.Rule{}
	}
	if base.Keywords == nil {
		base.Keywords = map[string]struct{}{}
	}
	for id, r := range extra.Rules {
		_, existed := base.Rules[id]
		base.Rules[id] = r
		for _, k := range r.Keywords {
			base.Keywords[strings.ToLower(k)] = struct{}{}
		}
		if !existed {
			base.OrderedRules = append(base.OrderedRules, id)
		}
	}
}

// recordRules updates the provenance table for the rules a single source
// defines. New IDs are appended. An ID already present is an OVERRIDE: we
// update its provenance to the winning (later, higher-priority) source
// instead of skipping it. The old code skipped already-seen IDs, so a
// project file that redefined an embedded rule left `rules list` reporting
// the pre-override embedded provenance — i.e. it lied about what was live.
func recordRules(defined map[string]config.Rule, src Source, path string) {
	for id, r := range defined {
		if idx := indexOfRule(id); idx >= 0 {
			prev := rules[idx].Source
			rules[idx].OverriddenFrom = prev
			rules[idx].Overridden = true
			rules[idx].Description = r.Description
			rules[idx].Source = src
			rules[idx].SourcePath = path
			continue
		}
		rules = append(rules, RuleInfo{
			ID:          id,
			Description: r.Description,
			Source:      src,
			SourcePath:  path,
		})
	}
}

func indexOfRule(id string) int {
	for i := range rules {
		if rules[i].ID == id {
			return i
		}
	}
	return -1
}

// warnProjectOverrides emits a loud STDERR warning and an audit-log entry
// when a project-scope .ctxcop.toml weakens detection: (a) it redefines an
// existing (embedded/upstream/user) rule ID, or (b) it contributes
// skip_paths. Project config keeps its override power by design — this is
// transparency, not enforcement. base holds the ruleset accumulated so far;
// extra is the just-parsed project config.
func warnProjectOverrides(base *config.Config, extra config.Config, path string) {
	var overridden []string
	for id := range extra.Rules {
		if _, existed := base.Rules[id]; existed {
			overridden = append(overridden, id)
		}
	}
	sort.Strings(overridden)
	skips := ProjectSkipPaths()

	if len(overridden) == 0 && len(skips) == 0 {
		return
	}

	fmt.Fprintf(os.Stderr, "ctxcop: WARNING: project config %s modifies ctxcop's ruleset and may weaken detection:\n", path)
	if len(overridden) > 0 {
		fmt.Fprintf(os.Stderr, "ctxcop:   overrides/disables %d existing rule(s): %s\n", len(overridden), strings.Join(overridden, ", "))
	}
	if len(skips) > 0 {
		fmt.Fprintf(os.Stderr, "ctxcop:   adds %d skip_paths pattern(s): %s\n", len(skips), strings.Join(skips, ", "))
	}
	fmt.Fprintf(os.Stderr, "ctxcop:   run `ctxcop rules list` to see effective state; review %s if unexpected\n", path)

	audit.Log(audit.Entry{
		Tool:   "rules",
		Action: "project-config-override",
		Rules:  overridden,
		Count:  len(overridden) + len(skips),
		Field:  path,
	})
}

// userRuleFiles returns ~/.ctxcop/*.toml, lexical-sorted.
func userRuleFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dir := filepath.Join(home, ".ctxcop")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(e.Name()), ".toml") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out
}

func disabledRules() []string {
	raw := os.Getenv("CTXCOP_DISABLE_RULES")
	if raw == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
