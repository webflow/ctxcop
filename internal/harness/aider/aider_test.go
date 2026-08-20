package aider

import (
	"github.com/webflow/ctxcop/internal/audit"
)

func init() { audit.Disable() }

// akia is a canonical-shape AWS access key literal used across tests.
// Written as a concatenation so this file itself doesn't ship a real-
// looking secret in the source tree.
const akia = "AKIA" + "LALEMEL33243OLIA"
