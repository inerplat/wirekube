package crd

import "embed"

// Files contains the CRDs shipped with wirekubectl.
//
//go:embed *.yaml
var Files embed.FS
