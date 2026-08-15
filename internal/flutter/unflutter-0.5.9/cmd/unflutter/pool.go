package unflutter

import (
	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/cluster"
	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/pipeline"
	"github.com/destruct/destruct/internal/flutter/unflutter-0.5.9/internal/snapshot"
)

type poolLookups = pipeline.PoolLookups

func buildPoolLookups(result *cluster.Result, ct *snapshot.CIDTable, vmResult *cluster.Result) *poolLookups {
	return pipeline.BuildPoolLookups(result, ct, vmResult)
}

func resolvePoolDisplay(pool []cluster.PoolEntry, l *poolLookups) map[int]string {
	return pipeline.ResolvePoolDisplay(pool, l)
}
