package unflutter

import (
	"fmt"
	"os"
)

// cmdDebug handles "unflutter _debug <cmd>" — internal/debug commands.
func cmdDebug(args []string) error {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, `unflutter _debug — internal commands

Usage:
  unflutter _debug <command> [args]

Commands:
  scan            Scan ELF and print snapshot info
  dump            Disassemble and dump symbols
  objects         Dump object pool
  strings         Extract strings from snapshot
  graph           Extract named object graph
  clusters        Parse clusters
  render          Render callgraph and HTML from JSONL
  thr-audit       Audit THR-relative memory accesses
  thr-cluster     Cluster unresolved THR offsets
  thr-classify    Classify unresolved THR offsets
  dart2-buckets   Dart 2.x bucket analysis
  find-libapp-batch   Batch find-libapp + report
`)
		return nil
	}

	cmd := args[0]
	subArgs := args[1:]

	switch cmd {
	case "scan":
		return cmdScan(subArgs)
	case "dump":
		return cmdDump(subArgs)
	case "objects":
		return cmdObjects(subArgs)
	case "strings":
		return cmdStrings(subArgs)
	case "graph":
		return cmdGraph(subArgs)
	case "clusters":
		return cmdClusters(subArgs)
	case "render":
		return cmdRender(subArgs)
	case "thr-audit":
		return cmdTHRAudit(subArgs)
	case "thr-cluster":
		return cmdTHRCluster(subArgs)
	case "thr-classify":
		return cmdTHRClassify(subArgs)
	case "dart2-buckets":
		return cmdDart2Buckets(subArgs)
	case "find-libapp-batch":
		return cmdFindLibappBatch(subArgs)
	default:
		return fmt.Errorf("unknown debug command: %s", cmd)
	}
}
