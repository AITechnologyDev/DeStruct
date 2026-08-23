package main

import (
	"flag"
	"strings"
)

// stringFlag registers the same string variable under a short and a long
// flag name, so callers can write either -o or --output for the same value.
func stringFlag(fs *flag.FlagSet, p *string, short, long, def, usage string) {
	fs.StringVar(p, short, def, usage)
	fs.StringVar(p, long, def, usage)
}

// boolFlag is stringFlag's counterpart for boolean flags (e.g. -v/--verbose).
func boolFlag(fs *flag.FlagSet, p *bool, short, long string, def bool, usage string) {
	fs.BoolVar(p, short, def, usage)
	fs.BoolVar(p, long, def, usage)
}

// parseArgs reorders args so every flag (and, for a non-boolean flag, the
// value token after it) comes before every positional argument, then parses
// it with fs. The stdlib flag package alone stops parsing at the first
// non-flag token, which would silently ignore flags in the exact
// "destruct <cmd> <input> -o <output>" order COMMANDS.md documents for
// every command - positional input first, flags after.
func parseArgs(fs *flag.FlagSet, args []string) error {
	return fs.Parse(reorderArgs(fs, args))
}

func reorderArgs(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			if strings.ContainsRune(name, '=') {
				continue // "-flag=value" already carries its value
			}
			if !isBoolFlag(fs, name) && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	return append(flags, positional...)
}

func isBoolFlag(fs *flag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	if f == nil {
		return false
	}
	bv, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && bv.IsBoolFlag()
}
