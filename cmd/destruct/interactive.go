package main

import (
	"fmt"
	"os"

	"github.com/destruct/destruct/internal/hermes"
)

func runInteractive(args []string) error {
	if len(args) < 1 || args[0] == "-h" || args[0] == "--help" {
		fmt.Println(`Usage: destruct interactive <input.hbc|input.bundle>  (alias: destruct repl)

Opens a radare2-like interactive shell for seeking, disassembling, and
patching the file in place. Type 'help' inside the session for commands.`)
		if len(args) < 1 {
			return fmt.Errorf("missing input file")
		}
		return nil
	}
	input := args[0]

	file, err := hermes.ParseFile(input)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", input, err)
	}

	r := hermes.NewRepl(file, input, os.Stdout)
	return r.Run(os.Stdin)
}
