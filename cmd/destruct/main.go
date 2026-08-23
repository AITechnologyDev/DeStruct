// Command destruct is a decompiler/disassembler toolkit covering JVM
// .class/.jar, Hermes .hbc (React Native), Flutter libapp.so (Dart AOT),
// and native ELF/PE binaries. See COMMANDS.md for the full command and
// flag reference.
package main

import (
	"fmt"
	"io"
	"os"
)

const version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 {
		printUsage(os.Stderr)
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "jvm":
		err = runJVM(args)
	case "hermes":
		err = runHermes(args)
	case "assemble":
		err = runAssemble(args)
	case "patch":
		err = runPatch(args)
	case "interactive", "repl":
		err = runInteractive(args)
	case "flutter":
		err = runFlutter(args)
	case "elf":
		err = runELF(args)
	case "pe":
		err = runPE(args)
	case "version":
		fmt.Println("destruct version " + version)
		return
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return
	default:
		fmt.Fprintf(os.Stderr, "destruct: unknown command %q\n\n", cmd)
		printUsage(os.Stderr)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `destruct - decompiler/disassembler toolkit (JVM, Hermes, Flutter, native ELF/PE)

Usage:
  destruct <command> [arguments]

Commands:
  jvm          decompile JVM .class/.jar to Java
  hermes       disassemble/decompile Hermes .hbc bytecode (React Native)
  assemble     reassemble a .hasm file back into .hbc
  patch        quick point-patch of Hermes bytecode
  interactive  interactive radare2-like patcher (alias: repl)
  flutter      disassemble Flutter libapp.so (Dart AOT)
  elf          disassemble ELF binaries (native .so, ARM/ARM64/x86)
  pe           disassemble PE binaries (Windows .exe/.dll) - not yet implemented
  version      print the version
  help         show this text

Run "destruct <command> -h" for a command's flags.
See COMMANDS.md for the full reference and patching workflows.
`)
}
