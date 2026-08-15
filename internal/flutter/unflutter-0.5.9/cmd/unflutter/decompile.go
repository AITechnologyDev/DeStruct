package unflutter

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ghidraLauncher holds the command and any prefix args needed to run Ghidra headless.
// For Ghidra <12 (Jython): cmd=analyzeHeadless, prefix=nil.
// For Ghidra 12+ (PyGhidra): cmd=pyghidraRun, prefix=["-H"].
type ghidraLauncher struct {
	cmd    string   // path to the launcher binary
	prefix []string // args inserted before analyzeHeadless args (e.g. ["-H"])
}

func cmdDecompile(args []string) error {
	fs := flag.NewFlagSet("decompile", flag.ExitOnError)
	inDir := fs.String("in", "", "input directory (disasm output)")
	libPath := fs.String("lib", "", "path to libapp.so (default: auto-detect from disasm)")
	projectDir := fs.String("projects", "scratch/ghidra-projects", "Ghidra project directory")
	ghidraHome := fs.String("ghidra-home", "", "Ghidra installation directory (auto-detected if omitted)")
	decompAll := fs.Bool("all", false, "decompile ALL functions (default: signal functions only)")

	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inDir == "" {
		return fmt.Errorf("--in is required")
	}

	// 1. Find Ghidra.
	ghLauncher, ghHome, err := findGhidra(*ghidraHome)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "ghidra: %s\n", ghHome)

	// 2. Generate flutter_meta.json (always regenerate to pick up --all).
	metaPath := filepath.Join(*inDir, "flutter_meta.json")
	metaArgs := []string{"--in", *inDir, "--out", metaPath}
	if *decompAll {
		metaArgs = append(metaArgs, "--decompile-all")
	}
	fmt.Fprintf(os.Stderr, "generating flutter_meta.json...\n")
	if err := cmdFlutterMeta(metaArgs); err != nil {
		return fmt.Errorf("flutter-meta: %w", err)
	}

	// 3. Find libapp.so if not specified.
	if *libPath == "" {
		// Try common locations relative to --in.
		candidates := []string{
			filepath.Join(filepath.Dir(*inDir), "libapp.so"),
			filepath.Join(*inDir, "..", "libapp.so"),
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				abs, _ := filepath.Abs(c)
				*libPath = abs
				break
			}
		}
		if *libPath == "" {
			return fmt.Errorf("cannot find libapp.so; specify with --lib")
		}
	}
	fmt.Fprintf(os.Stderr, "libapp: %s\n", *libPath)

	// 4. Prepare output paths.
	decompDir := filepath.Join(*inDir, "decompiled")
	absMetaPath, _ := filepath.Abs(metaPath)
	absDecompDir, _ := filepath.Abs(decompDir)
	absLibPath, _ := filepath.Abs(*libPath)

	// Ghidra project name from the input directory.
	projectName := sanitizeProjectName(filepath.Base(filepath.Dir(*inDir)))

	// 5. Create project directory.
	absProjDir := sanitizeGhidraPath(*projectDir)
	if err := os.MkdirAll(absProjDir, 0o755); err != nil {
		return fmt.Errorf("create project dir: %w", err)
	}

	// 6. Get script path.
	scriptPath, err := findScriptPath()
	if err != nil {
		return err
	}

	// 7. Run analyzeHeadless.
	if *decompAll {
		fmt.Fprintf(os.Stderr, "running Ghidra headless analysis (decompiling ALL functions)...\n")
	} else {
		fmt.Fprintf(os.Stderr, "running Ghidra headless analysis (signal functions only, use --all for everything)...\n")
	}
	fmt.Fprintf(os.Stderr, "  project: %s/%s\n", absProjDir, projectName)
	fmt.Fprintf(os.Stderr, "  import: %s\n", absLibPath)
	fmt.Fprintf(os.Stderr, "  decompile output: %s\n", absDecompDir)

	ghidraArgs := []string{
		absProjDir,
		projectName,
		"-import", absLibPath,
		"-overwrite",
		"-processor", "AARCH64:LE:64:v8A",
		"-scriptPath", scriptPath,
		"-preScript", "unflutter_prescript.py",
		"-postScript", "unflutter_apply.py", absMetaPath, absDecompDir,
	}

	// Set JAVA_HOME if not set (brew Ghidra needs it).
	env := os.Environ()
	if os.Getenv("JAVA_HOME") == "" {
		javaHome := findJavaHome(ghHome)
		if javaHome != "" {
			env = append(env, "JAVA_HOME="+javaHome)
		}
	}

	cmd := exec.Command(ghLauncher.cmd, append(ghLauncher.prefix, ghidraArgs...)...)
	cmd.Env = env
	cmd.Stdout = os.Stderr // Ghidra output goes to stderr.
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("analyzeHeadless failed: %w", err)
	}

	// 8. Report results.
	entries, _ := os.ReadDir(absDecompDir)
	cCount := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".c") {
			cCount++
		}
	}
	fmt.Fprintf(os.Stderr, "decompiled %d functions → %s\n", cCount, absDecompDir)

	return nil
}

// findGhidra locates the Ghidra installation and returns a launcher.
// Search order:
//  1. --ghidra-home flag
//  2. GHIDRA_HOME or UNFLUTTER_GHIDRA_HOME environment variable
//  3. analyzeHeadless in PATH
//  4. ghidraRun in PATH → derive installation directory
//  5. brew --prefix ghidra
func findGhidra(explicitHome string) (launcher ghidraLauncher, ghidraHome string, err error) {
	// 1. Explicit --ghidra-home.
	if explicitHome != "" {
		if l, home, ok := probeGhidraHome(explicitHome); ok {
			return l, home, nil
		}
		return ghidraLauncher{}, "", fmt.Errorf("analyzeHeadless not found in %s", explicitHome)
	}

	// 2. GHIDRA_HOME or UNFLUTTER_GHIDRA_HOME environment variable.
	for _, env := range []string{"GHIDRA_HOME", "UNFLUTTER_GHIDRA_HOME"} {
		if gh := os.Getenv(env); gh != "" {
			if l, home, ok := probeGhidraHome(gh); ok {
				return l, home, nil
			}
		}
	}

	// 3. analyzeHeadless in PATH.
	if ah, err := exec.LookPath("analyzeHeadless"); err == nil {
		home := filepath.Dir(filepath.Dir(ah))
		return ghidraLauncher{cmd: ah}, home, nil
	}

	// 4. ghidraRun in PATH → parse to find install dir.
	if gr, err := exec.LookPath("ghidraRun"); err == nil {
		home := deriveGhidraHome(gr)
		if home != "" {
			if l, h, ok := probeGhidraHome(home); ok {
				return l, h, nil
			}
		}
	}

	// 5. brew --prefix ghidra.
	if out, err := exec.Command("brew", "--prefix", "ghidra").Output(); err == nil {
		prefix := strings.TrimSpace(string(out))
		if l, home, ok := probeGhidraHome(prefix); ok {
			return l, home, nil
		}
		// Cellar layout: prefix/libexec is the real Ghidra home.
		if l, home, ok := probeGhidraHome(filepath.Join(prefix, "libexec")); ok {
			return l, home, nil
		}
	}

	return ghidraLauncher{}, "", fmt.Errorf(`Ghidra not found

Install Ghidra:
  brew install ghidra

Or set GHIDRA_HOME:
  export GHIDRA_HOME=/path/to/ghidra

Or pass --ghidra-home:
  unflutter decompile --ghidra-home /path/to/ghidra --in <dir>`)
}

// probeGhidraHome checks if a directory contains analyzeHeadless.
// Handles both direct layout (home/support/analyzeHeadless) and
// Caskroom layout (home/ghidra_*/support/analyzeHeadless).
// For Ghidra 12+ with pyghidraRun, returns a launcher that uses it
// so Python scripts work (PyGhidra replaces Jython).
func probeGhidraHome(home string) (launcher ghidraLauncher, ghidraHome string, ok bool) {
	// Direct: home/support/analyzeHeadless
	ah := filepath.Join(home, "support", "analyzeHeadless")
	if _, err := os.Stat(ah); err == nil {
		return makeLauncher(home, ah), home, true
	}
	// Caskroom: home/ghidra_*_PUBLIC/support/analyzeHeadless
	if subs, err := os.ReadDir(home); err == nil {
		for _, sub := range subs {
			if !sub.IsDir() {
				continue
			}
			subHome := filepath.Join(home, sub.Name())
			ah = filepath.Join(subHome, "support", "analyzeHeadless")
			if _, err := os.Stat(ah); err == nil {
				return makeLauncher(subHome, ah), subHome, true
			}
		}
	}
	return ghidraLauncher{}, "", false
}

// makeLauncher returns a ghidraLauncher for the given Ghidra home.
// If pyghidraRun exists (Ghidra 12+), uses it with -H flag so Python scripts work.
// Otherwise falls back to analyzeHeadless directly.
func makeLauncher(home, analyzeHeadless string) ghidraLauncher {
	pyghidra := filepath.Join(home, "support", "pyghidraRun")
	if _, err := os.Stat(pyghidra); err == nil {
		return ghidraLauncher{cmd: pyghidra, prefix: []string{"-H"}}
	}
	return ghidraLauncher{cmd: analyzeHeadless}
}

// deriveGhidraHome reads the ghidraRun shell script to find the real install path.
// Brew's ghidraRun wrapper contains: exec "/opt/homebrew/Cellar/ghidra/X.Y.Z/libexec/ghidraRun"
func deriveGhidraHome(ghidraRunPath string) string {
	data, err := os.ReadFile(ghidraRunPath)
	if err != nil {
		return ""
	}
	// Look for exec "..." pattern pointing to the real ghidraRun.
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		// exec "/opt/homebrew/Cellar/ghidra/12.0.2/libexec/ghidraRun"
		if strings.Contains(line, "exec") && strings.Contains(line, "ghidraRun") {
			// Extract the quoted path.
			idx := strings.Index(line, `"`)
			if idx < 0 {
				continue
			}
			rest := line[idx+1:]
			end := strings.Index(rest, `"`)
			if end < 0 {
				continue
			}
			realPath := rest[:end]
			// ghidraRun is at <home>/ghidraRun, so home = dirname.
			home := filepath.Dir(realPath)
			if _, err := os.Stat(filepath.Join(home, "support")); err == nil {
				return home
			}
		}
	}
	return ""
}

// findScriptPath returns the path to the ghidra_scripts directory.
// Validates that ALL required scripts exist, not just one.
func findScriptPath() (string, error) {
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)

	homeDir, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(homeDir, ".unflutter", "ghidra_scripts"),
		filepath.Join(homeDir, ".unflutter"),
		filepath.Join(exeDir, "ghidra_scripts"),
		"ghidra_scripts",
		filepath.Join(exeDir, "..", "ghidra_scripts"),
	}

	required := []string{"unflutter_apply.py", "unflutter_prescript.py"}

	for _, c := range candidates {
		abs, _ := filepath.Abs(c)
		allFound := true
		for _, req := range required {
			if _, err := os.Stat(filepath.Join(abs, req)); err != nil {
				allFound = false
				break
			}
		}
		if allFound {
			return abs, nil
		}
	}

	return "", fmt.Errorf("cannot find ghidra_scripts/ with both unflutter_apply.py and unflutter_prescript.py\n  checked: %s\n  fix: run 'make install' or run from the unflutter project root", strings.Join(candidates, ", "))
}

// findJavaHome tries to locate a suitable JDK for Ghidra.
func findJavaHome(ghidraHome string) string {
	// Check if the ghidraRun wrapper sets JAVA_HOME.
	gr := filepath.Join(ghidraHome, "ghidraRun")
	if data, err := os.ReadFile(gr); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.Contains(line, "JAVA_HOME") && strings.Contains(line, ":-") {
				// JAVA_HOME="${JAVA_HOME:-/opt/homebrew/opt/openjdk@21/...}"
				idx := strings.Index(line, ":-")
				if idx >= 0 {
					rest := line[idx+2:]
					end := strings.IndexAny(rest, `}"`)
					if end > 0 {
						jh := rest[:end]
						if _, err := os.Stat(jh); err == nil {
							return jh
						}
					}
				}
			}
		}
	}

	// Common brew JDK paths.
	jdks := []string{
		"/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
		"/opt/homebrew/opt/openjdk/libexec/openjdk.jdk/Contents/Home",
		"/usr/local/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home",
	}
	for _, jh := range jdks {
		if _, err := os.Stat(jh); err == nil {
			return jh
		}
	}

	return ""
}

// sanitizeProjectName builds a Ghidra project name from a directory basename.
// Strips characters that Java/Ghidra reject in project names (colon, etc.).
func sanitizeProjectName(base string) string {
	if base == "" || base == "." {
		return "unflutter_decompile"
	}
	clean := strings.Map(func(r rune) rune {
		if r == ':' || r == '\\' || r == '"' || r == '<' || r == '>' || r == '|' || r == '?' || r == '*' {
			return '_'
		}
		return r
	}, base)
	return "unflutter_" + clean
}

// sanitizeGhidraPath returns an absolute path safe for Java/Ghidra.
// If the resolved path contains ':', relocates to ~/.unflutter/ghidra-projects/.
func sanitizeGhidraPath(projectDir string) string {
	abs, _ := filepath.Abs(projectDir)
	if !strings.Contains(abs, ":") {
		return abs
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".unflutter", "ghidra-projects")
}
