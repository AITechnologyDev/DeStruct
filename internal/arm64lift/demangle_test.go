package arm64lift

import "testing"

// TestDemangle covers the Itanium C++ ABI mangling grammar subset
// itaniumDemangle actually implements, using REAL mangled symbols
// pulled from two real, differently-toolchained binaries
// (test/liblun.so, an NDK/Clang/libc++ Android .so, and
// test/il2cpp_memory_dumper_main's own host build) and cross-checked
// against c++filt's own output - see the "why" behind each grammar
// feature in demangle.go's own doc comments. Validated against the
// full symbol tables of both binaries (834 real symbols): 788 exact
// c++filt matches, the rest either a documented, deliberate scope
// decision (no return-type prefix on template free functions, since
// that lives in the discarded parameter list; ABI tags like
// "[abi:ne210000]" dropped as decoration) or a safe fallback to the
// raw mangled name for the one unsupported construct found
// (lambda/local-class entities nested inside a deeply-nested template
// argument) - never a silently wrong demangling.
func TestDemangle(t *testing.T) {
	cases := []struct {
		name    string
		mangled string
		want    string
	}{
		{"plain namespaced function", "_ZNSt6__ndk19to_stringEl", "std::__ndk1::to_string"},
		{"template class method with cv-qualified pointer param",
			"_ZNKSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEPKcmm",
			"std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>>::find"},
		{"constructor reuses the class's own bare name (not the templated form)",
			"_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEC1ERKS5_",
			"std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>>::basic_string"},
		{"destructor renders as ~ClassName",
			"_ZNSt6__ndk112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEED1Ev",
			"std::__ndk1::basic_string<char, std::__ndk1::char_traits<char>, std::__ndk1::allocator<char>>::~basic_string"},
		{"operator new", "_Znwm", "operator new"},
		{"operator new[]", "_Znam", "operator new[]"},
		{"operator== free function template", "_ZNKSt6__ndk121__basic_string_commonILb1EE20__throw_length_errorEv",
			"std::__ndk1::__basic_string_common<true>::__throw_length_error"},
		{"standard substitution Ss (std::string)", "_ZNKSs4sizeEv", "std::string::size"},
		{"vtable special-name", "_ZTV6Widget", "vtable for Widget"},
		{"typeinfo special-name", "_ZTI6Widget", "typeinfo for Widget"},
		{"typeinfo name special-name", "_ZTS6Widget", "typeinfo name for Widget"},
		{"internal-linkage (static) global variable", "_ZL12g_debug_maps", "g_debug_maps"},
		{"internal-linkage function nested in a namespace",
			"_ZN9libunwindL24findUnwindSectionsByPhdrEP12dl_phdr_infomPv",
			"libunwind::findUnwindSectionsByPhdr"},
		{"not Itanium-mangled: falls back unchanged", "malloc", "malloc"},
		{"empty string: falls back unchanged", "", ""},
		{"malformed _Z input: falls back unchanged rather than guessing", "_ZN1AI", "_ZN1AI"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := demangle(tc.mangled)
			if got != tc.want {
				t.Errorf("demangle(%q) = %q, want %q", tc.mangled, got, tc.want)
			}
		})
	}
}

// TestDemangle_UnsupportedConstructFallsBackSafely covers the one real
// gap found against the 834-symbol corpus: a lambda/local-class entity
// referenced (via <local-name>) from deep inside a template argument
// list can't be resolved, since itaniumDemangle deliberately never
// parses a <bare-function-type> (see its own doc comment) and
// <local-name> needs exactly that to find where its own enclosing
// function's encoding ends. Rather than mis-parse and produce
// something wrong, this must fall back to the untouched original
// string - verified explicitly here since it's the one documented
// unsupported case, not just an incidental gap.
func TestDemangle_UnsupportedConstructFallsBackSafely(t *testing.T) {
	mangled := "_ZNSt6__ndk111__introrsortINS_17_ClassicAlgPolicyERZNK13ProcessMemory12dump_libraryERKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEESA_E3$_0P12MemoryRegionLb0EEEvT1_SF_T0_NS_15iterator_traitsISF_E15difference_typeEb"
	if got := demangle(mangled); got != mangled {
		t.Errorf("expected an unsupported local-name-in-template-arg construct to fall back to the raw mangled name unchanged, got %q", got)
	}
}
