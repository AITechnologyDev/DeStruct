package fixture;

import java.io.ByteArrayOutputStream;

// Manual test fixture for internal/jvm's Astore local-type inference
// (see decoder_test.go's TestDecompileClassFile_AstoreLocalGetsDeclared).
// Compiled WITHOUT -g (matching real-world release/obfuscated builds,
// and the actual test/lunacy/classes_merge.jar fixture that surfaced
// this bug), so the class file carries no LocalVariableTable at all -
// "buf" only exists in the bytecode as an anonymous local slot,
// exactly the case collectLocalTypes previously had no Astore handling
// for at all.
// Regenerate with: javac -d . AstoreRetype.java
// then copy fixture/AstoreRetype.class into internal/jvm/testdata/
// (flattened, no fixture/ subdirectory).
public class AstoreRetype {
    public static byte[] build(String s) {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(s.length());
        buf.write(1);
        return buf.toByteArray();
    }
}
