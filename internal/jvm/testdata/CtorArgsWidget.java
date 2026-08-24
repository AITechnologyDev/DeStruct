package fixture;

// Manual test fixture for internal/jvm's SuperCallStmt/ThisCallStmt
// decompilation (see pipeline_test.go's TestDecompileClassFile_SuperAndThisCallArgs).
// Regenerate with: javac -d . CtorArgsWidget.java
// then copy fixture/CtorArgsWidget.class and fixture/CtorArgsBase.class
// into internal/jvm/testdata/ (flattened, no fixture/ subdirectory).
public class CtorArgsWidget extends CtorArgsBase {
    public CtorArgsWidget(String name) {
        super(name, 1);
    }

    public CtorArgsWidget() {
        this("default");
    }
}

class CtorArgsBase {
    CtorArgsBase(String name, int flags) {
    }
}
