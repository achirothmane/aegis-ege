package epistemic

import (
	"os"
	"testing"

	"github.com/achirothmane/aegis-ege/internal/easlruntime"
	"github.com/achirothmane/aegis-ege/internal/testsupport"
)

func TestMain(m *testing.M) {
	runtime, err := testsupport.NewSyntheticEASLRuntime()
	if err != nil {
		panic(err)
	}
	if err := easlruntime.Bind(runtime); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
