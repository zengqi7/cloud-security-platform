package migration

import "testing"

func TestEmbeddedMigrationOrdering(t *testing.T) {
	names, err := Files()
	if err != nil || len(names) < 2 {
		t.Fatal(names, err)
	}
	for i, name := range names {
		if i > 0 && name <= names[i-1] {
			t.Fatal("unsorted migration")
		}
		raw, err := scripts.ReadFile(name)
		if err != nil || len(Statements(string(raw))) == 0 {
			t.Fatal(name, err)
		}
	}
	if len(Statements("-- ignored\nSELECT 1;\nSELECT 2;")) != 2 {
		t.Fatal("statement parsing")
	}
}
