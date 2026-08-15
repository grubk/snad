package components

import "testing"

func TestGenerateNameAvoidsCollisions(t *testing.T) {
	taken := CreateSet[string]()
	seen := make(map[string]bool)

	for i := 0; i < 200; i++ {
		name := GenerateName(taken)
		if seen[name] {
			t.Fatalf("GenerateName returned a name already taken: %s", name)
		}
		seen[name] = true
		taken.Add(name)
	}
}
