package hooks

import "fmt"

// widget is unexported (camelCase) - idiomatic Go, must not be flagged as a
// naming violation.
type widget struct {
	name string
}

// String satisfies fmt.Stringer; called through the interface, never directly.
func (w widget) String() string {
	return w.name
}

// MarshalJSON satisfies json.Marshaler; invoked by encoding/json via reflection.
func (w widget) MarshalJSON() ([]byte, error) {
	return []byte("\"" + w.name + "\""), nil
}

// init runs at package load; the runtime calls it, no code does.
func init() {
	fmt.Println("loaded")
}

// reallyDead has no caller and is not a framework hook - genuinely dead.
func reallyDead() string {
	return "no caller"
}
