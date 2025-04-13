package proxyclient

import (
	"encoding/json"
	"fmt"
	"strings"
)

type Bool struct {
	v bool
}

func (i *Bool) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.v)
}

func (i *Bool) UnmarshalJSON(data []byte) error {
	// First try to unmarshal as an integer directly
	var v bool
	if err := json.Unmarshal(data, &v); err == nil {
		*i = Bool{v: v}
		return nil
	}

	// If that fails, try to unmarshal as a string
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("value must be a boolean or a string representation of a boolean: %w", err)
	}

	s = strings.ToLower(s)
	v = s == "true" || s == "1" || s == "yes" || s == "on" || s == "y" || s == "t"

	*i = Bool{v: v}
	return nil
}

// Add a getter method to retrieve the value
func (i Bool) Value() bool {
	return i.v
}
