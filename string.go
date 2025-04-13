package proxyclient

import (
	"encoding/json"
	"fmt"
)

type String struct {
	v string
}

func (i *String) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.v)
}

func (i *String) UnmarshalJSON(data []byte) error {
	// First try to unmarshal as an integer directly
	var v string
	if err := json.Unmarshal(data, &v); err == nil {
		*i = String{v: v}
		return nil
	}

	// If that fails, try to unmarshal as a string
	var s any
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("value must be an integer or a string representation of an integer: %w", err)
	}

	v = fmt.Sprint(s)

	*i = String{v: v}
	return nil
}

// Add a getter method to retrieve the value
func (i String) Value() string {
	return i.v
}
