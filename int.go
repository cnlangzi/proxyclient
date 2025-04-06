package proxyclient

import (
	"encoding/json"
	"fmt"
	"strconv"
)

type Int struct {
	v int
}

func (i *Int) MarshalJSON() ([]byte, error) {
	return json.Marshal(i.v)
}

func (i *Int) UnmarshalJSON(data []byte) error {
	// First try to unmarshal as an integer directly
	var valueInt int
	if err := json.Unmarshal(data, &valueInt); err == nil {
		*i = Int{v: valueInt}
		return nil
	}

	// If that fails, try to unmarshal as a string
	var valueStr string
	if err := json.Unmarshal(data, &valueStr); err != nil {
		return fmt.Errorf("value must be an integer or a string representation of an integer: %w", err)
	}

	// Convert the string to an integer
	valueInt, err := strconv.Atoi(valueStr)
	if err != nil {
		return fmt.Errorf("failed to convert string to integer: %w", err)
	}

	*i = Int{v: valueInt}
	return nil
}

// Add a getter method to retrieve the value
func (i Int) Value() int {
	return i.v
}
