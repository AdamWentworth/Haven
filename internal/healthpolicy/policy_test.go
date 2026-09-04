package healthpolicy

import "testing"

func TestCapacityThresholdBoundaries(t *testing.T) {
	tests := map[float64]string{84.99: "healthy", 85: "warning", 94.99: "warning", 95: "critical"}
	for value, expected := range tests {
		if actual := CapacityState(value); actual != expected {
			t.Fatalf("CapacityState(%v) = %q, want %q", value, actual, expected)
		}
	}
}

func TestTemperatureThresholdBoundaries(t *testing.T) {
	tests := []struct {
		kind     string
		value    float64
		expected string
	}{
		{"disk", 49.9, "healthy"}, {"disk", 50, "warning"}, {"disk", 60, "critical"},
		{"system", 74.9, "healthy"}, {"system", 75, "warning"}, {"system", 90, "critical"},
	}
	for _, test := range tests {
		if actual := TemperatureState(test.kind, test.value); actual != test.expected {
			t.Fatalf("TemperatureState(%q, %v) = %q, want %q", test.kind, test.value, actual, test.expected)
		}
	}
}
