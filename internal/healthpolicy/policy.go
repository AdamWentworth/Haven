// Package healthpolicy owns the small, explicit thresholds used to turn NAS
// measurements into review states. Keeping these rules in one package prevents
// the collector and hub from disagreeing about the same evidence.
package healthpolicy

import "strings"

const (
	CapacityWarningPercent  = 85.0
	CapacityCriticalPercent = 95.0
	DiskWarningC            = 50.0
	DiskCriticalC           = 60.0
	SystemWarningC          = 75.0
	SystemCriticalC         = 90.0
)

func CapacityState(usedPercentage float64) string {
	if usedPercentage >= CapacityCriticalPercent {
		return "critical"
	}
	if usedPercentage >= CapacityWarningPercent {
		return "warning"
	}
	return "healthy"
}

func TemperatureState(kind string, celsius float64) string {
	warning, critical := SystemWarningC, SystemCriticalC
	if strings.EqualFold(kind, "disk") {
		warning, critical = DiskWarningC, DiskCriticalC
	}
	if celsius >= critical {
		return "critical"
	}
	if celsius >= warning {
		return "warning"
	}
	return "healthy"
}
