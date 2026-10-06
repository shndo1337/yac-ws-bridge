package config

import "time"

// Config mirrors the subset of the Go helper config used by the iOS core.
// It is filled in from code (the Swift app passes values over), not from YAML.
type Config struct {
	Bridge struct {
		URL       string
		AuthToken string
		Reconnect struct {
			InitialDelayMs    int
			MaxDelayMs        int
			BackoffMultiplier float64
		}
		PingIntervalMs int
	}
	WsAPI struct {
		Mode  string
		Relay bool
	}
	WriteCoalescing struct {
		Enabled bool
		DelayMs int
	}
}

func (c *Config) InitialDelay() time.Duration {
	return time.Duration(c.Bridge.Reconnect.InitialDelayMs) * time.Millisecond
}

func (c *Config) MaxDelay() time.Duration {
	return time.Duration(c.Bridge.Reconnect.MaxDelayMs) * time.Millisecond
}

func (c *Config) PingInterval() time.Duration {
	return time.Duration(c.Bridge.PingIntervalMs) * time.Millisecond
}

func (c *Config) CoalesceDelay() time.Duration {
	if !c.WriteCoalescing.Enabled || c.WriteCoalescing.DelayMs <= 0 {
		return 0
	}
	return time.Duration(c.WriteCoalescing.DelayMs) * time.Millisecond
}
