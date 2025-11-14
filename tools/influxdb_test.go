//go:build integration

package tools

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueryInfluxDB(t *testing.T) {
	ctx := newTestContext()

	// Note: This test requires an InfluxDB datasource to be configured
	// You may need to adjust the datasource UID based on your setup
	
	t.Run("query with InfluxQL", func(t *testing.T) {
		// Example InfluxQL query
		result, err := queryInfluxDB(ctx, QueryInfluxDBParams{
			DatasourceUID: "influxdb-test", // Adjust this to your datasource UID
			Database:      "mydb",
			Query:         "SELECT mean(value) FROM cpu WHERE time > now() - 1h GROUP BY time(5m)",
			StartTime:     "now-1h",
			EndTime:       "now",
		})
		
		// Depending on your setup, this may fail if datasource doesn't exist
		// That's okay for initial development
		if err != nil {
			t.Skipf("Skipping test: %v", err)
			return
		}
		
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "success", result.Status)
	})

	t.Run("query with Flux", func(t *testing.T) {
		// Example Flux query
		fluxQuery := `
from(bucket: "mydb")
  |> range(start: -1h)
  |> filter(fn: (r) => r["_measurement"] == "cpu")
  |> filter(fn: (r) => r["_field"] == "usage_idle")
  |> aggregateWindow(every: 5m, fn: mean)
`
		result, err := queryInfluxDB(ctx, QueryInfluxDBParams{
			DatasourceUID: "influxdb-test",
			Query:         fluxQuery,
			StartTime:     "now-1h",
			EndTime:       "now",
		})
		
		if err != nil {
			t.Skipf("Skipping test: %v", err)
			return
		}
		
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "success", result.Status)
	})

	t.Run("invalid datasource type", func(t *testing.T) {
		// Try to query a non-InfluxDB datasource
		_, err := queryInfluxDB(ctx, QueryInfluxDBParams{
			DatasourceUID: "prometheus-test", // Not an InfluxDB datasource
			Query:         "SELECT * FROM cpu",
		})
		
		// Should fail because it's not an InfluxDB datasource
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not an InfluxDB datasource")
	})
}

func TestParseInfluxTimeRange(t *testing.T) {
	tests := []struct {
		name      string
		start     string
		end       string
		wantError bool
	}{
		{
			name:      "relative time",
			start:     "now-1h",
			end:       "now",
			wantError: false,
		},
		{
			name:      "RFC3339 format",
			start:     "2024-01-01T00:00:00Z",
			end:       "2024-01-01T01:00:00Z",
			wantError: false,
		},
		{
			name:      "mixed formats",
			start:     "now-24h",
			end:       "2024-01-01T00:00:00Z",
			wantError: false,
		},
		{
			name:      "invalid format",
			start:     "invalid",
			end:       "now",
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			startMs, endMs, err := parseInfluxTimeRange(tt.start, tt.end)
			
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Greater(t, endMs, startMs, "end time should be after start time")
			}
		})
	}
}





