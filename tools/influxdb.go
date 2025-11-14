package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/backend/gtime"
	mcpgrafana "github.com/grafana/mcp-grafana"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// QueryInfluxDBParams defines parameters for querying InfluxDB datasource
type QueryInfluxDBParams struct {
	DatasourceUID string `json:"datasourceUid" jsonschema:"required,description=The UID of the InfluxDB datasource"`
	Query         string `json:"query" jsonschema:"required,description=The InfluxQL or Flux query to execute"`
	Database      string `json:"database,omitempty" jsonschema:"description=The database name (required for InfluxQL\\, not needed for Flux)"`
	StartTime     string `json:"startTime,omitempty" jsonschema:"description=Start time in RFC3339 format or relative time (e.g.\\, 'now-1h'\\, 'now-24h')"`
	EndTime       string `json:"endTime,omitempty" jsonschema:"description=End time in RFC3339 format or relative time (e.g.\\, 'now')"`
}

// GrafanaQueryRequest represents the request payload for Grafana's /api/ds/query endpoint
type GrafanaQueryRequest struct {
	Queries []GrafanaQuery `json:"queries"`
	From    string         `json:"from,omitempty"`
	To      string         `json:"to,omitempty"`
}

// GrafanaQuery represents a single query in the request
type GrafanaQuery struct {
	RefID      string            `json:"refId"`
	Datasource GrafanaDatasource `json:"datasource"`
	RawQuery   bool              `json:"rawQuery"`
	Query      string            `json:"query"`
	Format     string            `json:"format,omitempty"`
	Database   string            `json:"database,omitempty"`
}

// GrafanaDatasource represents datasource info
type GrafanaDatasource struct {
	Type string `json:"type"`
	UID  string `json:"uid"`
}

// GrafanaQueryResponse represents the response from Grafana's /api/ds/query endpoint
type GrafanaQueryResponse struct {
	Results map[string]GrafanaQueryResult `json:"results"`
}

// GrafanaQueryResult represents a single query result
type GrafanaQueryResult struct {
	Status int                 `json:"status"`
	Frames []GrafanaDataFrame  `json:"frames,omitempty"`
	Error  string              `json:"error,omitempty"`
	Series []InfluxDBSeries    `json:"series,omitempty"` // For InfluxQL
	Tables []InfluxDBFluxTable `json:"tables,omitempty"` // For Flux
}

// GrafanaDataFrame represents a data frame in Grafana's response
type GrafanaDataFrame struct {
	Schema GrafanaSchema        `json:"schema"`
	Data   GrafanaDataFrameData `json:"data,omitempty"`
}

// GrafanaSchema represents the schema of a data frame
type GrafanaSchema struct {
	Name   string               `json:"name,omitempty"`
	Fields []GrafanaFieldSchema `json:"fields,omitempty"`
}

// GrafanaFieldSchema represents a field schema
type GrafanaFieldSchema struct {
	Name   string                 `json:"name"`
	Type   string                 `json:"type,omitempty"`
	Config map[string]interface{} `json:"config,omitempty"`
	Labels map[string]string      `json:"labels,omitempty"`
}

// GrafanaDataFrameData represents the data in a frame
type GrafanaDataFrameData struct {
	Values [][]interface{} `json:"values,omitempty"`
}

// InfluxDBSeries represents a series in InfluxQL response
type InfluxDBSeries struct {
	Name    string            `json:"name"`
	Tags    map[string]string `json:"tags,omitempty"`
	Columns []string          `json:"columns"`
	Values  [][]interface{}   `json:"values"`
}

// InfluxDBFluxTable represents a table in Flux response
type InfluxDBFluxTable struct {
	Columns []InfluxDBFluxColumn `json:"columns"`
	Rows    [][]interface{}      `json:"rows"`
}

// InfluxDBFluxColumn represents a column in Flux response
type InfluxDBFluxColumn struct {
	Text string `json:"text"`
	Type string `json:"type,omitempty"`
}

// InfluxDBQueryResult represents the simplified result to return
type InfluxDBQueryResult struct {
	Status string      `json:"status"`
	Data   interface{} `json:"data"`
	Error  string      `json:"error,omitempty"`
}

// queryInfluxDB executes a query against an InfluxDB datasource through Grafana's datasource query API
func queryInfluxDB(ctx context.Context, args QueryInfluxDBParams) (*InfluxDBQueryResult, error) {
	// Verify datasource exists and is InfluxDB
	ds, err := getDatasourceByUID(ctx, GetDatasourceByUIDParams{UID: args.DatasourceUID})
	if err != nil {
		return nil, fmt.Errorf("get datasource: %w", err)
	}

	if !strings.Contains(strings.ToLower(ds.Type), "influx") {
		return nil, fmt.Errorf("datasource %s is not an InfluxDB datasource (type: %s)", args.DatasourceUID, ds.Type)
	}

	cfg := mcpgrafana.GrafanaConfigFromContext(ctx)

	// Prepare query payload using Grafana's ds/query API format
	query := GrafanaQuery{
		RefID:    "A",
		RawQuery: true,
		Query:    args.Query,
		Format:   "time_series", // Can be "time_series" or "table"
		Datasource: GrafanaDatasource{
			Type: ds.Type,
			UID:  args.DatasourceUID,
		},
	}

	// Add database if specified (for InfluxQL)
	if args.Database != "" {
		query.Database = args.Database
	}

	payload := GrafanaQueryRequest{
		Queries: []GrafanaQuery{query},
	}

	// Add time range if specified
	if args.StartTime != "" && args.EndTime != "" {
		startMs, endMs, err := parseInfluxTimeRange(args.StartTime, args.EndTime)
		if err != nil {
			return nil, fmt.Errorf("parse time range: %w", err)
		}
		payload.From = fmt.Sprintf("%d", startMs)
		payload.To = fmt.Sprintf("%d", endMs)
	}

	// Marshal payload
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal query payload: %w", err)
	}

	// Build request URL
	url := fmt.Sprintf("%s/api/ds/query", strings.TrimRight(cfg.URL, "/"))

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	// Add authentication
	if cfg.AccessToken != "" && cfg.IDToken != "" {
		req.Header.Set("X-Access-Token", cfg.AccessToken)
		req.Header.Set("X-Grafana-Id", cfg.IDToken)
	} else if cfg.APIKey != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", cfg.APIKey))
	} else if cfg.BasicAuth != nil {
		password, _ := cfg.BasicAuth.Password()
		req.SetBasicAuth(cfg.BasicAuth.Username(), password)
	}

	// Add org ID if specified
	if cfg.OrgID > 0 {
		req.Header.Set("X-Grafana-Org-Id", fmt.Sprintf("%d", cfg.OrgID))
	}

	// Create HTTP client with TLS config if available
	var transport http.RoundTripper = http.DefaultTransport
	if tlsConfig := cfg.TLSConfig; tlsConfig != nil {
		customTransport, err := tlsConfig.HTTPTransport(http.DefaultTransport.(*http.Transport))
		if err != nil {
			return nil, fmt.Errorf("failed to create custom transport: %w", err)
		}
		transport = customTransport
	}

	// Wrap with org ID and user agent
	transport = mcpgrafana.NewOrgIDRoundTripper(transport, cfg.OrgID)
	transport = mcpgrafana.NewUserAgentTransport(transport)

	client := &http.Client{
		Timeout:   60 * time.Second,
		Transport: transport,
	}

	// Execute request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute query: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query failed with status %d: %s", resp.StatusCode, string(body))
	}

	// Parse Grafana's response
	var grafanaResp GrafanaQueryResponse
	if err := json.Unmarshal(body, &grafanaResp); err != nil {
		return nil, fmt.Errorf("parse grafana response: %w", err)
	}

	// Extract the result for refId "A"
	queryResult, ok := grafanaResp.Results["A"]
	if !ok {
		return nil, fmt.Errorf("no result found for query")
	}

	// Check for errors
	if queryResult.Error != "" {
		return &InfluxDBQueryResult{
			Status: "error",
			Error:  queryResult.Error,
		}, nil
	}

	// Process the result based on what's available
	var resultData interface{}

	if len(queryResult.Frames) > 0 {
		// Grafana returned data frames (modern format)
		resultData = queryResult.Frames
	} else if len(queryResult.Series) > 0 {
		// InfluxQL response format
		resultData = queryResult.Series
	} else if len(queryResult.Tables) > 0 {
		// Flux response format
		resultData = queryResult.Tables
	} else {
		return &InfluxDBQueryResult{
			Status: "success",
			Data:   []interface{}{},
		}, nil
	}

	return &InfluxDBQueryResult{
		Status: "success",
		Data:   resultData,
	}, nil
}

// parseInfluxTimeRange converts time strings to milliseconds timestamps
func parseInfluxTimeRange(start, end string) (int64, int64, error) {
	now := time.Now()

	startTime, err := parseInfluxTime(start, now)
	if err != nil {
		return 0, 0, fmt.Errorf("parse start time: %w", err)
	}

	endTime, err := parseInfluxTime(end, now)
	if err != nil {
		return 0, 0, fmt.Errorf("parse end time: %w", err)
	}

	return startTime.UnixMilli(), endTime.UnixMilli(), nil
}

// parseInfluxTime parses a time string (RFC3339 or relative like "now-1h")
func parseInfluxTime(timeStr string, now time.Time) (time.Time, error) {
	// Use Grafana's time parser for consistency
	tr := gtime.TimeRange{
		From: timeStr,
		Now:  now,
	}

	parsedTime, err := tr.ParseFrom()
	if err != nil {
		// Fallback to simple parsing
		if timeStr == "now" {
			return now, nil
		}

		// Try RFC3339 format
		t, err := time.Parse(time.RFC3339, timeStr)
		if err != nil {
			return time.Time{}, fmt.Errorf("parse time %s: %w", timeStr, err)
		}
		return t, nil
	}

	return parsedTime, nil
}

// QueryInfluxDB is the MCP tool for querying InfluxDB
var QueryInfluxDB = mcpgrafana.MustTool(
	"query_influxdb",
	"Execute a query against an InfluxDB datasource. Supports both InfluxQL and Flux queries. For InfluxQL\\, you must specify the database parameter. Time range can be specified using RFC3339 format or relative time expressions like 'now'\\, 'now-1h'\\, 'now-24h'\\, etc.",
	queryInfluxDB,
	mcp.WithTitleAnnotation("Query InfluxDB"),
	mcp.WithIdempotentHintAnnotation(true),
	mcp.WithReadOnlyHintAnnotation(true),
)

// AddInfluxDBTools registers InfluxDB query tools with the MCP server
func AddInfluxDBTools(s *server.MCPServer) {
	QueryInfluxDB.Register(s)
}
