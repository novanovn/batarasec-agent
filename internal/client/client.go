package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/batarasec/agent/internal/version"
	"github.com/batarasec/agent/pkg/findings"
)

const (
	chunkSize  = 100
	maxRetries = 3
)

// Client is an HTTP client for the BataraSec platform agent API.
type Client struct {
	baseURL    string
	token      string
	agentID    string
	httpClient *http.Client
}

func New(baseURL, token, agentID string, tlsSkipVerify bool) *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: tlsSkipVerify}, //nolint:gosec
	}
	if tlsSkipVerify {
		zap.L().Warn("TLS verification disabled - connections may be insecure")
	}
	return &Client{
		baseURL: baseURL,
		token:   token,
		agentID: agentID,
		httpClient: &http.Client{
			Timeout:   30 * time.Second,
			Transport: tr,
		},
	}
}

// — Internal helpers —

func (c *Client) do(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal: %w", err)
		}
		r = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "batarasec-agent/"+version.Version)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.httpClient.Do(req)
}

func (c *Client) doWithRetry(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var lastErr error
	for attempt := range maxRetries {
		if attempt > 0 {
			delay := time.Duration(1<<uint(attempt-1)) * time.Second // 1s, 2s
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}
		resp, err := c.do(ctx, method, path, body)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return string(b)
}

// — Public API —

type enrollRequest struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
}

type EnrollResponse struct {
	AgentID   string `json:"agent_id"`
	ProjectID string `json:"project_id"`
	JWT       string `json:"jwt"`
	Message   string `json:"message"`
}

// Enroll registers the agent. The client must be initialised with the
// enrollment API key as the token so it goes in the Authorization header.
func (c *Client) Enroll(ctx context.Context, req enrollRequest) (*EnrollResponse, error) {
	resp, err := c.doWithRetry(ctx, http.MethodPost, "/api/agent/v1/enroll", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("enroll: HTTP %d — %s", resp.StatusCode, readBody(resp))
	}
	var out EnrollResponse
	return &out, json.NewDecoder(resp.Body).Decode(&out)
}

func NewEnrollRequest(hostname, goos, goarch string) enrollRequest {
	return enrollRequest{Hostname: hostname, OS: goos, Arch: goarch, Version: version.Version}
}

// Heartbeat sends a ping to the platform. Called every 30 min via the scan timer.
func (c *Client) Heartbeat(ctx context.Context) error {
	body := map[string]string{"agent_id": c.agentID}
	resp, err := c.doWithRetry(ctx, http.MethodPost, "/api/agent/v1/heartbeat", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("heartbeat: HTTP %d", resp.StatusCode)
	}
	return nil
}

type scanStartRequest struct {
	AgentID   string `json:"agent_id"`
	ProjectID string `json:"project_id"`
}

type scanStartResponse struct {
	JobID string `json:"job_id"`
}

// ScanStart opens a new scan job and returns the job ID.
func (c *Client) ScanStart(ctx context.Context, projectID string) (string, error) {
	resp, err := c.doWithRetry(ctx, http.MethodPost, "/api/agent/v1/scan/start",
		scanStartRequest{AgentID: c.agentID, ProjectID: projectID})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("scan/start: HTTP %d — %s", resp.StatusCode, readBody(resp))
	}
	var out scanStartResponse
	return out.JobID, json.NewDecoder(resp.Body).Decode(&out)
}

type pushRequest struct {
	Findings []findings.Finding `json:"findings"`
}

// ScanPush sends one chunk (≤100 findings) to the platform.
func (c *Client) ScanPush(ctx context.Context, jobID string, chunk []findings.Finding) error {
	resp, err := c.doWithRetry(ctx, http.MethodPost,
		"/api/agent/v1/scan/"+jobID+"/push",
		pushRequest{Findings: chunk})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("scan/push: HTTP %d — %s", resp.StatusCode, readBody(resp))
	}
	return nil
}

type posturePushRequest struct {
	Findings []findings.PostureFinding `json:"findings"`
}

// ScanPosturePush sends posture findings to the platform.
func (c *Client) ScanPosturePush(ctx context.Context, jobID string, findings []findings.PostureFinding) error {
	resp, err := c.doWithRetry(ctx, http.MethodPost,
		"/api/agent/v1/scan/"+jobID+"/posture",
		posturePushRequest{Findings: findings})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("scan/posture: HTTP %d — %s", resp.StatusCode, readBody(resp))
	}
	return nil
}

type Command struct {
	ID     string          `json:"id"`
	Type   string          `json:"type"`
	Params json.RawMessage `json:"params"`
}

type pollCommandsResponse struct {
	Commands []Command `json:"commands"`
}

func (c *Client) PollCommands(ctx context.Context) ([]Command, error) {
	resp, err := c.doWithRetry(ctx, http.MethodGet, "/api/agent/v1/commands", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("commands: HTTP %d — %s", resp.StatusCode, readBody(resp))
	}
	var out pollCommandsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Commands, nil
}

type commandDoneRequest struct {
	Status       string `json:"status"`
	ScanJobID    string `json:"scan_job_id,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
}

func (c *Client) CommandDone(ctx context.Context, commandID, status, scanJobID, errorMessage string) error {
	resp, err := c.doWithRetry(ctx, http.MethodPost, "/api/agent/v1/commands/"+commandID+"/done", commandDoneRequest{
		Status:       status,
		ScanJobID:    scanJobID,
		ErrorMessage: errorMessage,
	})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("commands/done: HTTP %d — %s", resp.StatusCode, readBody(resp))
	}
	return nil
}

type doneRequest struct {
	TotalFindings int `json:"total_findings"`
}

// ScanDone finalises a scan job.
func (c *Client) ScanDone(ctx context.Context, jobID string, total int) error {
	resp, err := c.doWithRetry(ctx, http.MethodPost,
		"/api/agent/v1/scan/"+jobID+"/done",
		doneRequest{TotalFindings: total})
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("scan/done: HTTP %d — %s", resp.StatusCode, readBody(resp))
	}
	return nil
}

// SendChunked splits findings into 100-item chunks and calls ScanPush for each.
func (c *Client) SendChunked(ctx context.Context, jobID string, all []findings.Finding) error {
	for i := 0; i < len(all); i += chunkSize {
		end := i + chunkSize
		if end > len(all) {
			end = len(all)
		}
		if err := c.ScanPush(ctx, jobID, all[i:end]); err != nil {
			return fmt.Errorf("chunk %d-%d: %w", i, end, err)
		}
	}
	return nil
}

// DownloadVulnDBPack downloads the vulnerability pack for one ecosystem.
func (c *Client) DownloadVulnDBPack(ctx context.Context, ecosystem, destPath string) error {
	resp, err := c.do(ctx, http.MethodGet, "/api/agent/v1/vuln-db/pack?eco="+ecosystem, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vuln-db/pack: HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", destPath, err)
	}
	defer f.Close()

	// Limit download size to 500MB to prevent disk exhaustion
	_, err = io.Copy(f, io.LimitReader(resp.Body, 500<<20))
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	return nil
}

// GetAgentConfig fetches remote config overrides from the platform.
func (c *Client) GetAgentConfig(ctx context.Context) (map[string]interface{}, error) {
	resp, err := c.doWithRetry(ctx, http.MethodGet, "/api/agent/v1/config", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config: HTTP %d", resp.StatusCode)
	}
	var out map[string]interface{}
	return out, json.NewDecoder(resp.Body).Decode(&out)
}
