// Package elitedomains implements a DNS provider for Elitedomains (https://elitedomains.de).
package elitedomains

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/diff2"
	"github.com/StackExchange/dnscontrol/v4/pkg/printer"
	"github.com/StackExchange/dnscontrol/v4/pkg/providers"
)

/*
Elitedomains API DNS provider and Registrar:

Info required in `creds.json`:
   - token: API Bearer token (required)

Optional fields:
   - api_url: Custom API URL (default: https://api.elitedomains.de)
   - sandbox: Set to "1" to enable sandbox mode (no real changes)

Example creds.json:
{
  "elitedomains": {
    "TYPE": "ELITEDOMAINS",
    "token": "your-api-token-here"
  }
}

Supported record types: A, AAAA, CNAME, MX, TXT, SPF

Registrar features:
  - Update nameservers (external nameservers require exactly 2 NS)
  - Switch between Elitedomains DNS and external nameservers
*/

// elitedomainsProvider is the handle for operations.
type elitedomainsProvider struct {
	token   string
	apiURL  string
	sandbox bool
	client  *http.Client
}

// Default nameservers for Elitedomains
var defaultNameServerNames = []string{
	"ns1.elitedomains.de",
	"ns2.elitedomains.de",
	"ns3.elitedomains.de",
}

const (
	defaultAPIURL = "https://api.elitedomains.de"
)

var features = providers.DocumentationNotes{
	// The default for unlisted capabilities is 'Cannot'.
	// See providers/capabilities.go for the entire list of capabilities.
	providers.CanAutoDNSSEC:          providers.Cannot("Elitedomains requires external nameservers for DNSSEC"),
	providers.CanConcur:              providers.Can(),
	providers.CanGetZones:            providers.Can(),
	providers.CanUseAlias:            providers.Cannot(),
	providers.CanUseCAA:              providers.Cannot("Not supported by Elitedomains API"),
	providers.CanUseDHCID:            providers.Cannot(),
	providers.CanUseDNAME:            providers.Cannot(),
	providers.CanUseDNSKEY:           providers.Cannot(),
	providers.CanUseDS:               providers.Cannot(),
	providers.CanUseHTTPS:            providers.Cannot(),
	providers.CanUseLOC:              providers.Cannot(),
	providers.CanUseNAPTR:            providers.Cannot(),
	providers.CanUsePTR:              providers.Cannot(),
	providers.CanUseSOA:              providers.Cannot(),
	providers.CanUseSRV:              providers.Cannot("Not supported by Elitedomains API"),
	providers.CanUseSSHFP:            providers.Cannot(),
	providers.CanUseSMIMEA:           providers.Cannot(),
	providers.CanUseSVCB:             providers.Cannot(),
	providers.CanUseTLSA:             providers.Cannot(),
	providers.DocCreateDomains:       providers.Cannot("Domains must be registered separately via the Elitedomains website"),
	providers.DocDualHost:            providers.Can(),
	providers.DocOfficiallySupported: providers.Cannot(),
}

func init() {
	const providerName = "ELITEDOMAINS"
	const providerMaintainer = "@axeldunkel"
	fns := providers.DspFuncs{
		Initializer:   NewElitedomains,
		RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType(providerName, fns, features)
	providers.RegisterRegistrarType(providerName, newElitedomainsReg, features)
	providers.RegisterMaintainer(providerName, providerMaintainer)
}

// newElitedomainsReg creates a new Elitedomains registrar provider.
func newElitedomainsReg(m map[string]string) (providers.Registrar, error) {
	return newElitedomains(m, nil)
}

// NewElitedomains creates a new Elitedomains DNS provider.
func NewElitedomains(m map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	return newElitedomains(m, metadata)
}

// newElitedomains is the internal constructor shared by both provider types.
func newElitedomains(m map[string]string, _ json.RawMessage) (*elitedomainsProvider, error) {
	if m["token"] == "" {
		return nil, fmt.Errorf("elitedomains: token is required")
	}

	apiURL := m["api_url"]
	if apiURL == "" {
		apiURL = defaultAPIURL
	}

	api := &elitedomainsProvider{
		token:   m["token"],
		apiURL:  strings.TrimSuffix(apiURL, "/"),
		sandbox: m["sandbox"] == "1",
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}

	// Validate credentials by fetching domains
	_, err := api.getDomains()
	if err != nil {
		return nil, fmt.Errorf("elitedomains: failed to validate credentials: %w", err)
	}

	return api, nil
}

// API response structures
//
// NOTE: The Elitedomains API has inconsistent JSON typing. The documentation
// shows certain fields as integers or strings, but the actual API responses
// may return different types (e.g., integers as strings, booleans instead of
// strings). The flexible types below handle these inconsistencies gracefully.

type domainsResponse struct {
	CurrentPage flexibleInt  `json:"current_page"`
	PerPage     flexibleInt  `json:"per_page"`
	Data        []domainInfo `json:"data"`
}

type domainInfo struct {
	Name               string              `json:"name"`
	RedirectorSettings *redirectorSettings `json:"redirector_settings"`
	AuthInfo           flexibleString      `json:"authinfo"`
	AutoExpire         flexibleString      `json:"auto_expire"`
	PaidUntil          flexibleString      `json:"paid_until"`
	CreatedAt          flexibleString      `json:"created_at"`
}

type redirectorSettings struct {
	Type    string            `json:"type"`
	Method  string            `json:"method,omitempty"`
	URL     string            `json:"url,omitempty"`     // Required for type "redirect"
	DNS     []dnsRecord       `json:"dns,omitempty"`     // DNS records for type "dns" or "landing"
	NS      []string          `json:"ns,omitempty"`      // External nameservers (exactly 2 required)
	Options map[string]string `json:"options,omitempty"` // DNSSEC options
}

type dnsRecord struct {
	Type  string      `json:"type"`
	Name  string      `json:"name"`
	Value string      `json:"value"`
	Prio  flexibleInt `json:"prio,omitempty"`
	TTL   flexibleInt `json:"ttl,omitempty"`
}

// flexibleString handles JSON fields that can be either a string or a boolean.
// The Elitedomains API may return false instead of an empty string for optional
// fields like "auto_expire" when no value is set.
type flexibleString string

func (f *flexibleString) UnmarshalJSON(data []byte) error {
	// Try string first (most common case)
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = flexibleString(s)
		return nil
	}

	// Try bool (API returns false for unset optional fields)
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		if b {
			*f = "true"
		} else {
			*f = ""
		}
		return nil
	}

	*f = ""
	return nil
}

// flexibleInt handles JSON fields that can be either an integer or a string.
// The Elitedomains API documentation shows integers for fields like "ttl" and
// "prio", but the actual API may return them as quoted strings.
// When marshaling back to JSON, we output as integer (as documented).
type flexibleInt int

func (f *flexibleInt) UnmarshalJSON(data []byte) error {
	// Try int first (as documented)
	var i int
	if err := json.Unmarshal(data, &i); err == nil {
		*f = flexibleInt(i)
		return nil
	}

	// Try string (actual API behavior)
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "" {
			*f = 0
			return nil
		}
		var parsed int
		if _, err := fmt.Sscanf(s, "%d", &parsed); err == nil {
			*f = flexibleInt(parsed)
			return nil
		}
	}

	*f = 0
	return nil
}

func (f flexibleInt) MarshalJSON() ([]byte, error) {
	return json.Marshal(int(f))
}

type updateDomainRequest struct {
	Name               string             `json:"name"`
	RedirectorSettings redirectorSettings `json:"redirector_settings"`
}

type apiResponse struct {
	Message string `json:"message"`
}

// HTTP helper methods

func (api *elitedomainsProvider) doRequest(method, endpoint string, body interface{}) ([]byte, error) {
	url := api.apiURL + endpoint
	if api.sandbox {
		if strings.Contains(url, "?") {
			url += "&sandbox=1"
		} else {
			url += "?sandbox=1"
		}
	}

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+api.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := api.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var apiResp apiResponse
		if json.Unmarshal(respBody, &apiResp) == nil && apiResp.Message != "" {
			return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, apiResp.Message)
		}
		return nil, fmt.Errorf("API error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (api *elitedomainsProvider) getDomains() ([]domainInfo, error) {
	var allDomains []domainInfo
	page := 1

	for {
		endpoint := fmt.Sprintf("/domains?page=%d", page)
		respBody, err := api.doRequest("GET", endpoint, nil)
		if err != nil {
			return nil, err
		}

		var domainsResp domainsResponse
		if err := json.Unmarshal(respBody, &domainsResp); err != nil {
			return nil, fmt.Errorf("failed to parse domains response: %w", err)
		}

		allDomains = append(allDomains, domainsResp.Data...)

		// Check if we got all domains
		if len(domainsResp.Data) < int(domainsResp.PerPage) {
			break
		}
		page++
	}

	return allDomains, nil
}

func (api *elitedomainsProvider) getDomain(domain string) (*domainInfo, error) {
	domains, err := api.getDomains()
	if err != nil {
		return nil, err
	}

	for i := range domains {
		if domains[i].Name == domain {
			return &domains[i], nil
		}
	}

	return nil, fmt.Errorf("domain %s not found", domain)
}

func (api *elitedomainsProvider) updateDomain(domain string, settings redirectorSettings) error {
	req := updateDomainRequest{
		Name:               domain,
		RedirectorSettings: settings,
	}

	_, err := api.doRequest("PATCH", "/domains", req)
	return err
}

// DNSServiceProvider interface implementation

// GetNameservers returns the nameservers for a domain.
func (api *elitedomainsProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	domainInfo, err := api.getDomain(domain)
	if err != nil {
		// If we can't get the domain, return default nameservers
		return models.ToNameservers(defaultNameServerNames)
	}

	// If using external nameservers, return those
	if domainInfo.RedirectorSettings != nil &&
		domainInfo.RedirectorSettings.Type == "external" &&
		len(domainInfo.RedirectorSettings.NS) > 0 {
		return models.ToNameservers(domainInfo.RedirectorSettings.NS)
	}

	return models.ToNameservers(defaultNameServerNames)
}

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
func (api *elitedomainsProvider) GetZoneRecords(domain string, meta map[string]string) (models.Records, error) {
	domainInfo, err := api.getDomain(domain)
	if err != nil {
		return nil, err
	}

	var existingRecords []*models.RecordConfig

	if domainInfo.RedirectorSettings == nil || domainInfo.RedirectorSettings.DNS == nil {
		return existingRecords, nil
	}

	for i := range domainInfo.RedirectorSettings.DNS {
		rec := &domainInfo.RedirectorSettings.DNS[i]

		// Skip records with invalid/placeholder values that the API may return
		if rec.Value == "" || rec.Value == "invalid IP" {
			printer.Printf("WARNING: Skipping %s record '%s' with invalid value '%s' for domain %s\n",
				rec.Type, rec.Name, rec.Value, domain)
			continue
		}

		rc, err := api.toRecordConfig(domain, rec)
		if err != nil {
			// Log warning but continue processing other records
			printer.Printf("WARNING: Failed to parse %s record '%s' for domain %s: %v\n",
				rec.Type, rec.Name, domain, err)
			continue
		}
		existingRecords = append(existingRecords, rc)
	}

	return existingRecords, nil
}

// ListZones returns the list of zones (domains) in this account.
func (api *elitedomainsProvider) ListZones() ([]string, error) {
	domains, err := api.getDomains()
	if err != nil {
		return nil, err
	}

	var zones []string
	for _, d := range domains {
		zones = append(zones, d.Name)
	}

	return zones, nil
}

// GetZoneRecordsCorrections returns a list of corrections that will turn existing records into dc.Records.
func (api *elitedomainsProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, existingRecords models.Records) ([]*models.Correction, int, error) {
	var corrections []*models.Correction

	// Get current domain info for the redirector settings
	domainInfo, err := api.getDomain(dc.Name)
	if err != nil {
		return nil, 0, err
	}

	// Use diff2 to calculate the changes needed
	instructions, actualChangeCount, err := diff2.ByRecord(existingRecords, dc, nil)
	if err != nil {
		return nil, 0, err
	}

	if actualChangeCount == 0 {
		return nil, 0, nil
	}

	// Build the new DNS records list based on instructions
	// Note: Elitedomains API requires sending ALL records in a single PATCH request
	// We can't create/update/delete individual records

	// Collect all desired records
	var newRecords []dnsRecord
	for _, rec := range dc.Records {
		apiRec := api.toAPIRecord(rec)
		newRecords = append(newRecords, apiRec)
	}

	// Build the redirector settings, preserving all existing fields
	settings := api.buildSettingsForDNSUpdate(domainInfo, newRecords)

	// Create a single correction that applies all changes
	var msgs []string
	for _, inst := range instructions {
		if inst.MsgsJoined != "" {
			msgs = append(msgs, inst.MsgsJoined)
		}
	}

	corrections = append(corrections, &models.Correction{
		Msg: strings.Join(msgs, "\n"),
		F: func() error {
			return api.updateDomain(dc.Name, settings)
		},
	})

	return corrections, actualChangeCount, nil
}

// Record conversion helpers

func (api *elitedomainsProvider) toRecordConfig(domain string, rec *dnsRecord) (*models.RecordConfig, error) {
	rc := &models.RecordConfig{
		Type:     rec.Type,
		Original: rec,
	}

	// Set TTL (default 3600 if not specified)
	if rec.TTL > 0 {
		rc.TTL = uint32(rec.TTL)
	} else {
		rc.TTL = 3600
	}

	// Handle name: "@" means apex, otherwise it's a subdomain
	name := rec.Name
	if name == "@" {
		name = ""
	}
	rc.SetLabel(name, domain)

	// Handle target based on record type
	target := rec.Value

	switch rec.Type {
	case "MX":
		rc.MxPreference = uint16(rec.Prio)
		// MX targets should be FQDN with trailing dot
		if !strings.HasSuffix(target, ".") {
			target = target + "."
		}
		if err := rc.SetTarget(target); err != nil {
			return nil, err
		}
	case "CNAME":
		// CNAME targets should be FQDN with trailing dot
		if !strings.HasSuffix(target, ".") {
			target = target + "."
		}
		if err := rc.SetTarget(target); err != nil {
			return nil, err
		}
	case "TXT", "SPF":
		// TXT records: handle as-is
		if err := rc.SetTargetTXT(target); err != nil {
			return nil, err
		}
	default:
		if err := rc.SetTarget(target); err != nil {
			return nil, err
		}
	}

	return rc, nil
}

func (api *elitedomainsProvider) toAPIRecord(rc *models.RecordConfig) dnsRecord {
	rec := dnsRecord{
		Type: rc.Type,
		TTL:  flexibleInt(rc.TTL),
	}

	// Handle label: empty means apex, use "@"
	label := rc.GetLabel()
	if label == "" || label == "@" {
		rec.Name = "@"
	} else {
		rec.Name = label
	}

	// Handle target based on record type
	switch rc.Type {
	case "MX":
		rec.Prio = flexibleInt(rc.MxPreference)
		target := rc.GetTargetField()
		// Remove trailing dot for API
		rec.Value = strings.TrimSuffix(target, ".")
	case "CNAME":
		target := rc.GetTargetField()
		// Remove trailing dot for API
		rec.Value = strings.TrimSuffix(target, ".")
	case "TXT", "SPF":
		// Get TXT content joined
		rec.Value = rc.GetTargetTXTJoined()
	default:
		rec.Value = rc.GetTargetField()
	}

	return rec
}

// Debug helper
func (api *elitedomainsProvider) debugPrintRecords(domain string) {
	records, err := api.GetZoneRecords(domain, nil)
	if err != nil {
		printer.Printf("Error getting records: %v\n", err)
		return
	}
	for _, r := range records {
		printer.Printf("  %s %s %s %d\n", r.GetLabel(), r.Type, r.GetTargetField(), r.TTL)
	}
}

// buildSettingsForDNSUpdate creates redirector settings for a DNS update,
// preserving all existing settings and only replacing the DNS records.
// The Elitedomains API requires all settings to be sent in a single request,
// so we must copy all existing fields (Type, Method, URL, Options, NS) and
// only update the DNS array.
func (api *elitedomainsProvider) buildSettingsForDNSUpdate(domainInfo *domainInfo, newRecords []dnsRecord) redirectorSettings {
	// If no existing settings, use default DNS type
	if domainInfo.RedirectorSettings == nil {
		return redirectorSettings{
			Type: "dns",
			DNS:  newRecords,
		}
	}

	// Copy all existing settings and only replace DNS records
	existing := domainInfo.RedirectorSettings
	return redirectorSettings{
		Type:    existing.Type,
		Method:  existing.Method,
		URL:     existing.URL,
		NS:      existing.NS,
		Options: existing.Options,
		DNS:     newRecords,
	}
}

// Registrar interface implementation

// GetRegistrarCorrections returns corrections to update the domain's nameservers.
func (api *elitedomainsProvider) GetRegistrarCorrections(dc *models.DomainConfig) ([]*models.Correction, error) {
	// Get current domain info
	domainInfo, err := api.getDomain(dc.Name)
	if err != nil {
		return nil, err
	}

	// Get current nameservers from the domain
	currentNS := api.getCurrentNameservers(domainInfo)

	// Get desired nameservers from the domain config
	desiredNS := make([]string, 0, len(dc.Nameservers))
	for _, ns := range dc.Nameservers {
		desiredNS = append(desiredNS, strings.TrimSuffix(ns.Name, "."))
	}

	// Check if nameservers need to be updated
	if api.nameserversMatch(currentNS, desiredNS) {
		return nil, nil
	}

	// Elitedomains requires at least 2 nameservers for external NS
	if !api.isElitedomainsNameservers(desiredNS) && len(desiredNS) < 2 {
		return nil, fmt.Errorf("elitedomains: at least 2 external nameservers required, got %d", len(desiredNS))
	}

	// Build the correction
	correction := &models.Correction{
		Msg: fmt.Sprintf("Update nameservers: %s -> %s", strings.Join(currentNS, ", "), strings.Join(desiredNS, ", ")),
		F: func() error {
			return api.updateNameservers(dc.Name, desiredNS, domainInfo)
		},
	}

	return []*models.Correction{correction}, nil
}

// getCurrentNameservers extracts the current nameservers from domain info.
func (api *elitedomainsProvider) getCurrentNameservers(domainInfo *domainInfo) []string {
	if domainInfo.RedirectorSettings == nil {
		return defaultNameServerNames
	}

	// If using external nameservers
	if domainInfo.RedirectorSettings.Type == "external" && len(domainInfo.RedirectorSettings.NS) > 0 {
		return domainInfo.RedirectorSettings.NS
	}

	// Default to Elitedomains nameservers
	return defaultNameServerNames
}

// nameserversMatch checks if two nameserver lists are equivalent.
func (api *elitedomainsProvider) nameserversMatch(current, desired []string) bool {
	if len(current) != len(desired) {
		return false
	}

	// Create maps for comparison (case-insensitive)
	currentMap := make(map[string]bool)
	for _, ns := range current {
		currentMap[strings.ToLower(ns)] = true
	}

	for _, ns := range desired {
		if !currentMap[strings.ToLower(ns)] {
			return false
		}
	}

	return true
}

// updateNameservers updates the domain's nameservers via the API.
func (api *elitedomainsProvider) updateNameservers(domain string, nameservers []string, domainInfo *domainInfo) error {
	// Check if we're switching to Elitedomains' own nameservers or external ones
	isElitedomainsNS := api.isElitedomainsNameservers(nameservers)

	var settings redirectorSettings

	if isElitedomainsNS {
		// Switch back to Elitedomains DNS (landing page mode)
		settings = redirectorSettings{
			Type:   "landing",
			Method: "redirect_sale_page",
		}
		// Preserve existing DNS records if any
		if domainInfo.RedirectorSettings != nil && domainInfo.RedirectorSettings.DNS != nil {
			settings.DNS = domainInfo.RedirectorSettings.DNS
		}
	} else {
		// Switch to external nameservers
		// Elitedomains requires exactly 2 nameservers
		if len(nameservers) < 2 {
			return fmt.Errorf("elitedomains: exactly 2 external nameservers required, got %d", len(nameservers))
		}
		settings = redirectorSettings{
			Type: "external",
			NS:   nameservers[:2], // Take first 2 nameservers
		}
	}

	return api.updateDomain(domain, settings)
}

// isElitedomainsNameservers checks if the nameservers are Elitedomains' own nameservers.
func (api *elitedomainsProvider) isElitedomainsNameservers(nameservers []string) bool {
	for _, ns := range nameservers {
		nsLower := strings.ToLower(ns)
		isElite := false
		for _, defaultNS := range defaultNameServerNames {
			if strings.ToLower(defaultNS) == nsLower {
				isElite = true
				break
			}
		}
		if !isElite {
			return false
		}
	}
	return true
}
