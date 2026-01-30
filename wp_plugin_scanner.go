package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// ===================== STEALTH & WAF BYPASS =====================

var userAgents = []string{
	// Chrome variants (most common)
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	// Firefox variants
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
	"Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
	// Safari
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
	// Edge
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
	// Mobile
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
}

// Accept header variations for randomization
var acceptHeaders = []string{
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
}

// Language header variations
var acceptLanguages = []string{
	"en-US,en;q=0.9",
	"en-US,en;q=0.5",
	"en-GB,en-US;q=0.9,en;q=0.8",
	"en,en-US;q=0.9",
	"en-US,en;q=0.9,vi;q=0.8",
}

// randString returns a short random alphanumeric string
func randString(n int) string {
	letters := "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// getRandomUserAgent returns a random user-agent string with random suffix for variety
func getRandomUserAgent() string {
	base := userAgents[rand.Intn(len(userAgents))]
	// Append random suffix to create more UA variety
	suffix := randString(4 + rand.Intn(4)) // 4-7 random chars
	return base + " " + suffix
}

// getRandomIP generates a random IP for X-Forwarded-For spoofing
func getRandomIP() string {
	return fmt.Sprintf("%d.%d.%d.%d", rand.Intn(223)+1, rand.Intn(255), rand.Intn(255), rand.Intn(255))
}

// getJitter returns random delay jitter (±30% of base delay)
func getJitter(baseDelay time.Duration) time.Duration {
	if baseDelay == 0 {
		return 0
	}
	jitter := float64(baseDelay) * (0.7 + rand.Float64()*0.6) // 70%-130% of base
	return time.Duration(jitter)
}

// getCacheBuster returns a random cache busting parameter
func getCacheBuster() string {
	return fmt.Sprintf("?_=%d", time.Now().UnixNano())
}

// getWAFBypassHeaders returns headers to help bypass WAF protections
func getWAFBypassHeaders(stealthy bool, targetHost string) map[string]string {
	headers := make(map[string]string)
	
	if !stealthy {
		return headers
	}
	
	// Randomized Accept header
	headers["Accept"] = acceptHeaders[rand.Intn(len(acceptHeaders))]
	headers["Accept-Language"] = acceptLanguages[rand.Intn(len(acceptLanguages))]
	headers["Accept-Encoding"] = "gzip, deflate, br"
	headers["Connection"] = "keep-alive"
	headers["Upgrade-Insecure-Requests"] = "1"
	
	// Sec-Fetch headers (modern browser fingerprint)
	headers["Sec-Fetch-Dest"] = "document"
	headers["Sec-Fetch-Mode"] = "navigate"
	headers["Sec-Fetch-Site"] = "none"
	headers["Sec-Fetch-User"] = "?1"
	
	// Cache control variations
	cacheControls := []string{"max-age=0", "no-cache", "no-store, max-age=0"}
	headers["Cache-Control"] = cacheControls[rand.Intn(len(cacheControls))]
	
	// DNT header
	headers["DNT"] = "1"
	
	// Priority header (Chrome-like)
	headers["Priority"] = "u=0, i"
	
	// X-Forwarded-For spoofing (bypass IP-based rate limiting)
	headers["X-Forwarded-For"] = getRandomIP()
	headers["X-Real-IP"] = getRandomIP()
	headers["X-Client-IP"] = getRandomIP()
	headers["CF-Connecting-IP"] = getRandomIP()
	
	// X-Originating-IP
	headers["X-Originating-IP"] = getRandomIP()
	
	// Randomized referer
	referers := []string{
		"https://www.google.com/search?q=" + targetHost,
		"https://www.google.com/",
		"https://www.bing.com/search?q=" + targetHost,
		"https://duckduckgo.com/?q=" + targetHost,
		"https://www.facebook.com/",
		"https://twitter.com/",
		"https://www.linkedin.com/",
		"https://" + targetHost + "/",
		"", // No referer
	}
	if ref := referers[rand.Intn(len(referers))]; ref != "" {
		headers["Referer"] = ref
	}
	
	return headers
}

// Plugin represents a WordPress plugin

type Plugin struct {
	Slug           string `json:"slug"`
	Name           string `json:"name"`
	Version        string `json:"version"`
	LatestVersion  string `json:"latest_version"`
	ActiveInstalls int    `json:"active_installs"`
}

// PluginAPIResponse represents the WordPress API response
type PluginAPIResponse struct {
	Info struct {
		Page    int `json:"page"`
		Pages   int `json:"pages"`
		Results int `json:"results"`
	} `json:"info"`
	Plugins []struct {
		Slug           string `json:"slug"`
		Name           string `json:"name"`
		Version        string `json:"version"`
		ActiveInstalls int    `json:"active_installs"`
	} `json:"plugins"`
}

// Vulnerability represents a known vulnerability
type Vulnerability struct {
	VersionAffected string `json:"version_affected"`
	Severity        string `json:"severity"`
	CVE             string `json:"cve"`
	Description     string `json:"description"`
}

// RiskAnalysis contains risk assessment info
type RiskAnalysis struct {
	RiskScore      int      `json:"risk_score"`
	RiskFactors    []string `json:"risk_factors"`
	Recommendation string   `json:"recommendation"`
}

// ScanResult contains plugin scan result
type ScanResult struct {
	Slug                 string          `json:"slug"`
	Name                 string          `json:"name"`
	Installed            bool            `json:"installed"`
	CurrentVersion       string          `json:"current_version,omitempty"`
	LatestVersion        string          `json:"latest_version,omitempty"`
	NeedsUpdate          bool            `json:"needs_update,omitempty"`
	Path                 string          `json:"path,omitempty"`
	Confidence           int             `json:"confidence"`           // Confidence level 0-100%
	ConfidenceReason     string          `json:"confidence_reason"`    // Why this confidence level
	KnownVulnerabilities []Vulnerability `json:"known_vulnerabilities,omitempty"`
	RiskAnalysis         *RiskAnalysis   `json:"risk_analysis,omitempty"`
}

// Scanner handles WordPress plugin scanning
type Scanner struct {
	targetURL        string
	wordlistFile     string
	customPluginFile string
	outputFile       string
	threads          int
	timeout          time.Duration
	delay            time.Duration
	stealthy         bool
	fastMode         bool
	proxyURL         string
	client           *http.Client
	plugins          []Plugin
	pluginsData      map[string]Plugin
	vulnDB           map[string][]Vulnerability
	results          []ScanResult
	vulnerable       []ScanResult
	mu               sync.Mutex
	// WAF detection
	wafMu       sync.Mutex
	wafDetected bool
	wafReason   string
	stopScan    bool
}

// firstN returns first N chars of string
func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// IsWAFDetected returns whether a WAF was detected
func (s *Scanner) IsWAFDetected() bool {
	s.wafMu.Lock()
	defer s.wafMu.Unlock()
	return s.wafDetected
}

// SetWAFDetected marks WAF as detected
func (s *Scanner) SetWAFDetected(reason string) {
	s.wafMu.Lock()
	defer s.wafMu.Unlock()
	if !s.wafDetected {
		s.wafDetected = true
		s.wafReason = reason
		s.stopScan = true
	}
}

// ShouldStop returns whether scan should stop
func (s *Scanner) ShouldStop() bool {
	s.wafMu.Lock()
	defer s.wafMu.Unlock()
	return s.stopScan
}

// ===================== PLUGIN COLLECTOR =====================

// CollectPlugins collects plugins from WordPress.org API
func CollectPlugins(outputFile string, minInstalls int, fullMode bool) error {
	fmt.Println("\n[*] ========== PLUGIN COLLECTOR ==========")
	
	client := &http.Client{Timeout: 30 * time.Second}
	apiURL := "https://api.wordpress.org/plugins/info/1.2/"
	
	var plugins []Plugin
	
	if fullMode {
		fmt.Println("[*] Mode: Thu thập TOÀN BỘ plugins (sẽ mất nhiều thời gian)")
		plugins = collectAllPlugins(client, apiURL)
	} else {
		fmt.Printf("[*] Mode: Thu thập plugins phổ biến (>= %d active installs)\n", minInstalls)
		plugins = collectPopularPlugins(client, apiURL, minInstalls)
	}
	
	if len(plugins) == 0 {
		return fmt.Errorf("không thu thập được plugins nào")
	}
	
	// Sort by active installs
	sort.Slice(plugins, func(i, j int) bool {
		return plugins[i].ActiveInstalls > plugins[j].ActiveInstalls
	})
	
	// Save to file
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("không thể tạo file: %v", err)
	}
	defer file.Close()
	
	for _, p := range plugins {
		line := fmt.Sprintf("%s|%s|%s|%d\n", p.Slug, p.Name, p.Version, p.ActiveInstalls)
		file.WriteString(line)
	}
	
	fmt.Printf("[+] Đã lưu %d plugins vào %s\n", len(plugins), outputFile)
	
	// Also save JSON
	jsonFile, err := os.Create("plugins.json")
	if err == nil {
		encoder := json.NewEncoder(jsonFile)
		encoder.SetIndent("", "  ")
		encoder.SetEscapeHTML(false)
		encoder.Encode(plugins)
		jsonFile.Close()
		fmt.Println("[+] Đã lưu chi tiết vào plugins.json")
	}
	
	return nil
}

func collectPopularPlugins(client *http.Client, apiURL string, minInstalls int) []Plugin {
	var plugins []Plugin
	page := 1
	
	for {
		params := url.Values{}
		params.Set("action", "query_plugins")
		params.Set("request[browse]", "popular")
		params.Set("request[page]", strconv.Itoa(page))
		params.Set("request[per_page]", "250")
		params.Set("request[fields][slug]", "1")
		params.Set("request[fields][name]", "1")
		params.Set("request[fields][version]", "1")
		params.Set("request[fields][active_installs]", "1")
		
		reqURL := apiURL + "?" + params.Encode()
		resp, err := client.Get(reqURL)
		if err != nil {
			fmt.Printf("\n[!] Request error: %v\n", err)
			break
		}
		
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		var response PluginAPIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			break
		}
		
		if len(response.Plugins) == 0 {
			break
		}
		
		foundLow := false
		for _, p := range response.Plugins {
			if p.ActiveInstalls >= minInstalls {
				plugins = append(plugins, Plugin{
					Slug:           p.Slug,
					Name:           p.Name,
					Version:        p.Version,
					LatestVersion:  p.Version,
					ActiveInstalls: p.ActiveInstalls,
				})
			} else {
				foundLow = true
				break
			}
		}
		
		fmt.Printf("\r[*] Page %d - Đã thu thập %d plugins...", page, len(plugins))
		
		if foundLow {
			break
		}
		
		page++
		time.Sleep(300 * time.Millisecond)
	}
	
	fmt.Printf("\n[+] Tổng cộng: %d plugins\n", len(plugins))
	return plugins
}

func collectAllPlugins(client *http.Client, apiURL string) []Plugin {
	var plugins []Plugin
	
	// Get first page to know total
	params := url.Values{}
	params.Set("action", "query_plugins")
	params.Set("request[page]", "1")
	params.Set("request[per_page]", "250")
	params.Set("request[fields][slug]", "1")
	params.Set("request[fields][name]", "1")
	params.Set("request[fields][version]", "1")
	params.Set("request[fields][active_installs]", "1")
	
	reqURL := apiURL + "?" + params.Encode()
	resp, err := client.Get(reqURL)
	if err != nil {
		fmt.Printf("[!] Error: %v\n", err)
		return plugins
	}
	
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	
	var firstPage PluginAPIResponse
	if err := json.Unmarshal(body, &firstPage); err != nil {
		return plugins
	}
	
	totalPages := firstPage.Info.Pages
	fmt.Printf("[*] Tổng số pages: %d\n", totalPages)
	
	// Add first page
	for _, p := range firstPage.Plugins {
		plugins = append(plugins, Plugin{
			Slug:           p.Slug,
			Name:           p.Name,
			Version:        p.Version,
			LatestVersion:  p.Version,
			ActiveInstalls: p.ActiveInstalls,
		})
	}
	
	// Collect remaining pages
	for page := 2; page <= totalPages; page++ {
		params.Set("request[page]", strconv.Itoa(page))
		reqURL := apiURL + "?" + params.Encode()
		
		resp, err := client.Get(reqURL)
		if err != nil {
			continue
		}
		
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		var response PluginAPIResponse
		if err := json.Unmarshal(body, &response); err != nil {
			continue
		}
		
		for _, p := range response.Plugins {
			plugins = append(plugins, Plugin{
				Slug:           p.Slug,
				Name:           p.Name,
				Version:        p.Version,
				LatestVersion:  p.Version,
				ActiveInstalls: p.ActiveInstalls,
			})
		}
		
		fmt.Printf("\r[*] Page %d/%d - %d plugins...", page, totalPages, len(plugins))
		time.Sleep(500 * time.Millisecond)
	}
	
	fmt.Printf("\n[+] Tổng cộng: %d plugins\n", len(plugins))
	return plugins
}

// ===================== VULNERABILITY DATABASE =====================

func loadVulnDatabase() map[string][]Vulnerability {
	return map[string][]Vulnerability{
		"elementor": {
			{VersionAffected: "<3.18.0", Severity: "high", CVE: "CVE-2024-XXXXX", Description: "Authenticated RCE"},
		},
		"contact-form-7": {
			{VersionAffected: "<5.8.4", Severity: "medium", CVE: "CVE-2023-XXXXX", Description: "File Upload Bypass"},
		},
		"woocommerce": {
			{VersionAffected: "<8.0.0", Severity: "high", CVE: "CVE-2023-XXXXX", Description: "SQL Injection"},
		},
		"wp-file-manager": {
			{VersionAffected: "<6.9", Severity: "critical", CVE: "CVE-2020-25213", Description: "Unauthenticated RCE"},
		},
		"duplicator": {
			{VersionAffected: "<1.5.7", Severity: "critical", CVE: "CVE-2023-XXXXX", Description: "Unauthenticated Information Disclosure"},
		},
		"all-in-one-seo-pack": {
			{VersionAffected: "<4.2.9", Severity: "high", CVE: "CVE-2023-XXXXX", Description: "SQL Injection"},
		},
		"wpforms-lite": {
			{VersionAffected: "<1.8.4", Severity: "medium", CVE: "CVE-2023-XXXXX", Description: "XSS Vulnerability"},
		},
		"really-simple-ssl": {
			{VersionAffected: "<7.2.0", Severity: "critical", CVE: "CVE-2023-XXXXX", Description: "Authentication Bypass"},
		},
		"wordpress-seo": {
			{VersionAffected: "<21.0", Severity: "medium", CVE: "CVE-2023-XXXXX", Description: "XSS in Schema"},
		},
		"updraftplus": {
			{VersionAffected: "<1.23.8", Severity: "high", CVE: "CVE-2023-XXXXX", Description: "Privilege Escalation"},
		},
		"jetpack": {
			{VersionAffected: "<12.0", Severity: "high", CVE: "CVE-2023-XXXXX", Description: "Privilege Escalation"},
		},
		"wordfence": {
			{VersionAffected: "<7.10.0", Severity: "medium", CVE: "CVE-2023-XXXXX", Description: "Information Disclosure"},
		},
		"revslider": {
			{VersionAffected: "<6.6.0", Severity: "critical", CVE: "CVE-2021-XXXXX", Description: "Unauthenticated File Read"},
		},
		"all-in-one-wp-migration": {
			{VersionAffected: "<7.60", Severity: "high", CVE: "CVE-2023-XXXXX", Description: "Arbitrary File Download"},
		},
		"backupbuddy": {
			{VersionAffected: "<8.7.5", Severity: "critical", CVE: "CVE-2022-XXXXX", Description: "Directory Traversal"},
		},
	}
}

// ===================== SCANNER =====================

func NewScanner(target, wordlist, customFile, outputFile string, threads int, timeout int, delay int, stealthy bool, fastMode bool, proxyURL string) *Scanner {
	// Seed random once
	rand.Seed(time.Now().UnixNano())
	
	// Enhanced transport with connection pooling
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 200,
		MaxConnsPerHost:     200,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
	}

	// Configure proxy if specified
	if proxyURL != "" {
		parsedProxy, err := url.Parse(proxyURL)
		if err != nil {
			fmt.Printf("[!] Invalid proxy URL: %v\n", err)
			os.Exit(1)
		}

		switch parsedProxy.Scheme {
		case "http", "https":
			// HTTP/HTTPS proxy
			tr.Proxy = http.ProxyURL(parsedProxy)
			fmt.Printf("[*] Using HTTP/HTTPS proxy: %s\n", proxyURL)
		case "socks5", "socks5h":
			// SOCKS5 proxy
			auth := &proxy.Auth{}
			if parsedProxy.User != nil {
				auth.User = parsedProxy.User.Username()
				auth.Password, _ = parsedProxy.User.Password()
			} else {
				auth = nil
			}
			dialer, err := proxy.SOCKS5("tcp", parsedProxy.Host, auth, proxy.Direct)
			if err != nil {
				fmt.Printf("[!] Failed to create SOCKS5 proxy: %v\n", err)
				os.Exit(1)
			}
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
			fmt.Printf("[*] Using SOCKS5 proxy: %s\n", proxyURL)
		case "socks4", "socks4a":
			// SOCKS4 proxy - use SOCKS5 dialer (compatible)
			dialer, err := proxy.SOCKS5("tcp", parsedProxy.Host, nil, proxy.Direct)
			if err != nil {
				fmt.Printf("[!] Failed to create SOCKS4 proxy: %v\n", err)
				os.Exit(1)
			}
			tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.Dial(network, addr)
			}
			fmt.Printf("[*] Using SOCKS4 proxy: %s\n", proxyURL)
		default:
			fmt.Printf("[!] Unsupported proxy scheme: %s (supported: http, https, socks4, socks5)\n", parsedProxy.Scheme)
			os.Exit(1)
		}
	}

	return &Scanner{
		targetURL:        strings.TrimRight(target, "/"),
		wordlistFile:     wordlist,
		customPluginFile: customFile,
		outputFile:       outputFile,
		stealthy:         stealthy,
		fastMode:         fastMode,
		proxyURL:         proxyURL,
		threads:          threads,
		timeout:          time.Duration(timeout) * time.Second,
		delay:            time.Duration(delay) * time.Millisecond,
		client: &http.Client{
			Timeout:   time.Duration(timeout) * time.Second,
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		pluginsData: make(map[string]Plugin),
		vulnDB:      loadVulnDatabase(),
		results:     make([]ScanResult, 0),
		vulnerable:  make([]ScanResult, 0),
	}
}

func (s *Scanner) LoadPluginsList() error {
	s.plugins = make([]Plugin, 0)

	// Load from wordlist file
	if err := s.loadPluginsFromFile(s.wordlistFile); err != nil {
		return err
	}

	// Load custom plugins if specified
	if s.customPluginFile != "" {
		if err := s.loadCustomPlugins(s.customPluginFile); err != nil {
			fmt.Printf("[!] Warning: Cannot load custom plugins: %v\n", err)
		}
	}

	return nil
}

func (s *Scanner) loadPluginsFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("file %s không tồn tại", filename)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "|")
		if len(parts) < 1 {
			continue
		}

		slug := strings.TrimSpace(parts[0])
		name := slug
		version := ""
		activeInstalls := 0

		// Parse format: slug|name|version|active_installs
		// Handle case where name might contain |
		if len(parts) >= 4 {
			// Try to parse last part as number
			lastPart := strings.TrimSpace(parts[len(parts)-1])
			if val, err := strconv.Atoi(lastPart); err == nil {
				activeInstalls = val
				version = strings.TrimSpace(parts[len(parts)-2])
				name = strings.Join(parts[1:len(parts)-2], "|")
			} else {
				name = parts[1]
				if len(parts) > 2 {
					version = parts[2]
				}
			}
		} else if len(parts) == 3 {
			name = parts[1]
			version = parts[2]
		} else if len(parts) == 2 {
			name = parts[1]
		}

		plugin := Plugin{
			Slug:           slug,
			Name:           name,
			LatestVersion:  version,
			ActiveInstalls: activeInstalls,
		}
		
		// Normalize invalid version strings to empty
		invalidVersions := []string{"null", "unknown", "0", "N/A", "n/a", "", "none"}
		for _, inv := range invalidVersions {
			if strings.EqualFold(plugin.LatestVersion, inv) {
				plugin.LatestVersion = ""
				break
			}
		}
		
		s.plugins = append(s.plugins, plugin)
		s.pluginsData[slug] = plugin
	}

	return scanner.Err()
}

func (s *Scanner) loadCustomPlugins(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, "|")
		slug := strings.TrimSpace(parts[0])

		// Check if exists
		exists := false
		for _, p := range s.plugins {
			if p.Slug == slug {
				exists = true
				break
			}
		}

		if !exists {
			name := slug
			version := ""
			activeInstalls := 0

			// Parse format: slug|name|version|active_installs
			// Handle case where name might contain |
			if len(parts) >= 4 {
				// Try to parse last part as number
				lastPart := strings.TrimSpace(parts[len(parts)-1])
				if val, err := strconv.Atoi(lastPart); err == nil {
					activeInstalls = val
					version = strings.TrimSpace(parts[len(parts)-2])
					name = strings.Join(parts[1:len(parts)-2], "|")
				} else {
					name = parts[1]
					if len(parts) > 2 {
						version = parts[2]
					}
				}
			} else if len(parts) == 3 {
				name = parts[1]
				version = parts[2]
			} else if len(parts) == 2 {
				name = parts[1]
			}

			plugin := Plugin{Slug: slug, Name: name, LatestVersion: version, ActiveInstalls: activeInstalls}
			
			// Normalize invalid version strings to empty
			invalidVersions := []string{"null", "unknown", "0", "N/A", "n/a", "", "none"}
			for _, inv := range invalidVersions {
				if strings.EqualFold(plugin.LatestVersion, inv) {
					plugin.LatestVersion = ""
					break
				}
			}
			
			s.plugins = append(s.plugins, plugin)
			s.pluginsData[slug] = plugin
			count++
		}
	}

	fmt.Printf("[+] Loaded %d custom plugins từ %s\n", count, filename)
	return scanner.Err()
}

func (s *Scanner) CheckPluginExists(slug string) *ScanResult {
	// Parse target host for referer generation
	parsedURL, _ := url.Parse(s.targetURL)
	targetHost := ""
	if parsedURL != nil {
		targetHost = parsedURL.Host
	}

	// Define paths with confidence levels - OPTIMIZED ORDER (fastest detection first)
	type pathCheck struct {
		path       string
		confidence int
		reason     string
		isDir      bool
	}

	var checkPaths []pathCheck
	
	if s.fastMode {
		// FAST MODE: Only check directory (1 request per plugin = 7x faster)
		checkPaths = []pathCheck{
			{fmt.Sprintf("/wp-content/plugins/%s/", slug), 60, "plugin directory accessible (fast mode)", true},
		}
	} else {
		// FULL MODE: Check all paths for maximum accuracy
		checkPaths = []pathCheck{
			// Plugin directory first - fastest check (often returns 200 or 403)
			{fmt.Sprintf("/wp-content/plugins/%s/", slug), 60, "plugin directory accessible", true},
			// Readme files - highest confidence (100%) - most reliable
			{fmt.Sprintf("/wp-content/plugins/%s/readme.txt", slug), 100, "readme.txt found", false},
			// Main plugin file - high confidence (95%)
			{fmt.Sprintf("/wp-content/plugins/%s/%s.php", slug, slug), 95, "main plugin PHP file found", false},
			// README variants
			{fmt.Sprintf("/wp-content/plugins/%s/README.txt", slug), 100, "README.txt found", false},
			{fmt.Sprintf("/wp-content/plugins/%s/readme.md", slug), 95, "readme.md found", false},
			// Changelog - high confidence
			{fmt.Sprintf("/wp-content/plugins/%s/changelog.txt", slug), 90, "changelog.txt found", false},
			// Index file
			{fmt.Sprintf("/wp-content/plugins/%s/index.php", slug), 70, "index.php found", false},
		}
	}

	var bestResult *ScanResult

	for _, check := range checkPaths {
		// Add cache busting in stealthy mode to bypass CDN caching
		reqURL := s.targetURL + check.path
		if s.stealthy {
			reqURL += getCacheBuster()
		}
		
		req, err := http.NewRequest("GET", reqURL, nil)
		if err != nil {
			continue
		}

		// Set random user-agent
		req.Header.Set("User-Agent", getRandomUserAgent())
		
		// Add WAF bypass headers if stealthy mode is enabled
		wafHeaders := getWAFBypassHeaders(s.stealthy, targetHost)
		for key, value := range wafHeaders {
			req.Header.Set(key, value)
		}
		
		// Add Host header explicitly
		req.Host = targetHost

		// Add jitter delay in stealthy mode
		if s.stealthy && s.delay > 0 {
			time.Sleep(getJitter(s.delay))
		}

		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}

		// Check if scan should stop (WAF detected by another goroutine)
		if s.ShouldStop() {
			resp.Body.Close()
			return &ScanResult{Installed: false, Confidence: 0, ConfidenceReason: "scan stopped - WAF detected"}
		}

		// WAF/Challenge detection - check for common WAF patterns
		if resp.StatusCode == 429 || resp.StatusCode == 503 || resp.StatusCode == 403 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			content := strings.ToLower(string(body))
			
			// Check for WAF/Challenge signatures
			wafSignatures := []string{
				"attention required", "checking your browser", "cf-chl-bypass",
				"browser integrity check", "captcha", "challenge-platform",
				"please wait while we verify", "ddos protection", "security check",
				"access denied", "blocked by", "cloudflare ray id",
				"sucuri", "wordfence", "imunify360", "modsecurity",
			}
			
			for _, sig := range wafSignatures {
				if strings.Contains(content, sig) {
					reason := fmt.Sprintf("WAF detected: status=%d, signature='%s', snippet='%s'", 
						resp.StatusCode, sig, firstN(content, 100))
					s.SetWAFDetected(reason)
					return &ScanResult{Installed: false, Confidence: 0, ConfidenceReason: "WAF/Challenge detected"}
				}
			}
			
			// 403 for directory might still be a detection (plugin exists but blocked)
			if resp.StatusCode == 403 && check.isDir {
				if bestResult == nil || 55 > bestResult.Confidence {
					bestResult = &ScanResult{
						Installed:        true,
						Path:             check.path,
						CurrentVersion:   "",
						Confidence:       55,
						ConfidenceReason: "plugin directory exists (403 forbidden)",
					}
				}
			}
			continue
		}

		// Handle 403 for directory - plugin exists but access denied (common with Cloudflare)
		if resp.StatusCode == 403 && check.isDir {
			resp.Body.Close()
			// Plugin directory exists but access is forbidden - still a detection
			if bestResult == nil || 55 > bestResult.Confidence {
				bestResult = &ScanResult{
					Installed:        true,
					Path:             check.path,
					CurrentVersion:   "",
					Confidence:       55,
					ConfidenceReason: "plugin directory exists (403 forbidden)",
				}
			}
			continue
		}

		if resp.StatusCode == 200 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			content := string(body)

			// For directory listing, verify it looks like a plugin directory
			if check.isDir {
				// Check if response contains typical plugin files/folders or is a valid response
				// Accept: plugin files, readme, empty/small content (index.php), or slug name
				isPluginDir := strings.Contains(content, ".php") || strings.Contains(content, "readme") ||
					strings.Contains(content, "Index of") || strings.Contains(content, slug) ||
					len(content) == 0 || len(content) < 500 // Empty or small = likely index.php redirect
				
				if isPluginDir {
					confidence := check.confidence
					reason := check.reason
					
					// Boost if we see actual plugin files
					if strings.Contains(content, ".php") || strings.Contains(content, "readme") {
						confidence = min(confidence+15, 85)
						reason += " + plugin files visible"
					} else if len(content) == 0 {
						reason += " + empty response (index.php)"
					}
					
					if bestResult == nil || confidence > bestResult.Confidence {
						bestResult = &ScanResult{
							Installed:        true,
							Path:             check.path,
							CurrentVersion:   "",
							Confidence:       confidence,
							ConfidenceReason: reason,
						}
					}
				}
				continue
			}

			version := extractVersion(content)

			// Boost confidence if version found
			confidence := check.confidence
			reason := check.reason
			if version != "" {
				if confidence < 100 {
					confidence = min(confidence+10, 100)
				}
				reason += " + version detected"
			}

			// Return immediately if we found readme (100% confidence)
			if check.confidence == 100 {
				return &ScanResult{
					Installed:        true,
					Path:             check.path,
					CurrentVersion:   version,
					Confidence:       confidence,
					ConfidenceReason: reason,
				}
			}

			// Keep track of best result
			if bestResult == nil || confidence > bestResult.Confidence {
				bestResult = &ScanResult{
					Installed:        true,
					Path:             check.path,
					CurrentVersion:   version,
					Confidence:       confidence,
					ConfidenceReason: reason,
				}
			}
		} else {
			resp.Body.Close()
		}
	}

	if bestResult != nil {
		return bestResult
	}

	return &ScanResult{Installed: false, Confidence: 0}
}

func extractVersion(content string) string {
	patterns := []string{
		`Stable tag:\s*([0-9]+\.[0-9]+\.?[0-9]*\.?[0-9]*)`,
		`Version:\s*([0-9]+\.[0-9]+\.?[0-9]*\.?[0-9]*)`,
		`\*\s*Version:\s*([0-9]+\.[0-9]+\.?[0-9]*\.?[0-9]*)`,
		`version\s*=\s*["']([0-9]+\.[0-9]+\.?[0-9]*\.?[0-9]*)["']`,
		`define\s*\(\s*['"][A-Z_]*VERSION['"]\s*,\s*['"]([0-9]+\.[0-9]+\.?[0-9]*\.?[0-9]*)['"]`,
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile("(?i)" + pattern)
		matches := re.FindStringSubmatch(content)
		if len(matches) > 1 {
			return matches[1]
		}
	}

	return ""
}

func compareVersions(v1, v2 string) bool {
	if v1 == "" || v2 == "" {
		return false
	}

	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var n1, n2 int
		if i < len(parts1) {
			n1, _ = strconv.Atoi(parts1[i])
		}
		if i < len(parts2) {
			n2, _ = strconv.Atoi(parts2[i])
		}

		if n1 < n2 {
			return true
		} else if n1 > n2 {
			return false
		}
	}

	return false
}

func (s *Scanner) checkVulnerabilities(slug, version string) []Vulnerability {
	var vulns []Vulnerability

	if dbVulns, ok := s.vulnDB[slug]; ok {
		for _, vuln := range dbVulns {
			affected := vuln.VersionAffected
			if strings.HasPrefix(affected, "<=") {
				vulnVersion := strings.TrimPrefix(affected, "<=")
				if version != "" && (compareVersions(version, vulnVersion) || version == vulnVersion) {
					vulns = append(vulns, vuln)
				}
			} else if strings.HasPrefix(affected, "<") {
				vulnVersion := strings.TrimPrefix(affected, "<")
				if version != "" && compareVersions(version, vulnVersion) {
					vulns = append(vulns, vuln)
				}
			}
		}
	}

	return vulns
}

func (s *Scanner) analyzeRisk(slug, currentVersion, latestVersion string) *RiskAnalysis {
	riskScore := 0
	var riskFactors []string

	// Factor 1: Version outdated
	if currentVersion != "" && latestVersion != "" && compareVersions(currentVersion, latestVersion) {
		currParts := strings.Split(currentVersion, ".")
		lateParts := strings.Split(latestVersion, ".")

		if len(currParts) > 0 && len(lateParts) > 0 {
			currMajor, _ := strconv.Atoi(currParts[0])
			lateMajor, _ := strconv.Atoi(lateParts[0])

			if currMajor < lateMajor {
				riskScore += 40
				riskFactors = append(riskFactors, fmt.Sprintf("Major version outdated (%s vs %s)", currentVersion, latestVersion))
			} else if len(currParts) > 1 && len(lateParts) > 1 {
				currMinor, _ := strconv.Atoi(currParts[1])
				lateMinor, _ := strconv.Atoi(lateParts[1])
				if currMinor < lateMinor-3 {
					riskScore += 25
					riskFactors = append(riskFactors, "Multiple minor versions behind")
				} else if currMinor < lateMinor {
					riskScore += 10
					riskFactors = append(riskFactors, "Minor version outdated")
				}
			}
		}
	}

	// Factor 2: Popular plugin
	if plugin, ok := s.pluginsData[slug]; ok {
		if plugin.ActiveInstalls >= 1000000 {
			riskScore += 15
			riskFactors = append(riskFactors, fmt.Sprintf("High-value target (%d+ installs)", plugin.ActiveInstalls))
		} else if plugin.ActiveInstalls >= 100000 {
			riskScore += 10
			riskFactors = append(riskFactors, fmt.Sprintf("Popular plugin (%d+ installs)", plugin.ActiveInstalls))
		}
	}

	// Factor 3: High-risk categories
	highRiskKeywords := []string{"file-manager", "backup", "security", "admin", "editor", "upload", "import", "export", "migration"}
	slugLower := strings.ToLower(slug)
	for _, keyword := range highRiskKeywords {
		if strings.Contains(slugLower, keyword) {
			riskScore += 15
			riskFactors = append(riskFactors, fmt.Sprintf("High-risk category: %s", keyword))
			break
		}
	}

	if riskScore > 100 {
		riskScore = 100
	}

	return &RiskAnalysis{
		RiskScore:      riskScore,
		RiskFactors:    riskFactors,
		Recommendation: getRecommendation(riskScore),
	}
}

func getRecommendation(score int) string {
	switch {
	case score >= 70:
		return "CRITICAL - Investigate immediately for known CVEs"
	case score >= 50:
		return "HIGH - Research for recent vulnerabilities"
	case score >= 30:
		return "MEDIUM - Check for security advisories"
	case score >= 10:
		return "LOW - Standard security check"
	default:
		return "INFO - Up to date"
	}
}

func (s *Scanner) ScanPlugin(plugin Plugin) *ScanResult {
	result := s.CheckPluginExists(plugin.Slug)

	if result.Installed {
		result.Slug = plugin.Slug
		result.Name = plugin.Name
		result.LatestVersion = plugin.LatestVersion
		result.NeedsUpdate = compareVersions(result.CurrentVersion, plugin.LatestVersion)
		result.KnownVulnerabilities = s.checkVulnerabilities(plugin.Slug, result.CurrentVersion)
		result.RiskAnalysis = s.analyzeRisk(plugin.Slug, result.CurrentVersion, plugin.LatestVersion)
	}

	return result
}

func (s *Scanner) RunScan() {
	fmt.Printf("\n%s\n", strings.Repeat("=", 70))
	fmt.Println("  WordPress Plugin Vulnerability Scanner v1.0.1")
	fmt.Printf("  Target: %s\n", s.targetURL)
	fmt.Printf("  Threads: %d | Timeout: %v | Delay: %v\n", s.threads, s.timeout, s.delay)
	if s.proxyURL != "" {
		fmt.Printf("  Proxy: %s\n", s.proxyURL)
	}
	
	// Display mode info
	modeInfo := []string{}
	if s.stealthy {
		modeInfo = append(modeInfo, "🕵️ STEALTHY")
	}
	if s.fastMode {
		modeInfo = append(modeInfo, "⚡ FAST")
	}
	if s.proxyURL != "" {
		modeInfo = append(modeInfo, "🔒 PROXY")
	}
	if len(modeInfo) > 0 {
		fmt.Printf("  Mode: %s\n", strings.Join(modeInfo, " + "))
	}
	fmt.Printf("%s\n\n", strings.Repeat("=", 70))

	if err := s.LoadPluginsList(); err != nil {
		fmt.Printf("[!] Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[*] Loaded %d plugins từ %s\n", len(s.plugins), s.wordlistFile)
	fmt.Printf("[*] Bắt đầu scan với %d goroutines...\n\n", s.threads)

	jobs := make(chan Plugin, len(s.plugins))
	results := make(chan *ScanResult, len(s.plugins))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < s.threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for plugin := range jobs {
				// Check if WAF detected - skip remaining work
				if s.ShouldStop() {
					results <- &ScanResult{Installed: false, Confidence: 0}
					continue
				}
				
				result := s.ScanPlugin(plugin)
				if result.Installed {
					result.Slug = plugin.Slug
					result.Name = plugin.Name
				}
				results <- result
				
				// Apply delay between requests (for slow mode)
				if s.delay > 0 {
					time.Sleep(s.delay)
				}
			}
		}()
	}

	// Send jobs
	go func() {
		for _, plugin := range s.plugins {
			jobs <- plugin
		}
		close(jobs)
	}()

	// Wait and close
	go func() {
		wg.Wait()
		close(results)
	}()

	// Process results
	foundCount := 0
	vulnCount := 0
	processed := 0

	for result := range results {
		processed++

		if result.Installed {
			foundCount++
			s.mu.Lock()
			s.results = append(s.results, *result)

			if len(result.KnownVulnerabilities) > 0 {
				vulnCount++
				s.vulnerable = append(s.vulnerable, *result)
			}
			s.mu.Unlock()

			// Print found with confidence indicator
			confidenceIcon := "🔴" // Low
			if result.Confidence >= 90 {
				confidenceIcon = "🟢" // High
			} else if result.Confidence >= 70 {
				confidenceIcon = "🟡" // Medium
			} else if result.Confidence >= 50 {
				confidenceIcon = "🟠" // Low-Medium
			}

			fmt.Printf("\n[+] FOUND: %s (%s) %s %d%%\n", result.Name, result.Slug, confidenceIcon, result.Confidence)
			fmt.Printf("    Path: %s\n", result.Path)
			fmt.Printf("    Confidence: %d%% - %s\n", result.Confidence, result.ConfidenceReason)

			if result.CurrentVersion != "" {
				fmt.Printf("    Current Version: %s\n", result.CurrentVersion)
			} else {
				fmt.Println("    Current Version: Unknown")
			}

			if result.LatestVersion != "" {
				fmt.Printf("    Latest Version: %s\n", result.LatestVersion)
				if result.NeedsUpdate {
					fmt.Println("    [!] UPDATE AVAILABLE")
				}
			}

			if len(result.KnownVulnerabilities) > 0 {
				fmt.Println("    [!!!] KNOWN VULNERABILITIES:")
				for _, vuln := range result.KnownVulnerabilities {
					fmt.Printf("        - %s: %s\n", strings.ToUpper(vuln.Severity), vuln.Description)
					if vuln.CVE != "" {
						fmt.Printf("          CVE: %s\n", vuln.CVE)
					}
				}
			}

			if result.RiskAnalysis != nil && result.RiskAnalysis.RiskScore > 0 {
				fmt.Printf("    Risk Score: %d/100\n", result.RiskAnalysis.RiskScore)
				fmt.Printf("    Recommendation: %s\n", result.RiskAnalysis.Recommendation)
				for _, factor := range result.RiskAnalysis.RiskFactors {
					fmt.Printf("        - %s\n", factor)
				}
			}
		}

		fmt.Printf("\r[*] Progress: %d/%d plugins checked, %d found...", processed, len(s.plugins), foundCount)
	}

	fmt.Printf("\n\n%s\n", strings.Repeat("=", 70))
	
	// Check if WAF was detected
	if s.IsWAFDetected() {
		fmt.Println("  ⚠️  SCAN STOPPED - WAF DETECTED")
		fmt.Printf("%s\n", strings.Repeat("=", 70))
		fmt.Printf("\n[!!!] WAF/Security Challenge detected!\n")
		s.wafMu.Lock()
		fmt.Printf("[!!!] Reason: %s\n", s.wafReason)
		s.wafMu.Unlock()
		fmt.Println("\n[*] Recommendations:")
		fmt.Println("    - Use stealthy mode: -s")
		fmt.Println("    - Reduce threads: -t 1 or -t 2")
		fmt.Println("    - Add delay: -delay 1000 or higher")
		fmt.Println("    - Try from different IP/VPN")
		fmt.Println("    - Wait before retrying")
	} else {
		fmt.Println("  SCAN COMPLETED")
	}
	
	fmt.Printf("%s\n", strings.Repeat("=", 70))
	fmt.Printf("\n[*] Plugins checked: %d\n", processed)
	fmt.Printf("[+] Plugins found: %d\n", foundCount)
	fmt.Printf("[!] Vulnerable plugins: %d\n", vulnCount)

	s.SaveResults()
}

func (s *Scanner) SaveResults() {
	// Sort by risk score
	sort.Slice(s.results, func(i, j int) bool {
		scoreI := 0
		scoreJ := 0
		if s.results[i].RiskAnalysis != nil {
			scoreI = s.results[i].RiskAnalysis.RiskScore
		}
		if s.results[j].RiskAnalysis != nil {
			scoreJ = s.results[j].RiskAnalysis.RiskScore
		}
		return scoreI > scoreJ
	})

	// Only save files if output file is specified
	if s.outputFile == "" {
		return
	}

	// Determine output filenames
	var jsonFilename, reportFilename string
	// Remove extension if present and create filenames
	baseName := s.outputFile
	if strings.HasSuffix(baseName, ".json") {
		baseName = strings.TrimSuffix(baseName, ".json")
	} else if strings.HasSuffix(baseName, ".txt") {
		baseName = strings.TrimSuffix(baseName, ".txt")
	}
	jsonFilename = baseName + ".json"
	reportFilename = baseName + ".txt"

	// Save JSON
	output := map[string]interface{}{
		"target":             s.targetURL,
		"scan_time":          time.Now().Format("2006-01-02 15:04:05"),
		"total_found":        len(s.results),
		"vulnerable_count":   len(s.vulnerable),
		"installed_plugins":  s.results,
		"vulnerable_plugins": s.vulnerable,
	}

	jsonFile, err := os.Create(jsonFilename)
	if err == nil {
		encoder := json.NewEncoder(jsonFile)
		encoder.SetIndent("", "  ")
		encoder.Encode(output)
		jsonFile.Close()
		fmt.Printf("\n[+] Results saved to %s\n", jsonFilename)
	}

	// Save text report
	reportFile, err := os.Create(reportFilename)
	if err == nil {
		defer reportFile.Close()

		fmt.Fprintf(reportFile, "WordPress Plugin Vulnerability Scan Report\n")
		fmt.Fprintf(reportFile, "%s\n", strings.Repeat("=", 60))
		fmt.Fprintf(reportFile, "Target: %s\n", s.targetURL)
		fmt.Fprintf(reportFile, "Scan Time: %s\n", time.Now().Format("2006-01-02 15:04:05"))
		fmt.Fprintf(reportFile, "Plugins Found: %d\n", len(s.results))
		fmt.Fprintf(reportFile, "Vulnerable: %d\n\n", len(s.vulnerable))

		if len(s.vulnerable) > 0 {
			fmt.Fprintf(reportFile, "\n%s\n", strings.Repeat("=", 60))
			fmt.Fprintf(reportFile, "VULNERABLE PLUGINS - PRIORITY TARGETS\n")
			fmt.Fprintf(reportFile, "%s\n\n", strings.Repeat("=", 60))

			for _, plugin := range s.vulnerable {
				fmt.Fprintf(reportFile, "Plugin: %s (%s)\n", plugin.Name, plugin.Slug)
				fmt.Fprintf(reportFile, "Version: %s\n", plugin.CurrentVersion)
				for _, vuln := range plugin.KnownVulnerabilities {
					fmt.Fprintf(reportFile, "  - [%s] %s\n", strings.ToUpper(vuln.Severity), vuln.Description)
					if vuln.CVE != "" {
						fmt.Fprintf(reportFile, "    CVE: %s\n", vuln.CVE)
					}
				}
				fmt.Fprintf(reportFile, "\n")
			}
		}

		fmt.Fprintf(reportFile, "\n%s\n", strings.Repeat("=", 60))
		fmt.Fprintf(reportFile, "ALL INSTALLED PLUGINS (sorted by risk)\n")
		fmt.Fprintf(reportFile, "%s\n\n", strings.Repeat("=", 60))

		for _, plugin := range s.results {
			score := 0
			if plugin.RiskAnalysis != nil {
				score = plugin.RiskAnalysis.RiskScore
			}
			fmt.Fprintf(reportFile, "[Risk:%3d][Conf:%3d%%] %s", score, plugin.Confidence, plugin.Slug)
			if plugin.CurrentVersion != "" {
				fmt.Fprintf(reportFile, " v%s", plugin.CurrentVersion)
			}
			if plugin.NeedsUpdate {
				fmt.Fprintf(reportFile, " -> v%s [UPDATE]", plugin.LatestVersion)
			}
			fmt.Fprintf(reportFile, " (%s)\n", plugin.ConfidenceReason)
		}

		fmt.Printf("[+] Report saved to %s\n", reportFilename)
	}
}

// ===================== MAIN =====================

func main() {
	// Define flags
	targetURL := flag.String("u", "", "Target WordPress URL (required for scan)")
	wordlist := flag.String("w", "plugins.txt", "Wordlist file containing plugins")
	customFile := flag.String("c", "", "Custom plugins file (additional)")
	outputFile := flag.String("o", "", "Output filename (without extension, will create .json and .txt)")
	threads := flag.Int("t", 50, "Number of concurrent threads (default: 50, use 1-5 for slow mode)")
	timeout := flag.Int("timeout", 10, "Request timeout in seconds")
	delay := flag.Int("delay", 0, "Delay between requests in ms (for slow/stealth mode)")
	proxyURL := flag.String("proxy", "", "Proxy URL (http://host:port, https://host:port, socks5://host:port, socks4://host:port)")
	stealthy := flag.Bool("s", false, "Enable stealthy mode: random UA, WAF bypass, IP spoofing, cache busting")
	flag.BoolVar(stealthy, "stealthy", false, "(Alias for -s) Enable stealthy mode")
	fastMode := flag.Bool("f", false, "Fast mode: 1 request per plugin (7x faster, lower confidence)")
	flag.BoolVar(fastMode, "fast", false, "(Alias for -f) Fast mode")
	collectMode := flag.Bool("collect", false, "Collect plugins from WordPress.org (creates wordlist)")
	minInstalls := flag.Int("min-installs", 100, "Minimum active installs when collecting")
	fullCollect := flag.Bool("full", false, "Collect ALL plugins (slow, use with -collect)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `
WordPress Plugin Scanner v1.0.1 - All-in-one Tool
==================================================

USAGE:
  %s [options]

SCAN MODE:
  %s -u <target_url> [-w wordlist] [-t threads] [-c custom_plugins] [-o output] [-proxy url]

COLLECT MODE (create wordlist):
  %s -collect [-min-installs 100] [-full]

OPTIONS:
`, os.Args[0], os.Args[0], os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
EXAMPLES:
  # Collect plugins (create wordlist first)
  %s -collect
  %s -collect -min-installs 1000
  %s -collect -full

  # Scan target (fast - 50 threads default)
  %s -u https://example.com
  %s -u https://example.com -t 100

  # FAST mode (7x faster, 1 request per plugin)
  %s -u https://example.com -f
  %s -u https://example.com -f -t 100

  # Scan with custom wordlist
  %s -u https://example.com -w my_plugins.txt -c custom.txt

  # Scan with custom output file
  %s -u https://example.com -o my_report

  # Stealthy + FAST (best for WAF-protected sites)
  %s -u https://protected-site.com/ -s -f -t 10

  # Stealthy mode (bypasses WAF/Cloudflare) - use -s for short
  %s -u https://protected-site.com/ -s -t 5 -delay 200

  # Ultra stealth for aggressive WAF
  %s -u https://protected-site.com/ -s -t 1 -delay 1000

  # Scan through SOCKS5 proxy (SSH tunnel)
  %s -u https://example.com -proxy socks5://127.0.0.1:9999

  # Scan through HTTP proxy
  %s -u https://example.com -proxy http://127.0.0.1:8080

  # Stealthy + Proxy (maximum anonymity)
  %s -u https://protected-site.com/ -s -f -t 10 -proxy socks5://127.0.0.1:9999

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0], os.Args[0])
	}

	flag.Parse()

	// Collect mode
	if *collectMode {
		if err := CollectPlugins(*wordlist, *minInstalls, *fullCollect); err != nil {
			fmt.Printf("[!] Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("\n[+] Collection completed!")
		return
	}

	// Scan mode - need target URL
	if *targetURL == "" {
		// Check if wordlist exists, if not, auto-collect
		if _, err := os.Stat(*wordlist); os.IsNotExist(err) {
			fmt.Printf("[!] Wordlist %s không tồn tại.\n", *wordlist)
			fmt.Println("[*] Tự động thu thập plugins...")
			if err := CollectPlugins(*wordlist, *minInstalls, false); err != nil {
				fmt.Printf("[!] Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("\n[+] Wordlist đã được tạo. Chạy lại với -u <target> để scan.")
			return
		}
		
		flag.Usage()
		os.Exit(1)
	}

	// Auto-collect if wordlist doesn't exist
	if _, err := os.Stat(*wordlist); os.IsNotExist(err) {
		fmt.Printf("[!] Wordlist %s không tồn tại. Đang thu thập...\n", *wordlist)
		if err := CollectPlugins(*wordlist, *minInstalls, false); err != nil {
			fmt.Printf("[!] Error collecting plugins: %v\n", err)
			os.Exit(1)
		}
	}

	// Auto-adjust settings for stealthy mode
	if *stealthy && *delay == 0 {
		*delay = 300 // Default 300ms delay in stealthy mode
	}

	// Run scanner
	scanner := NewScanner(*targetURL, *wordlist, *customFile, *outputFile, *threads, *timeout, *delay, *stealthy, *fastMode, *proxyURL)
	scanner.RunScan()
}
