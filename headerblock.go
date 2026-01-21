// Package headerblock is a plugin to block headers which regex matched by their name and/or value
package headerblock

import (
	"context"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
)

// Config the plugin configuration.
type Config struct {
	RequestHeaders          []HeaderConfig `json:"requestHeaders,omitempty"`
	WhitelistRequestHeaders []HeaderConfig `json:"whitelistRequestHeaders,omitempty"`
	AllowedIPs              []string       `json:"allowedIPs,omitempty"`
	Log                     bool           `json:"log,omitempty"`
}

// HeaderConfig is part of the plugin configuration.
type HeaderConfig struct {
	Name  string `json:"header,omitempty"`
	Value string `json:"env,omitempty"`
}

type rule struct {
	name  *regexp.Regexp
	value *regexp.Regexp
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Log: false,
	}
}

// headerBlock a Traefik plugin.
type headerBlock struct {
	next                  http.Handler
	requestHeaderRules    []rule
	whitelistRequestRules []rule
	allowedIPNets         []*net.IPNet
	log                   bool
}

func parseAllowedIPs(raw []string, logEnabled bool) []*net.IPNet {
	var ipNets []*net.IPNet

	for _, entry := range raw {
		// Split by comma to support "1.1.1.1/32, 2.2.2.2/32"
		parts := strings.Split(entry, ",")

		for _, part := range parts {
			ip := strings.TrimSpace(part)
			if ip == "" {
				continue
			}

			// Try CIDR first
			if _, netCIDR, err := net.ParseCIDR(ip); err == nil {
				ipNets = append(ipNets, netCIDR)
				continue
			}

			// Try single IP
			parsedIP := net.ParseIP(ip)
			if parsedIP != nil {
				bits := 128
				if parsedIP.To4() != nil {
					bits = 32
				}
				ipNets = append(ipNets, &net.IPNet{
					IP:   parsedIP,
					Mask: net.CIDRMask(bits, bits),
				})
				continue
			}

			// Fault-tolerant: log and skip
			if logEnabled {
				log.Printf("headerblock: invalid allowedIP entry skipped: %q", ip)
			}
		}
	}

	return ipNets
}

func getClientIP(req *http.Request) net.IP {
	// 1. X-Forwarded-For (Traefik trusted chain)
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if parsed := net.ParseIP(ip); parsed != nil {
				return parsed
			}
		}
	}

	// 2. Fallback to RemoteAddr (already ProxyProtocol-processed by Traefik)
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return net.ParseIP(req.RemoteAddr)
	}

	return net.ParseIP(host)
}

func isIPAllowed(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}

	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// New creates a new headerBlock plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	ipNets := parseAllowedIPs(config.AllowedIPs, config.Log)

	return &headerBlock{
		next:                  next,
		requestHeaderRules:    prepareRules(config.RequestHeaders),
		whitelistRequestRules: prepareRules(config.WhitelistRequestHeaders),
		allowedIPNets:         ipNets,
		log:                   config.Log,
	}, nil
}

func prepareRules(headerConfig []HeaderConfig) []rule {
	headerRules := make([]rule, 0)
	for _, requestHeader := range headerConfig {
		requestRule := rule{}
		if len(requestHeader.Name) > 0 {
			requestRule.name = regexp.MustCompile(requestHeader.Name)
		}
		if len(requestHeader.Value) > 0 {
			requestRule.value = regexp.MustCompile(requestHeader.Value)
		}
		headerRules = append(headerRules, requestRule)
	}
	return headerRules
}

func isWhitelisted(name string, values []string, whitelist []rule) bool {
	for _, rule := range whitelist {
		if rule.name != nil && !rule.name.MatchString(name) {
			continue
		}

		if rule.value == nil {
			return true
		}

		for _, value := range values {
			if rule.value.MatchString(value) {
				return true
			}
		}
	}
	return false
}

func (c *headerBlock) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	for name, values := range req.Header {
		for _, blockRule := range c.requestHeaderRules {
			if applyRule(blockRule, name, values) {

				// Header is blocked → check whitelist by header/value
				if isWhitelisted(name, values, c.whitelistRequestRules) {
					if c.log {
						log.Printf("%s: access allowed - whitelisted header %s", req.URL.String(), name)
					}
					continue
				}

				// Header violation → check allowed IPs
				clientIP := getClientIP(req)
				if isIPAllowed(clientIP, c.allowedIPNets) {
					if c.log {
						log.Printf(
							"%s: access allowed - IP %s bypassed blocked header %s",
							req.URL.String(),
							clientIP,
							name,
						)
					}
					continue
				}

				// Final deny
				if c.log {
					log.Printf(
						"%s: access denied - blocked header %s from IP %s",
						req.URL.String(),
						name,
						clientIP,
					)
				}

				rw.WriteHeader(http.StatusForbidden)
				return
			}
		}
	}

	// No blocking rules matched
	c.next.ServeHTTP(rw, req)
}

func applyRule(rule rule, name string, values []string) bool {
	nameMatch := rule.name != nil && rule.name.MatchString(name)
	if rule.value == nil && nameMatch {
		return true
	} else if rule.value != nil && (nameMatch || rule.name == nil) {
		for _, value := range values {
			if rule.value.MatchString(value) {
				return true
			}
		}
	}
	return false
}
