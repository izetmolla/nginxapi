package utils

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

func GetFreePort() (string, error) {
	// Listen on a random available port
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		fmt.Println("Error:", err)
		return "0", err
	}
	defer listener.Close()

	// Get the address of the listener
	addr := listener.Addr().(*net.TCPAddr)
	return strconv.Itoa(addr.Port), nil
}

func MakeHTTPRequestWithTimeout(url string) ([]byte, error) {
	// Create a context with a timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) //nolint
	defer cancel()

	// Create an HTTP GET request with the context
	request, err := http.NewRequestWithContext(ctx, "GET", url, nil) //nolint
	if err != nil {
		return nil, err
	}

	// Create an HTTP client
	client := &http.Client{}

	// Perform the request
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Read the response body
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func IsPublicDomain(domains []string, verificationCode string) bool {
	for _, domain := range domains {
		ips, err := net.LookupIP(domain)
		if err != nil {
			return false
		}
		for _, ip := range ips {
			if !IsPublicIP(ip) {
				return false
			}
		}
		_, err = MakeHTTPRequestWithTimeout(fmt.Sprintf("http://%s/.well-known/acme-challenge/%s", domain, verificationCode))
		if err != nil {
			return false
		} else {
			return true
		}
	}
	return true
}

func IsPublicIP(ip net.IP) bool {
	// Check if the IP is an IPv4 or IPv6 address
	if ip.To4() != nil {
		// Check for private IPv4 ranges
		privateRanges := []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		}

		for _, privateRange := range privateRanges {
			_, privateNet, err := net.ParseCIDR(privateRange)
			if err != nil {
				fmt.Println("Error parsing CIDR:", err)
				return false
			}

			if privateNet.Contains(ip) {
				return false
			}
		}
	} else if ip.To16() != nil {
		// Check for private IPv6 ranges (not exhaustive)
		privateRanges := []string{
			"fc00::/7",
			"::1/128",
		}

		for _, privateRange := range privateRanges {
			_, privateNet, err := net.ParseCIDR(privateRange)
			if err != nil {
				fmt.Println("Error parsing CIDR:", err)
				return false
			}

			if privateNet.Contains(ip) {
				return false
			}
		}
	}

	// If the IP is not in any private range, consider it public
	return true
}
