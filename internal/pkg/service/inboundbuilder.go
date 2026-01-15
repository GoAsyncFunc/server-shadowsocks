package service

import (
	"encoding/json"
	"fmt"
	"strings"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

const shadowsocksProtocol = api.Shadowsocks

// InboundBuilder builds Inbound config for Shadowsocks
func InboundBuilder(config *Config, nodeInfo *api.NodeInfo) (*core.InboundHandlerConfig, error) {
	if nodeInfo.Shadowsocks == nil {
		return nil, fmt.Errorf("node info missing Shadowsocks config")
	}
	ssInfo := nodeInfo.Shadowsocks

	inboundDetourConfig := &conf.InboundDetourConfig{}

	// Build Port
	portList := &conf.PortList{
		Range: []conf.PortRange{{From: uint32(ssInfo.ServerPort), To: uint32(ssInfo.ServerPort)}},
	}
	inboundDetourConfig.PortList = portList
	// Build Tag
	inboundDetourConfig.Tag = fmt.Sprintf("%s_%d", shadowsocksProtocol, ssInfo.ServerPort)
	// SniffingConfig
	sniffingConfig := &conf.SniffingConfig{
		Enabled:      true,
		DestOverride: &conf.StringList{"http", "tls"},
	}
	inboundDetourConfig.SniffingConfig = sniffingConfig

	// 1. Build Shadowsocks Server Config
	proxySetting, err := buildShadowsocksServerConfig(ssInfo)
	if err != nil {
		return nil, err
	}

	setting, err := json.Marshal(proxySetting)
	if err != nil {
		return nil, fmt.Errorf("marshal proxy %s config failed: %s", shadowsocksProtocol, err)
	}
	rawSetting := json.RawMessage(setting)

	// 2. Build Stream Settings (including Obfs)
	streamSetting, err := buildStreamConfig(ssInfo)
	if err != nil {
		return nil, err
	}

	inboundDetourConfig.Protocol = shadowsocksProtocol
	inboundDetourConfig.StreamSetting = streamSetting
	inboundDetourConfig.Settings = &rawSetting
	return inboundDetourConfig.Build()
}

func buildShadowsocksServerConfig(ssInfo *api.ShadowsocksNode) (interface{}, error) {
	cipher := strings.TrimSpace(ssInfo.Cipher)
	password := ssInfo.ServerKey
	if password == "" {
		password = "placeholder_password_for_initialization"
	}

	// Legacy/Standard Shadowsocks
	if !strings.Contains(cipher, "2022") {
		return &conf.ShadowsocksServerConfig{
			Cipher:   cipher,
			Password: password,
			Level:    0,
		}, nil
	}

	// Shadowsocks 2022
	// We trust the provided ServerKey (PSK) as-is.
	// Users must be populated to trigger MultiUserInbound.

	// Determine key length for placeholder
	is128 := strings.Contains(cipher, "128")
	placeholderKey := "AAAAAAAAAAAAAAAAAAAAAA==" // 16 bytes base64
	if !is128 {
		placeholderKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 bytes base64
	}

	return &conf.ShadowsocksServerConfig{
		Cipher:      cipher,
		Password:    password,
		Level:       0,
		NetworkList: &conf.NetworkList{"tcp", "udp"},
		Users: []*conf.ShadowsocksUserConfig{
			{
				Cipher:   "", // Must be empty for 2022 multi-user
				Password: placeholderKey,
				Email:    "placeholder@initialization",
				Level:    0,
			},
		},
	}, nil
}

func buildStreamConfig(ssInfo *api.ShadowsocksNode) (*conf.StreamConfig, error) {
	streamSetting := new(conf.StreamConfig)
	transportProtocol := conf.TransportProtocol("tcp")
	streamSetting.Network = &transportProtocol

	// Handle Obfs (http)
	if ssInfo.Obfs == "http" {
		tcpHeader, err := buildHTTPObfsHeader(ssInfo)
		if err != nil {
			return nil, err
		}

		headerBytes, _ := json.Marshal(tcpHeader)
		headerRaw := json.RawMessage(headerBytes)

		streamSetting.TCPSettings = &conf.TCPConfig{
			HeaderConfig: headerRaw,
		}
	}

	return streamSetting, nil
}

// Helper structs for HTTP Obfs
type HTTPRequestConfig struct {
	Version string              `json:"version"`
	Method  string              `json:"method"`
	Path    []string            `json:"path"`
	Headers map[string][]string `json:"headers"`
}
type TCPHeaderConfig struct {
	Type     string             `json:"type"`
	Request  *HTTPRequestConfig `json:"request,omitempty"`
	Response *HTTPRequestConfig `json:"response,omitempty"`
}

func buildHTTPObfsHeader(ssInfo *api.ShadowsocksNode) (*TCPHeaderConfig, error) {
	tcpHeader := &TCPHeaderConfig{
		Type: "http",
	}

	// Default configuration
	defaultRequest := &HTTPRequestConfig{
		Version: "1.1",
		Method:  "GET",
		Path:    []string{"/"},
		Headers: map[string][]string{
			"Host": {"www.bing.com"},
			"User-Agent": {
				"Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.75 Safari/537.36",
				"Mozilla/5.0 (iPhone; CPU iPhone OS 10_0_2 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/14A456 Safari/602.1",
			},
			"Accept-Encoding": {"gzip, deflate"},
			"Connection":      {"keep-alive"},
			"Pragma":          {"no-cache"},
		},
	}

	if len(ssInfo.ObfsSettings) > 0 {
		var simpleSettings struct {
			Host string `json:"host"`
			Path string `json:"path"`
		}
		// Use a separate config to merge changes if valid
		reqConfig := *defaultRequest                  // Copy default struct
		reqConfig.Headers = make(map[string][]string) // New map
		for k, v := range defaultRequest.Headers {    // Deep copy headers
			reqConfig.Headers[k] = v
		}

		if err := json.Unmarshal(ssInfo.ObfsSettings, &simpleSettings); err == nil {
			if simpleSettings.Path != "" {
				reqConfig.Path = []string{simpleSettings.Path}
			}
			if simpleSettings.Host != "" {
				reqConfig.Headers["Host"] = []string{simpleSettings.Host}
			}
		}
		tcpHeader.Request = &reqConfig
		tcpHeader.Response = &reqConfig
	} else {
		tcpHeader.Request = defaultRequest
		tcpHeader.Response = defaultRequest
	}
	return tcpHeader, nil
}
