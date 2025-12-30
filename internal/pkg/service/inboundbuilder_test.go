package service

import (
	"encoding/json"
	"testing"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/proxy/shadowsocks"
	"github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

func TestInboundBuilder_SS2022_KeyHandling(t *testing.T) {
	// 128-bit key in Hex (32 chars) -> 16 bytes
	// 404142434445464748494a4b4c4d4e4f -> @ABCDEFGHIJKLMNO
	hexKey128 := "404142434445464748494a4b4c4d4e4f"
	expectedBase64_128 := "QEFCQ0RFRkdISUpLTE1OTw=="

	// 256-bit key in Hex (64 chars) -> 32 bytes
	// 404142434445464748494a4b4c4d4e4f404142434445464748494a4b4c4d4e4f
	hexKey256 := "404142434445464748494a4b4c4d4e4f404142434445464748494a4b4c4d4e4f"
	expectedBase64_256 := "QEFCQ0RFRkdISUpLTE1OT0BBQkNERUZHSElKS0xNTk8=" // Used for valid base64 test case

	tests := []struct {
		name        string
		cipher      string
		serverKey   string
		expectKey   string // Expected Base64 key in config
		expectDeriv bool   // If true, we expect the key to NOT match input (hashed) - NOT USED directly, but implies logic
		expectExact bool   // If true, the resulting password must match expectKey exactly
	}{
		{
			name:        "128-bit Valid Base64",
			cipher:      "2022-blake3-aes-128-gcm",
			serverKey:   expectedBase64_128,
			expectKey:   expectedBase64_128,
			expectExact: true,
		},
		{
			name:        "256-bit Valid Base64",
			cipher:      "2022-blake3-aes-256-gcm",
			serverKey:   expectedBase64_256,
			expectKey:   expectedBase64_256,
			expectExact: true,
		},
		{
			name:        "128-bit Valid Hex (Should NOT be decoded by builder)",
			cipher:      "2022-blake3-aes-128-gcm",
			serverKey:   hexKey128,
			expectKey:   hexKey128, // Builder should pass it through
			expectExact: true,
		},
		{
			name:        "256-bit Valid Hex (Should NOT be decoded by builder)",
			cipher:      "2022-blake3-aes-256-gcm",
			serverKey:   hexKey256,
			expectKey:   hexKey256, // Builder should pass it through
			expectExact: true,
		},
		{
			name:        "Invalid Key (Plaintext) - Should NOT be Hashed",
			cipher:      "2022-blake3-aes-128-gcm",
			serverKey:   "short_password",
			expectKey:   "short_password", // Builder should pass it through
			expectExact: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			nodeInfo := &api.NodeInfo{
				Shadowsocks: &api.ShadowsocksNode{
					CommonNode: api.CommonNode{
						ServerPort: 12345,
					},
					Cipher:    tt.cipher,
					ServerKey: tt.serverKey,
				},
			}
			config := &Config{} // Empty config okay for this test

			inboundConfig, err := InboundBuilder(config, nodeInfo)
			if err != nil {
				t.Fatalf("InboundBuilder failed: %v", err)
			}

			// Verify Settings
			if inboundConfig.ProxySettings == nil {
				t.Fatal("ProxySettings is nil")
			}

			// Get config instance
			settingsObj, err := inboundConfig.ProxySettings.GetInstance()
			if err != nil {
				t.Fatalf("Failed to get settings instance: %v", err)
			}

			// Log the type we got
			t.Logf("Got config type: %T", settingsObj)

			// Check for SS-2022 config
			if ssConfig, ok := settingsObj.(*shadowsocks_2022.MultiUserServerConfig); ok {
				// Log config
				jsonBytes, _ := json.MarshalIndent(ssConfig, "", "  ")
				t.Logf("SS-2022 Config: %s", string(jsonBytes))

				// Check Key (PSK)
				// Key is string (Base64) in MultiUserServerConfig
				actualKeyBase64 := ssConfig.Key
				t.Logf("Actual Configured Key (Base64): %s", actualKeyBase64)

				if tt.expectExact {
					if actualKeyBase64 != tt.expectKey {
						t.Errorf("Expected key %s, got %s", tt.expectKey, actualKeyBase64)
					}
				} else {
					if actualKeyBase64 == "" {
						t.Errorf("Expected a derived key, but got empty")
					}
					// If original was short plaintext, it should be hashed
					if tt.serverKey == "short_password" && actualKeyBase64 == tt.serverKey {
						t.Errorf("Expected derived key, got input key")
					}
				}

			} else if ssConfig, ok := settingsObj.(*shadowsocks.ServerConfig); ok {
				// Fallback for non-2022 if any (though we only test 2022 here)
				jsonBytes, _ := json.MarshalIndent(ssConfig, "", "  ")
				t.Logf("Got legacy SS Config: %s", string(jsonBytes))
			} else {
				t.Fatalf("Unknown config type: %T", settingsObj)
			}
		})
	}
}
