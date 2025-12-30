package service

import (
	"encoding/json"

	api "github.com/GoAsyncFunc/uniproxy/pkg"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
)

func OutboundBuilder(config *Config, nodeInfo *api.NodeInfo, extConf []byte) (*core.OutboundHandlerConfig, error) {
	// If external config is provided, can load it.
	// Use default "freedom" outbound.

	// Example: parse extFileBytes if you have complex routing rules.

	outboundDetourConfig := &conf.OutboundDetourConfig{}
	outboundDetourConfig.Protocol = "freedom"
	outboundDetourConfig.Tag = "direct"
	outboundDetourConfig.Settings = &json.RawMessage{'{', '}'}

	return outboundDetourConfig.Build()
}
