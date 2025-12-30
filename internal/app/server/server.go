package server

import (
	"context"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"

	_ "github.com/GoAsyncFunc/server-shadowsocks/internal/pkg/dep"
	"github.com/GoAsyncFunc/server-shadowsocks/internal/pkg/dispatcher"
	"github.com/GoAsyncFunc/server-shadowsocks/internal/pkg/service"
	api "github.com/GoAsyncFunc/uniproxy/pkg"
)

type Config struct {
	LogLevel string
}

const (
	LogLevelDebug  = "debug"
	LogLevelInfo   = "info"
	LogLevelError  = "error"
	DefaultDataDir = "/var/lib/server-shadowsocks"
)

type Server struct {
	instance      *core.Instance
	logLevel      string
	serviceConfig *service.Config
	apiClient     *api.Client
	config        *Config
	extConfBytes  []byte
	service       *service.Builder
	mu            sync.Mutex
	dataDir       string
}

func New(config *Config, apiConfig *api.Config, serviceConfig *service.Config, extConfBytes []byte, dataDir string) (*Server, error) {
	// API Client initialization
	client := api.New(apiConfig)
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	return &Server{
		config:        config,
		logLevel:      config.LogLevel,
		apiClient:     client,
		serviceConfig: serviceConfig,
		extConfBytes:  extConfBytes,
		dataDir:       dataDir,
	}, nil
}

func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	log.Infoln("server start")

	// Create context
	ctx := context.Background()

	// Fetch node config
	// uniproxy Client stores NodeID/Type internally, so we just call GetNodeInfo(ctx)
	nodeConfig, err := s.apiClient.GetNodeInfo(ctx)
	if err != nil {
		return fmt.Errorf("get node info error: %s", err)
	}
	// If uniproxy returns nil (Not Modified) on first call?
	// Usually first call should return data if client is fresh.
	// But check nil safety.
	if nodeConfig == nil {
		return fmt.Errorf("node info is empty (or 304 Not Modified on first start)")
	}

	// Update serviceConfig NodeID if needed (though client has it)
	s.serviceConfig.NodeID = nodeConfig.Id

	// Registration: uniproxy implementation seems to not imply explicit Register call.
	// We proceed to build services.

	inboundHandlerConfig, err := service.InboundBuilder(s.serviceConfig, nodeConfig)
	if err != nil {
		return fmt.Errorf("build inbound config error: %s", err)
	}

	outboundHandlerConfig, err := service.OutboundBuilder(s.serviceConfig, nodeConfig, s.extConfBytes)
	if err != nil {
		return fmt.Errorf("build outbound config error: %s", err)
	}

	pbConfig, err := s.loadCore(inboundHandlerConfig, outboundHandlerConfig)
	if err != nil {
		return fmt.Errorf("load core config error: %s", err)
	}

	instance, err := core.New(pbConfig)
	if err != nil {
		return fmt.Errorf("create core instance error: %s", err)
	}
	s.instance = instance

	if err := s.instance.Start(); err != nil {
		return fmt.Errorf("start core instance error: %s", err)
	}

	s.service = service.New(
		inboundHandlerConfig.Tag,
		s.instance,
		s.serviceConfig,
		nodeConfig,
		s.apiClient,
	)

	if err := s.service.Start(); err != nil {
		return fmt.Errorf("start service error: %s", err)
	}

	log.Infof("Server started")
	return nil
}

func (s *Server) loadCore(inboundConfig *core.InboundHandlerConfig, outboundConfig *core.OutboundHandlerConfig) (*core.Config, error) {
	logConfig := &conf.LogConfig{}
	logConfig.LogLevel = s.config.LogLevel
	if s.config.LogLevel != LogLevelDebug {
		logConfig.AccessLog = "none"
		logConfig.ErrorLog = "none"
		logConfig.DNSLog = false
	}
	pbLogConfig := logConfig.Build()

	inboundConfigs := []*core.InboundHandlerConfig{inboundConfig}
	outBoundConfigs := []*core.OutboundHandlerConfig{outboundConfig}

	// PolicyConfig - simplified default
	// We can copy the policy building logic from trojan if needed, keeping it simple here.
	policyConfig := &conf.PolicyConfig{}
	// ... (Simplified: actual policy implementation usually required for stats)
	// I will add a minimalist policy that enables stats.
	pbPolicy := &conf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
	}
	policyConfig.Levels = map[uint32]*conf.Policy{0: pbPolicy}
	pbPolicyConfig, _ := policyConfig.Build()

	pbCoreConfig := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(pbLogConfig),
			serial.ToTypedMessage(pbPolicyConfig),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&dispatcher.Config{}), // Custom dispatcher
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
		},
		Outbound: outBoundConfigs,
		Inbound:  inboundConfigs,
	}

	// Correct logic:
	return pbCoreConfig, nil
}

func (s *Server) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.service != nil {
		err := s.service.Close()
		if err != nil {
			log.Errorf("server close failed: %s", err)
		}
	}
	log.Infoln("server close")
}
