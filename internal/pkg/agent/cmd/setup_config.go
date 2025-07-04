// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import "time"

// setup configuration

type setupConfig struct {
	Fleet       fleetConfig       `config:"fleet"`
	FleetServer fleetServerConfig `config:"fleet_server"`
	Kibana      kibanaConfig      `config:"kibana"`
}

type fleetConfig struct {
	CA              string            `config:"ca"`
	Enroll          bool              `config:"enroll"`
	EnrollmentToken string            `config:"enrollment_token"`
	ID              string            `config:"id"`
	ReplaceToken    string            `config:"replace_token"`
	Force           bool              `config:"force"`
	Insecure        bool              `config:"insecure"`
	TokenName       string            `config:"token_name"`
	TokenPolicyName string            `config:"token_policy_name"`
	URL             string            `config:"url"`
	Headers         map[string]string `config:"headers"`
	DaemonTimeout   time.Duration     `config:"daemon_timeout"`
	EnrollTimeout   time.Duration     `config:"enroll_timeout"`
	Cert            string            `config:"cert"`
	CertKey         string            `config:"cert_key"`
}

type fleetServerConfig struct {
	Cert           string              `config:"cert"`
	CertKey        string              `config:"cert_key"`
	PassphrasePath string              `config:"key_passphrase_path"`
	ClientAuth     string              `config:"client_authentication"`
	Elasticsearch  elasticsearchConfig `config:"elasticsearch"`
	Enable         bool                `config:"enable"`
	Host           string              `config:"host"`
	InsecureHTTP   bool                `config:"insecure_http"`
	PolicyID       string              `config:"policy_id"`
	Port           string              `config:"port"`
	Headers        map[string]string   `config:"headers"`
	Timeout        time.Duration       `config:"timeout"`
}

type elasticsearchConfig struct {
	CA                   string `config:"ca"`
	CATrustedFingerprint string `config:"ca_trusted_fingerprint"`
	Host                 string `config:"host"`
	ServiceToken         string `config:"service_token"`
	ServiceTokenPath     string `config:"service_token_path"`
	Insecure             bool   `config:"insecure"`
	Cert                 string `config:"cert"`
	CertKey              string `config:"cert_key"`
}

type kibanaConfig struct {
	Fleet              kibanaFleetConfig `config:"fleet"`
	RetrySleepDuration time.Duration     `config:"retry_sleep_duration"`
	RetryMaxCount      int               `config:"retry_max_count"`
	Headers            map[string]string `config:"headers"`
}

type kibanaFleetConfig struct {
	CA               string `config:"ca"`
	Host             string `config:"host"`
	Username         string `config:"username"`
	Password         string `config:"password"`
	ServiceToken     string `config:"service_token"`
	ServiceTokenPath string `config:"service_token_path"`
}

func defaultAccessConfig() (setupConfig, error) {
	retrySleepDuration, err := envDurationWithDefault(defaultRequestRetrySleep, requestRetrySleepEnv)
	if err != nil {
		return setupConfig{}, err
	}

	retryMaxCount, err := envIntWithDefault(defaultMaxRequestRetries, maxRequestRetriesEnv)
	if err != nil {
		return setupConfig{}, err
	}

	cfg := setupConfig{
		Fleet: fleetConfig{
			CA:              envWithDefault("", "FLEET_CA", "KIBANA_CA", "ELASTICSEARCH_CA"),
			Enroll:          envBool("FLEET_ENROLL", "FLEET_SERVER_ENABLE"),
			EnrollmentToken: envWithDefault("", "FLEET_ENROLLMENT_TOKEN"),
			ID:              envWithDefault("", "ELASTIC_AGENT_ID"),
			ReplaceToken:    envWithDefault("", "FLEET_REPLACE_TOKEN"),
			Force:           envBool("FLEET_FORCE"),
			Insecure:        envBool("FLEET_INSECURE"),
			TokenName:       envWithDefault("Default", "FLEET_TOKEN_NAME"),
			TokenPolicyName: envWithDefault("", "FLEET_TOKEN_POLICY_NAME"),
			URL:             envWithDefault("", "FLEET_URL"),
			Headers:         envMap("FLEET_HEADER"),
			DaemonTimeout:   envTimeout("FLEET_DAEMON_TIMEOUT"),
			EnrollTimeout:   envTimeout("FLEET_ENROLL_TIMEOUT"),
			Cert:            envWithDefault("", "ELASTIC_AGENT_CERT"),
			CertKey:         envWithDefault("", "ELASTIC_AGENT_CERT_KEY"),
		},
		FleetServer: fleetServerConfig{
			Cert:           envWithDefault("", "FLEET_SERVER_CERT"),
			CertKey:        envWithDefault("", "FLEET_SERVER_CERT_KEY"),
			PassphrasePath: envWithDefault("", "FLEET_SERVER_CERT_KEY_PASSPHRASE"),
			ClientAuth:     envWithDefault("none", "FLEET_SERVER_CLIENT_AUTH"),
			Elasticsearch: elasticsearchConfig{
				Host:                 envWithDefault("http://elasticsearch:9200", "FLEET_SERVER_ELASTICSEARCH_HOST", "ELASTICSEARCH_HOST"),
				ServiceToken:         envWithDefault("", "FLEET_SERVER_SERVICE_TOKEN"),
				ServiceTokenPath:     envWithDefault("", "FLEET_SERVER_SERVICE_TOKEN_PATH"),
				CA:                   envWithDefault("", "FLEET_SERVER_ELASTICSEARCH_CA", "ELASTICSEARCH_CA"),
				CATrustedFingerprint: envWithDefault("", "FLEET_SERVER_ELASTICSEARCH_CA_TRUSTED_FINGERPRINT"),
				Insecure:             envBool("FLEET_SERVER_ELASTICSEARCH_INSECURE"),
				Cert:                 envWithDefault("", "FLEET_SERVER_ES_CERT"),
				CertKey:              envWithDefault("", "FLEET_SERVER_ES_CERT_KEY"),
			},
			Enable:       envBool("FLEET_SERVER_ENABLE"),
			Host:         envWithDefault("", "FLEET_SERVER_HOST"),
			InsecureHTTP: envBool("FLEET_SERVER_INSECURE_HTTP"),
			PolicyID:     envWithDefault("", "FLEET_SERVER_POLICY_ID", "FLEET_SERVER_POLICY"),
			Port:         envWithDefault("", "FLEET_SERVER_PORT"),
			Headers:      envMap("FLEET_HEADER"),
			Timeout:      envTimeout("FLEET_SERVER_TIMEOUT"),
		},
		Kibana: kibanaConfig{
			Fleet: kibanaFleetConfig{
				Host:             envWithDefault("http://kibana:5601", "KIBANA_FLEET_HOST", "KIBANA_HOST"),
				Username:         envWithDefault("elastic", "KIBANA_FLEET_USERNAME", "KIBANA_USERNAME", "ELASTICSEARCH_USERNAME"),
				Password:         envWithDefault("changeme", "KIBANA_FLEET_PASSWORD", "KIBANA_PASSWORD", "ELASTICSEARCH_PASSWORD"),
				ServiceToken:     envWithDefault("", "KIBANA_FLEET_SERVICE_TOKEN", "FLEET_SERVER_SERVICE_TOKEN"),
				ServiceTokenPath: envWithDefault("", "KIBANA_FLEET_SERVICE_TOKEN_PATH", "FLEET_SERVER_SERVICE_TOKEN_PATH"),
				CA:               envWithDefault("", "KIBANA_FLEET_CA", "KIBANA_CA", "ELASTICSEARCH_CA"),
			},
			RetrySleepDuration: retrySleepDuration,
			RetryMaxCount:      retryMaxCount,
			Headers:            envMap("FLEET_KIBANA_HEADER"),
		},
	}
	return cfg, nil
}
