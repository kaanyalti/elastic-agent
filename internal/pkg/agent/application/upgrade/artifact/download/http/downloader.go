// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/artifact/download"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/upgrade/details"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	agtversion "github.com/elastic/elastic-agent/pkg/version"
)

const (
	packagePermissions = 0o660

	// downloadProgressIntervalPercentage defines how often to report the current download progress when percentage
	// of time has passed in the overall interval for the complete download to complete. 5% is a good default, as
	// the default timeout is 10 minutes and this will have it log every 30 seconds.
	downloadProgressIntervalPercentage = 0.05

	// downloadProgressDefaultInterval defines the default interval at which the current download progress will be reported.
	// This value is used if the timeout is not specified (and therefore equal to 0).
	downloadProgressMinInterval = 10 * time.Second

	// warningProgressIntervalPercentage defines how often to log messages as a warning once the amount of time
	// passed is this percentage or more of the total allotted time to download.
	warningProgressIntervalPercentage = 0.75

	// template for insufficient disk space errors and logs
	insufficientDiskSpaceMsg = "insufficient disk space for %s: available=%d, required~=%d"
)

type DiskSpaceChecker func(log *logger.Logger, path string) (uint64, error)

// Downloader is a downloader able to fetch artifacts from elastic.co web page.
type Downloader struct {
	log            *logger.Logger
	config         *artifact.Config
	client         http.Client
	upgradeDetails *details.Details
	checkDiskSpace DiskSpaceChecker
}

// NewDownloader creates and configures Elastic Downloader
func NewDownloader(log *logger.Logger, config *artifact.Config, upgradeDetails *details.Details) (*Downloader, error) {
	client, err := config.HTTPTransportSettings.Client(
		httpcommon.WithAPMHTTPInstrumentation(),
		httpcommon.WithKeepaliveSettings{Disable: false, IdleConnTimeout: 30 * time.Second},
	)
	if err != nil {
		return nil, err
	}

	client.Transport = download.WithHeaders(client.Transport, download.Headers)
	return NewDownloaderWithClient(log, config, *client, upgradeDetails), nil
}

// NewDownloaderWithClient creates Elastic Downloader with specific client used
func NewDownloaderWithClient(log *logger.Logger, config *artifact.Config, client http.Client, upgradeDetails *details.Details) *Downloader {
	return &Downloader{
		log:            log,
		config:         config,
		client:         client,
		upgradeDetails: upgradeDetails,
		checkDiskSpace: download.CheckDiskSpace,
	}
}

func (e *Downloader) Reload(c *artifact.Config) error {
	// reload client
	client, err := c.HTTPTransportSettings.Client(
		httpcommon.WithAPMHTTPInstrumentation(),
	)
	if err != nil {
		return errors.New(err, "http.downloader: failed to generate client out of config")
	}

	client.Transport = download.WithHeaders(client.Transport, download.Headers)

	e.client = *client
	e.config = c

	return nil
}

// Download fetches the package from configured source.
// Returns absolute path to downloaded package and an error.
func (e *Downloader) Download(ctx context.Context, a artifact.Artifact, version *agtversion.ParsedSemVer) (_ string, err error) {
	remoteArtifact := a.Artifact
	downloadedFiles := make([]string, 0, 2)
	defer func() {
		if err != nil {
			for _, path := range downloadedFiles {
				if err := os.Remove(path); err != nil {
					e.log.Warnf("failed to cleanup %s: %v", path, err)
				}
			}
		}
	}()

	filename, _ := artifact.GetArtifactName(a, *version, e.config.OS(), e.config.Arch())
	fullPath, _ := artifact.GetArtifactPath(a, *version, e.config.OS(), e.config.Arch(), e.config.TargetDirectory)
	e.log.Infof("[Agent Downloader] Attempting to download artifact: %s to %s", filename, fullPath)

	// download from source to dest
	path, err := e.download(ctx, remoteArtifact, e.config.OS(), a, *version)
	if err != nil {
		return "", err
	}

	hashPath, err := e.downloadHash(ctx, remoteArtifact, e.config.OS(), a, *version)
	downloadedFiles = append(downloadedFiles, hashPath)
	e.log.Infof("[Agent Downloader] Downloaded artifact to %s", path)
	return path, err
}

func (e *Downloader) composeURI(artifactName, packageName string) (string, error) {
	upstream := e.config.SourceURI
	if !strings.HasPrefix(upstream, "http") && !strings.HasPrefix(upstream, "file") && !strings.HasPrefix(upstream, "/") {
		// always default to https
		upstream = fmt.Sprintf("https://%s", upstream)
	}

	// example: https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-7.1.1-x86_64.rpm
	uri, err := url.Parse(upstream)
	if err != nil {
		return "", errors.New(err, "invalid upstream URI", errors.TypeConfig)
	}

	uri.Path = path.Join(uri.Path, artifactName, packageName)
	return uri.String(), nil
}

func (e *Downloader) download(ctx context.Context, remoteArtifact string, operatingSystem string, a artifact.Artifact, version agtversion.ParsedSemVer) (string, error) {
	filename, err := artifact.GetArtifactName(a, version, operatingSystem, e.config.Arch())
	if err != nil {
		return "", errors.New(err, "generating package name failed")
	}

	fullPath, err := artifact.GetArtifactPath(a, version, operatingSystem, e.config.Arch(), e.config.TargetDirectory)
	if err != nil {
		return "", errors.New(err, "generating package path failed")
	}

	return e.downloadFile(ctx, remoteArtifact, filename, fullPath)
}

func (e *Downloader) downloadHash(ctx context.Context, remoteArtifact string, operatingSystem string, a artifact.Artifact, version agtversion.ParsedSemVer) (string, error) {
	filename, err := artifact.GetArtifactName(a, version, operatingSystem, e.config.Arch())
	if err != nil {
		return "", errors.New(err, "generating package name failed")
	}

	fullPath, err := artifact.GetArtifactPath(a, version, operatingSystem, e.config.Arch(), e.config.TargetDirectory)
	if err != nil {
		return "", errors.New(err, "generating package path failed")
	}

	filename = filename + ".sha512"
	fullPath = fullPath + ".sha512"

	return e.downloadFile(ctx, remoteArtifact, filename, fullPath)
}

func (e *Downloader) downloadFile(ctx context.Context, artifactName, filename, fullPath string) (string, error) {
	e.log.Infof("[Downloader] Starting downloadFile: artifactName=%s, filename=%s, fullPath=%s", artifactName, filename, fullPath)
	e.log.Infof("[Agent Downloader] Checking if artifact exists at %s", fullPath)
	if _, err := os.Stat(fullPath); err == nil {
		e.log.Infof("[Agent Downloader] Artifact already exists at %s, skipping download", fullPath)
		return fullPath, nil
	}

	sourceURI, err := e.composeURI(artifactName, filename)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("GET", sourceURI, nil)
	if err != nil {
		return "", errors.New(err, "fetching package failed", errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}

	if destinationDir := filepath.Dir(fullPath); destinationDir != "" && destinationDir != "." {
		if err := os.MkdirAll(destinationDir, 0o755); err != nil {
			return "", err
		}
	}

	destinationFile, err := os.OpenFile(fullPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, packagePermissions)
	if err != nil {
		return "", errors.New(err, "creating package file failed", errors.TypeFilesystem, errors.M(errors.MetaKeyPath, fullPath))
	}
	defer destinationFile.Close()

	resp, err := e.client.Do(req.WithContext(ctx))
	if err != nil {
		// return path, file already exists and needs to be cleaned up
		return fullPath, errors.New(err, "fetching package failed", errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		// return path, file already exists and needs to be cleaned up
		return fullPath, errors.New(fmt.Sprintf("call to '%s' returned unsuccessful status code: %d", sourceURI, resp.StatusCode), errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}

	// Content-Length check and logging
	contentLengthHeader := resp.Header.Get("Content-Length")
	e.log.Infof("[Downloader] Content-Length header: %s", contentLengthHeader)
	fileSize := -1
	if contentLengthHeader != "" {
		length, err := strconv.Atoi(contentLengthHeader)
		if err != nil {
			e.log.Warnf("[Downloader] Failed to parse Content-Length header '%s': %v", contentLengthHeader, err)
		} else {
			fileSize = length
			e.log.Infof("[Downloader] Parsed Content-Length as fileSize: %d bytes", fileSize)
		}
	} else {
		e.log.Infof("[Downloader] No Content-Length header present; fileSize remains unset")
	}

	e.log.Infof("[Downloader] Checking disk space at path: %s", fullPath)
	available, err := e.checkDiskSpace(e.log, filepath.Dir(fullPath))
	if err != nil {
		e.log.Errorf("[Downloader] Error checking disk space at %s: %v", fullPath, err)
	} else {
		e.log.Infof("[Downloader] Available disk space at %s: %d bytes", fullPath, available)
	}

	if fileSize > 0 && available < uint64(fileSize)*2 {
		errString := fmt.Sprintf(insufficientDiskSpaceMsg, filename, available, fileSize*2)
		e.log.Errorf(errString)
		return "", errors.New(errString)
	}

	loggingObserver := newLoggingProgressObserver(e.log, e.config.HTTPTransportSettings.Timeout)
	detailsObserver := newDetailsProgressObserver(e.upgradeDetails)
	dp := newDownloadProgressReporter(sourceURI, e.config.HTTPTransportSettings.Timeout, fileSize, loggingObserver, detailsObserver)
	dp.Report(ctx)
	_, err = io.Copy(destinationFile, io.TeeReader(resp.Body, dp))
	if err != nil {
		dp.ReportFailed(err)
		// return path, file already exists and needs to be cleaned up
		return fullPath, errors.New(err, "copying fetched package failed", errors.TypeNetwork, errors.M(errors.MetaKeyURI, sourceURI))
	}
	dp.ReportComplete()

	e.log.Infof("[Agent Downloader] Completed download to %s", fullPath)
	return fullPath, nil
}
