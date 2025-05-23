// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package mage

import (
	"errors"
	"fmt"
	"go/build"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"

	"github.com/magefile/mage/sh"

	"github.com/elastic/elastic-agent/dev-tools/mage/gotool"
	v1 "github.com/elastic/elastic-agent/pkg/api/v1"
)

const (
	fpmVersion = "1.13.1"

	// Docker images. See https://github.com/elastic/golang-crossbuild.
	beatsFPMImage = "docker.elastic.co/beats-dev/fpm"
	// BeatsCrossBuildImage is the image used for crossbuilding Beats.
	BeatsCrossBuildImage = "docker.elastic.co/beats-dev/golang-crossbuild"

	elasticAgentImportPath = "github.com/elastic/elastic-agent"

	elasticAgentModulePath = "github.com/elastic/elastic-agent"

	defaultName = "elastic-agent"

	// Env vars
	// agent package version
	agentPackageVersionEnvVar = "AGENT_PACKAGE_VERSION"
	//ManifestUrlEnvVar is the name fo the environment variable containing the Manifest URL to be used for packaging agent
	ManifestUrlEnvVar = "MANIFEST_URL"
	// AgentCommitHashEnvVar allows to override agent commit hash string during packaging
	AgentCommitHashEnvVar = "AGENT_COMMIT_HASH_OVERRIDE"

	// Mapped functions
	agentPackageVersionMappedFunc    = "agent_package_version"
	agentManifestGeneratorMappedFunc = "manifest"
	snapshotSuffix                   = "snapshot_suffix"
)

// Common settings with defaults derived from files, CWD, and environment.
var (
	GOOS         = build.Default.GOOS
	GOARCH       = build.Default.GOARCH
	GOARM        = EnvOr("GOARM", "")
	Platform     = MakePlatformAttributes(GOOS, GOARCH, GOARM)
	BinaryExt    = ""
	XPackDir     = "../x-pack"
	RaceDetector = false
	TestCoverage = false
	PLATFORMS    = EnvOr("PLATFORMS", "")
	PACKAGES     = EnvOr("PACKAGES", "")
	CI           = EnvOr("CI", "")

	// CrossBuildMountModcache mounts $GOPATH/pkg/mod into
	// the crossbuild images at /go/pkg/mod, read-only,  when set to true.
	CrossBuildMountModcache = true

	BeatName        = EnvOr("BEAT_NAME", defaultName)
	BeatServiceName = EnvOr("BEAT_SERVICE_NAME", BeatName)
	BeatIndexPrefix = EnvOr("BEAT_INDEX_PREFIX", BeatName)
	BeatDescription = EnvOr("BEAT_DESCRIPTION", "")
	BeatVendor      = EnvOr("BEAT_VENDOR", "Elastic")
	BeatLicense     = EnvOr("BEAT_LICENSE", "Elastic License 2.0")
	BeatURL         = EnvOr("BEAT_URL", "https://www.elastic.co/beats/"+BeatName)
	BeatUser        = EnvOr("BEAT_USER", "root")

	BeatProjectType ProjectType

	Snapshot      bool
	DevBuild      bool
	ExternalBuild bool
	FIPSBuild     bool

	versionQualified bool
	versionQualifier string

	// Env var to set the agent package version
	agentPackageVersion string

	// PackagingFromManifest This value is set to tru when we have defined a ManifestURL variable
	PackagingFromManifest bool
	// ManifestURL Location of the manifest file to package
	ManifestURL string

	FuncMap = map[string]interface{}{
		"beat_doc_branch":                BeatDocBranch,
		"beat_version":                   BeatQualifiedVersion,
		"commit":                         CommitHash,
		"commit_short":                   CommitHashShort,
		"date":                           BuildDate,
		"elastic_beats_dir":              ElasticBeatsDir,
		"go_version":                     GoVersion,
		"repo":                           GetProjectRepoInfo,
		"title":                          func(s string) string { return cases.Title(language.English, cases.NoLower).String(s) },
		"tolower":                        strings.ToLower,
		"contains":                       strings.Contains,
		"substring":                      Substring,
		agentPackageVersionMappedFunc:    AgentPackageVersion,
		agentManifestGeneratorMappedFunc: PackageManifest,
		snapshotSuffix:                   SnapshotSuffix,
	}
)

func init() {
	initGlobals()
}

func initGlobals() {
	if GOOS == "windows" {
		BinaryExt = ".exe"
	}

	var err error
	RaceDetector, err = strconv.ParseBool(EnvOr("RACE_DETECTOR", "false"))
	if err != nil {
		panic(fmt.Errorf("failed to parse RACE_DETECTOR env value: %w", err))
	}

	TestCoverage, err = strconv.ParseBool(EnvOr("TEST_COVERAGE", "false"))
	if err != nil {
		panic(fmt.Errorf("failed to parse TEST_COVERAGE env value: %w", err))
	}

	Snapshot, err = strconv.ParseBool(EnvOr("SNAPSHOT", "false"))
	if err != nil {
		panic(fmt.Errorf("failed to parse SNAPSHOT env value: %w", err))
	}

	DevBuild, err = strconv.ParseBool(EnvOr("DEV", "false"))
	if err != nil {
		panic(fmt.Errorf("failed to parse DEV env value: %w", err))
	}

	ExternalBuild, err = strconv.ParseBool(EnvOr("EXTERNAL", "false"))
	if err != nil {
		panic(fmt.Errorf("failed to parse EXTERNAL env value: %w", err))
	}

	FIPSBuild, err = strconv.ParseBool(EnvOr("FIPS", "false"))
	if err != nil {
		panic(fmt.Errorf("failed to parse FIPS env value: %w", err))
	}

	versionQualifier, versionQualified = os.LookupEnv("VERSION_QUALIFIER")

	agentPackageVersion = EnvOr(agentPackageVersionEnvVar, "")

	ManifestURL = EnvOr(ManifestUrlEnvVar, "")
	PackagingFromManifest = ManifestURL != ""
}

// ProjectType specifies the type of project (OSS vs X-Pack).
type ProjectType uint8

// Project types.
const (
	OSSProject ProjectType = iota
	XPackProject
	CommunityProject
)

// ErrUnknownProjectType is returned if an unknown ProjectType value is used.
var ErrUnknownProjectType = fmt.Errorf("unknown ProjectType")

// EnvMap returns map containing the common settings variables and all variables
// from the environment. args are appended to the output prior to adding the
// environment variables (so env vars have the highest precedence).
func EnvMap(args ...map[string]interface{}) map[string]interface{} {
	envMap := varMap(args...)

	// Add the environment (highest precedence).
	for _, e := range os.Environ() {
		env := strings.SplitN(e, "=", 2)
		envMap[env[0]] = env[1]
	}

	return envMap
}

func varMap(args ...map[string]interface{}) map[string]interface{} {
	data := map[string]interface{}{
		"GOOS":            GOOS,
		"GOARCH":          GOARCH,
		"GOARM":           GOARM,
		"Platform":        Platform,
		"PLATFORMS":       PLATFORMS,
		"PACKAGES":        PACKAGES,
		"BinaryExt":       BinaryExt,
		"XPackDir":        XPackDir,
		"BeatName":        BeatName,
		"BeatServiceName": BeatServiceName,
		"BeatIndexPrefix": BeatIndexPrefix,
		"BeatDescription": BeatDescription,
		"BeatVendor":      BeatVendor,
		"BeatLicense":     BeatLicense,
		"BeatURL":         BeatURL,
		"BeatUser":        BeatUser,
		"Snapshot":        Snapshot,
		"DEV":             DevBuild,
		"EXTERNAL":        ExternalBuild,
		"FIPS":            FIPSBuild,
		"Qualifier":       versionQualifier,
		"CI":              CI,
	}

	// Add the extra args to the map.
	for _, m := range args {
		for k, v := range m {
			data[k] = v
		}
	}

	return data
}

func dumpVariables() (string, error) {
	var dumpTemplate = `## Variables

GOOS             = {{.GOOS}}
GOARCH           = {{.GOARCH}}
GOARM            = {{.GOARM}}
Platform         = {{.Platform}}
BinaryExt        = {{.BinaryExt}}
XPackDir         = {{.XPackDir}}
BeatName         = {{.BeatName}}
BeatServiceName  = {{.BeatServiceName}}
BeatIndexPrefix  = {{.BeatIndexPrefix}}
BeatDescription  = {{.BeatDescription}}
BeatVendor       = {{.BeatVendor}}
BeatLicense      = {{.BeatLicense}}
BeatURL          = {{.BeatURL}}
BeatUser         = {{.BeatUser}}
VersionQualifier = {{.Qualifier}}
PLATFORMS        = {{.PLATFORMS}}
PACKAGES         = {{.PACKAGES}}
CI               = {{.CI}}

## Functions

beat_doc_branch              = {{ beat_doc_branch }}
beat_version                 = {{ beat_version }}
commit                       = {{ commit }}
date                         = {{ date }}
elastic_beats_dir            = {{ elastic_beats_dir }}
go_version                   = {{ go_version }}
repo.RootImportPath          = {{ repo.RootImportPath }}
repo.CanonicalRootImportPath = {{ repo.CanonicalRootImportPath }}
repo.RootDir                 = {{ repo.RootDir }}
repo.ImportPath              = {{ repo.ImportPath }}
repo.SubDir                  = {{ repo.SubDir }}
agent_package_version        = {{ agent_package_version}}
snapshot_suffix              = {{ snapshot_suffix }}
`

	return Expand(dumpTemplate)
}

// DumpVariables writes the template variables and values to stdout.
func DumpVariables() error {
	out, err := dumpVariables()
	if err != nil {
		return err
	}

	fmt.Println(out)
	return nil
}

var (
	commitHash     string
	commitHashOnce sync.Once
)

// CommitHash returns the full length git commit hash.
func CommitHash() (string, error) {
	var err error
	commitHashOnce.Do(func() {
		// Check commit hash override first
		commitHash = EnvOr(AgentCommitHashEnvVar, "")
		if commitHash == "" {
			// no override found, get the hash from HEAD
			commitHash, err = sh.Output("git", "rev-parse", "HEAD")
		}
	})
	return commitHash, err
}

// CommitHashShort returns the short length git commit hash.
func CommitHashShort() (string, error) {
	shortHash, err := CommitHash()
	if len(shortHash) > 6 {
		shortHash = shortHash[:6]
	}
	return shortHash, err
}

// TagContainsCommit returns true or false depending on if the current commit is part of a git tag.
func TagContainsCommit() (bool, error) {
	commitHash, err := CommitHash()
	if err != nil {
		return false, err
	}

	out, err := sh.Output("git", "tag", "--contains", commitHash)
	if err != nil {
		return false, err
	}

	return strings.TrimSpace(out) != "", nil
}

func AgentPackageVersion() (string, error) {

	if agentPackageVersion != "" {
		return agentPackageVersion, nil
	}

	return BeatQualifiedVersion()
}

func PackageManifest(fips bool) (string, error) {

	packageVersion, err := AgentPackageVersion()
	if err != nil {
		return "", fmt.Errorf("retrieving agent package version: %w", err)
	}

	hash, err := CommitHash()
	if err != nil {
		return "", fmt.Errorf("retrieving agent commit hash: %w", err)
	}

	commitHashShort, err := CommitHashShort()
	if err != nil {
		return "", fmt.Errorf("retrieving agent commit hash: %w", err)
	}

	registry, err := loadFlavorsRegistry()
	if err != nil {
		return "", fmt.Errorf("retrieving agent flavors: %w", err)
	}

	return GeneratePackageManifest(BeatName, packageVersion, Snapshot, hash, commitHashShort, fips, registry)
}

func GeneratePackageManifest(beatName, packageVersion string, snapshot bool, fullHash, shortHash string, fips bool, flavorsRegistry map[string][]string) (string, error) {
	m := v1.NewManifest()
	m.Package.Version = packageVersion
	m.Package.Snapshot = snapshot
	m.Package.Hash = fullHash
	m.Package.Fips = fips

	versionedHomePath := path.Join("data", fmt.Sprintf("%s-%s", beatName, shortHash))
	m.Package.VersionedHome = versionedHomePath
	m.Package.PathMappings = []map[string]string{{}}
	m.Package.PathMappings[0][versionedHomePath] = fmt.Sprintf("data/%s-%s%s-%s", beatName, m.Package.Version, GenerateSnapshotSuffix(snapshot), shortHash)
	m.Package.PathMappings[0][v1.ManifestFileName] = fmt.Sprintf("data/%s-%s%s-%s/%s", beatName, m.Package.Version, GenerateSnapshotSuffix(snapshot), shortHash, v1.ManifestFileName)
	m.Package.Flavors = flavorsRegistry
	yamlBytes, err := yaml.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("marshaling manifest: %w", err)

	}
	return string(yamlBytes), nil
}

func SnapshotSuffix() string {
	return GenerateSnapshotSuffix(Snapshot)
}

func Substring(s string, start, length int) string {
	if start < 0 || start >= len(s) {
		return ""
	}
	end := start + length
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

func GenerateSnapshotSuffix(snapshot bool) string {
	if !snapshot {
		return ""
	}

	return "-SNAPSHOT"
}

var (
	elasticBeatsDirValue string
	elasticBeatsDirErr   error
	elasticBeatsDirLock  sync.Mutex
)

// SetElasticBeatsDir sets the internal elastic beats dir to a preassigned value
func SetElasticBeatsDir(path string) {
	elasticBeatsDirLock.Lock()
	defer elasticBeatsDirLock.Unlock()

	elasticBeatsDirValue = path
}

// ElasticBeatsDir returns the path to Elastic beats dir.
func ElasticBeatsDir() (string, error) {
	elasticBeatsDirLock.Lock()
	defer elasticBeatsDirLock.Unlock()

	if elasticBeatsDirValue != "" || elasticBeatsDirErr != nil {
		return elasticBeatsDirValue, elasticBeatsDirErr
	}

	elasticBeatsDirValue, elasticBeatsDirErr = findElasticBeatsDir()
	if elasticBeatsDirErr == nil {
		log.Println("Found Elastic Beats dir at", elasticBeatsDirValue)
	}
	return elasticBeatsDirValue, elasticBeatsDirErr
}

// findElasticBeatsDir returns the root directory of the Elastic Beats module, using "go list".
//
// When running within the Elastic Beats repo, this will return the repo root. Otherwise,
// it will return the root directory of the module from within the module cache or vendor
// directory.
func findElasticBeatsDir() (string, error) {
	repo, err := GetProjectRepoInfo()
	if err != nil {
		return "", err
	}
	if repo.IsElasticBeats() {
		return repo.RootDir, nil
	}
	return gotool.ListModuleCacheDir(elasticAgentModulePath)
}

var (
	buildDate = time.Now().UTC().Format(time.RFC3339)
)

// BuildDate returns the time that the build started.
func BuildDate() string {
	return buildDate
}

var (
	goVersionValue string
	goVersionErr   error
	goVersionOnce  sync.Once
)

// GoVersion returns the version of Go defined in the project's .go-version
// file.
func GoVersion() (string, error) {
	goVersionOnce.Do(func() {
		goVersionValue = os.Getenv("BEAT_GO_VERSION")
		if goVersionValue != "" {
			return
		}

		goVersionValue, goVersionErr = getBuildVariableSources().GetGoVersion()
	})

	return goVersionValue, goVersionErr
}

var (
	beatVersionRegex = regexp.MustCompile(`(?m)^const defaultBeatVersion = "(.+)"\r?$`)
	beatVersionValue string
	beatVersionErr   error
	beatVersionOnce  sync.Once

	flavorsRegistry    map[string][]string
	flavorsRegistryErr error
	flavorsOnce        sync.Once
)

// BeatQualifiedVersion returns the Beat's qualified version.  The value can be overwritten by
// setting VERSION_QUALIFIER in the environment.
func BeatQualifiedVersion() (string, error) {
	version, err := beatVersion()
	if err != nil {
		return "", err
	}
	// version qualifier can intentionally be set to "" to override build time var
	if !versionQualified || versionQualifier == "" {
		return version, nil
	}
	return version + "-" + versionQualifier, nil
}

// BeatVersion returns the Beat's version. The value can be overridden by
// setting BEAT_VERSION in the environment.
func beatVersion() (string, error) {
	beatVersionOnce.Do(func() {
		beatVersionValue = os.Getenv("BEAT_VERSION")
		if beatVersionValue != "" {
			return
		}

		beatVersionValue, beatVersionErr = getBuildVariableSources().GetBeatVersion()
	})

	return beatVersionValue, beatVersionErr
}

func loadFlavorsRegistry() (map[string][]string, error) {
	flavorsOnce.Do(func() {
		flavorsRegistry, flavorsRegistryErr = getBuildVariableSources().GetFlavorsRegistry()
	})

	return flavorsRegistry, flavorsRegistryErr
}

var (
	beatDocBranchRegex     = regexp.MustCompile(`(?m)doc-branch:\s*([^\s]+)\r?$`)
	beatDocSiteBranchRegex = regexp.MustCompile(`(?m)doc-site-branch:\s*([^\s]+)\r?$`)
	beatDocBranchValue     string
	beatDocBranchErr       error
	beatDocBranchOnce      sync.Once
)

// BeatDocBranch returns the documentation branch name associated with the
// Beat branch.
func BeatDocBranch() (string, error) {
	beatDocBranchOnce.Do(func() {
		beatDocBranchValue = os.Getenv("BEAT_DOC_BRANCH")
		if beatDocBranchValue != "" {
			return
		}

		beatDocBranchValue, beatDocBranchErr = getBuildVariableSources().GetDocBranch()
	})

	return beatDocBranchValue, beatDocBranchErr
}

// --- BuildVariableSources

var (
	// DefaultBeatBuildVariableSources contains the default locations build
	// variables are read from by Elastic Beats.
	DefaultBeatBuildVariableSources = &BuildVariableSources{
		BeatVersion:     "{{ elastic_beats_dir }}/version/version.go",
		GoVersion:       "{{ elastic_beats_dir }}/.go-version",
		DocBranch:       "{{ elastic_beats_dir }}/version/docs/version.asciidoc",
		FlavorsRegistry: "{{ elastic_beats_dir }}/_meta/.flavors",
	}

	buildVariableSources     *BuildVariableSources
	buildVariableSourcesLock sync.Mutex
)

// SetBuildVariableSources sets the BuildVariableSources that defines where
// certain build data should be sourced from. Community Beats must call this.
func SetBuildVariableSources(s *BuildVariableSources) {
	buildVariableSourcesLock.Lock()
	defer buildVariableSourcesLock.Unlock()

	buildVariableSources = s
}

func getBuildVariableSources() *BuildVariableSources {
	buildVariableSourcesLock.Lock()
	defer buildVariableSourcesLock.Unlock()

	if buildVariableSources != nil {
		return buildVariableSources
	}

	repo, err := GetProjectRepoInfo()
	if err != nil {
		panic(err)
	}
	if repo.IsElasticBeats() {
		buildVariableSources = DefaultBeatBuildVariableSources
		return buildVariableSources
	}

	panic(fmt.Errorf("magefile must call devtools.SetBuildVariableSources() "+
		"because it is not an elastic beat (repo=%+v)", repo.RootImportPath))
}

// BuildVariableSources is used to explicitly define what files contain build
// variables and how to parse the values from that file. This removes ambiguity
// about where the data is sources and allows a degree of customization for
// community Beats.
//
// Default parsers are used if one is not defined.
type BuildVariableSources struct {
	// File containing the Beat version.
	BeatVersion string

	// Parses the Beat version from the BeatVersion file.
	BeatVersionParser func(data []byte) (string, error)

	// File containing the Go version to be used in cross-builds.
	GoVersion string

	// Parses the Go version from the GoVersion file.
	GoVersionParser func(data []byte) (string, error)

	// File containing the documentation branch.
	DocBranch string

	// Parses the documentation branch from the DocBranch file.
	DocBranchParser func(data []byte) (string, error)

	// File containing definition of flavors.
	FlavorsRegistry string
}

func (s *BuildVariableSources) expandVar(in string) (string, error) {
	return expandTemplate("inline", in, map[string]interface{}{
		"elastic_beats_dir": ElasticBeatsDir,
	})
}

// GetBeatVersion reads the BeatVersion file and parses the version from it.
func (s *BuildVariableSources) GetBeatVersion() (string, error) {
	file, err := s.expandVar(s.BeatVersion)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read beat version file=%v: %w", file, err)
	}

	if s.BeatVersionParser == nil {
		s.BeatVersionParser = parseBeatVersion
	}
	return s.BeatVersionParser(data)
}

// GetGoVersion reads the GoVersion file and parses the version from it.
func (s *BuildVariableSources) GetGoVersion() (string, error) {
	file, err := s.expandVar(s.GoVersion)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read go version file=%v: %w", file, err)
	}

	if s.GoVersionParser == nil {
		s.GoVersionParser = parseGoVersion
	}
	return s.GoVersionParser(data)
}

// GetFlavorsRegistry reads the flavors file and parses the list of components of it.
func (s *BuildVariableSources) GetFlavorsRegistry() (map[string][]string, error) {
	file, err := s.expandVar(s.FlavorsRegistry)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read flavors from file=%v: %w", file, err)
	}

	registry := make(map[string][]string)
	if err := yaml.Unmarshal(data, registry); err != nil {
		return nil, fmt.Errorf("failed to parse flavors: %w", err)
	}

	return registry, nil
}

// GetDocBranch reads the DocBranch file and parses the branch from it.
func (s *BuildVariableSources) GetDocBranch() (string, error) {
	file, err := s.expandVar(s.DocBranch)
	if err != nil {
		return "", err
	}

	data, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read doc branch file=%v: %w", file, err)
	}

	if s.DocBranchParser == nil {
		s.DocBranchParser = parseDocBranch
	}
	return s.DocBranchParser(data)
}

func parseBeatVersion(data []byte) (string, error) {
	matches := beatVersionRegex.FindSubmatch(data)
	if len(matches) == 2 {
		return string(matches[1]), nil
	}

	return "", errors.New("failed to parse beat version file")
}

func parseGoVersion(data []byte) (string, error) {
	return strings.TrimSpace(string(data)), nil
}

func parseDocBranch(data []byte) (string, error) {
	matches := beatDocSiteBranchRegex.FindSubmatch(data)
	if len(matches) == 2 {
		return string(matches[1]), nil
	}

	matches = beatDocBranchRegex.FindSubmatch(data)
	if len(matches) == 2 {
		return string(matches[1]), nil
	}

	return "", errors.New("failed to parse beat doc branch")
}

// --- ProjectRepoInfo

// ProjectRepoInfo contains information about the project's repo.
type ProjectRepoInfo struct {
	RootImportPath          string // Import path at the project root.
	CanonicalRootImportPath string // Pre-modules root import path (does not contain semantic import version identifier).
	RootDir                 string // Root directory of the project.
	ImportPath              string // Import path of the current directory.
	SubDir                  string // Relative path from the root dir to the current dir.
}

// IsElasticBeats returns true if the current project is
// github.com/elastic/beats.
func (r *ProjectRepoInfo) IsElasticBeats() bool {
	return r.CanonicalRootImportPath == elasticAgentImportPath
}

var (
	repoInfoValue *ProjectRepoInfo
	repoInfoErr   error
	repoInfoOnce  sync.Once
)

// GetProjectRepoInfo returns information about the repo including the root
// import path and the current directory's import path.
func GetProjectRepoInfo() (*ProjectRepoInfo, error) {
	repoInfoOnce.Do(func() {
		if isUnderGOPATH() {
			repoInfoValue, repoInfoErr = getProjectRepoInfoUnderGopath()
		} else {
			repoInfoValue, repoInfoErr = getProjectRepoInfoWithModules()
		}
	})

	return repoInfoValue, repoInfoErr
}

func isUnderGOPATH() bool {
	underGOPATH := false
	srcDirs, err := listSrcGOPATHs()
	if err != nil {
		return false
	}
	for _, srcDir := range srcDirs {
		rel, err := filepath.Rel(srcDir, CWD())
		if err != nil {
			continue
		}

		if !strings.Contains(rel, "..") {
			underGOPATH = true
		}
	}

	return underGOPATH
}

func getProjectRepoInfoWithModules() (*ProjectRepoInfo, error) {
	var (
		cwd     = CWD()
		rootDir string
		subDir  string
	)

	possibleRoot := cwd
	var errs []string
	for {
		isRoot, err := isGoModRoot(possibleRoot)
		if err != nil {
			errs = append(errs, err.Error())
		}

		if isRoot {
			rootDir = possibleRoot
			subDir, err = filepath.Rel(rootDir, cwd)
			if err != nil {
				errs = append(errs, err.Error())
			}
			break
		}

		possibleRoot = filepath.Dir(possibleRoot)
	}

	if rootDir == "" {
		return nil, fmt.Errorf("failed to find root dir of module file: %v", errs)
	}

	rootImportPath, err := gotool.GetModuleName()
	if err != nil {
		return nil, err
	}

	return &ProjectRepoInfo{
		RootImportPath:          rootImportPath,
		CanonicalRootImportPath: filepath.ToSlash(extractCanonicalRootImportPath(rootImportPath)),
		RootDir:                 rootDir,
		SubDir:                  subDir,
		ImportPath:              filepath.ToSlash(filepath.Join(rootImportPath, subDir)),
	}, nil
}

func isGoModRoot(path string) (bool, error) {
	gomodPath := filepath.Join(path, "go.mod")
	_, err := os.Stat(gomodPath)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return true, nil
}

func getProjectRepoInfoUnderGopath() (*ProjectRepoInfo, error) {
	var (
		cwd     = CWD()
		errs    []string
		rootDir string
	)

	srcDirs, err := listSrcGOPATHs()
	if err != nil {
		return nil, err
	}

	for _, srcDir := range srcDirs {
		root, err := fromDir(cwd, srcDir)
		if err != nil {
			// Try the next gopath.
			errs = append(errs, err.Error())
			continue
		}
		rootDir = filepath.Join(srcDir, root)
		break
	}

	if rootDir == "" {
		return nil, fmt.Errorf("error while determining root directory: %v", errs)
	}

	subDir, err := filepath.Rel(rootDir, cwd)
	if err != nil {
		err = errors.Unwrap(err)
		return nil, fmt.Errorf("failed to get relative path to repo root: %w", err)
	}

	rootImportPath, err := gotool.GetModuleName()
	if err != nil {
		return nil, err
	}

	return &ProjectRepoInfo{
		RootImportPath:          rootImportPath,
		CanonicalRootImportPath: filepath.ToSlash(extractCanonicalRootImportPath(rootImportPath)),
		RootDir:                 rootDir,
		SubDir:                  subDir,
		ImportPath:              filepath.ToSlash(filepath.Join(rootImportPath, subDir)),
	}, nil
}

var vcsList = []string{
	"hg",
	"git",
	"svn",
	"bzr",
}

func fromDir(dir, srcRoot string) (root string, err error) {
	// Clean and double-check that dir is in (a subdirectory of) srcRoot.
	dir = filepath.Clean(dir)
	srcRoot = filepath.Clean(srcRoot)
	if len(dir) <= len(srcRoot) || dir[len(srcRoot)] != filepath.Separator {
		return "", fmt.Errorf("directory %q is outside source root %q", dir, srcRoot)
	}

	var vcsRet string
	var rootRet string

	origDir := dir
	for len(dir) > len(srcRoot) {
		for _, vcs := range vcsList {
			if _, err := os.Stat(filepath.Join(dir, "."+vcs)); err == nil {
				root := filepath.ToSlash(dir[len(srcRoot)+1:])
				// Record first VCS we find, but keep looking,
				// to detect mistakes like one kind of VCS inside another.
				if vcsRet == "" {
					vcsRet = vcs
					rootRet = root
					continue
				}
				// Allow .git inside .git, which can arise due to submodules.
				if vcsRet == vcs && vcs == "git" {
					continue
				}
				// Otherwise, we have one VCS inside a different VCS.
				return "", fmt.Errorf("directory %q uses %s, but parent %q uses %s",
					filepath.Join(srcRoot, rootRet), vcsRet, filepath.Join(srcRoot, root), vcs)
			}
		}

		// Move to parent.
		ndir := filepath.Dir(dir)
		if len(ndir) >= len(dir) {
			// Shouldn't happen, but just in case, stop.
			break
		}
		dir = ndir
	}

	if vcsRet != "" {
		return rootRet, nil
	}

	return "", fmt.Errorf("directory %q is not using a known version control system", origDir)
}

func extractCanonicalRootImportPath(rootImportPath string) string {
	// In order to be compatible with go modules, the root import
	// path of any module at major version v2 or higher must include
	// the major version.
	// Ref: https://github.com/golang/go/wiki/Modules#semantic-import-versioning
	//
	// Thus, Beats has to include the major version as well.
	// This regex removes the major version from the import path.
	re := regexp.MustCompile(`(/v[1-9][0-9]*)$`)
	return re.ReplaceAllString(rootImportPath, "")
}

func listSrcGOPATHs() ([]string, error) {
	var (
		cwd     = CWD()
		errs    []string
		srcDirs []string
	)
	for _, gopath := range filepath.SplitList(build.Default.GOPATH) {
		gopath = filepath.Clean(gopath)

		if !strings.HasPrefix(cwd, gopath) {
			// Fixes an issue on macOS when /var is actually /private/var.
			var err error
			gopath, err = filepath.EvalSymlinks(gopath)
			if err != nil {
				errs = append(errs, err.Error())
				continue
			}
		}

		srcDirs = append(srcDirs, filepath.Join(gopath, "src"))
	}

	if len(srcDirs) == 0 {
		return srcDirs, fmt.Errorf("failed to find any GOPATH %v", errs)
	}

	return srcDirs, nil
}
