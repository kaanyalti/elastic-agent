package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/go-ucfg"
)

type ActionPolicyChangeData struct {
	Policy map[string]interface{} `json:"policy" yaml:"policy,omitempty"`
}

type action struct {
	Data ActionPolicyChangeData `json:"data" yaml:"data"`
}

func main() {
	base := "/Users/kaanyalti/repos/elastic-agent-worktrees/fix/5871_add_redaction_keys/internal/pkg/diagnostics/experiment"
	fileName := "testfile"
	filePath := filepath.Join(base, "withmarkers", fileName+".yaml")
	contents, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read policy file: %v\n", err)
		os.Exit(1)
	}
	var policy map[string]interface{}
	if err := yaml.Unmarshal(contents, &policy); err != nil {
		fmt.Fprintf(os.Stderr, "failed to unmarshal policy YAML: %v\n", err)
		os.Exit(1)
	}
	act := action{Data: ActionPolicyChangeData{Policy: policy}}
	cfg, err := config.NewConfigFrom(act.Data.Policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse the configuration from the policy: %v\n", err)
		os.Exit(1)
	}

	secretsRedactor := SecretsRedactor{}
	secretsRedactor.AddSecretMarkers(cfg)

	agentMap := make(map[string]interface{})
	if err := cfg.Agent.Unpack(&agentMap); err != nil {
		fmt.Fprintf(os.Stderr, "failed to unpack c.Agent: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("================================================")
	redactMap(os.Stdout, agentMap, false)
	fmt.Println("================================================")

	yamlBytes, err := yaml.Marshal(agentMap)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal agentMap to YAML: %v\n", err)
		os.Exit(1)
	}
	// fmt.Println("c.Agent as YAML:")
	// fmt.Println(string(yamlBytes))

	// Write yamlBytes to a file, overwriting if it already exists
	outBase := filepath.Join(base, "output")
	outputFile := filepath.Join(outBase, fileName+"-out.yaml")
	if err := os.WriteFile(outputFile, yamlBytes, 0777); err != nil {
		fmt.Fprintf(os.Stderr, "failed to write agentMap to file: %v\n", err)
		os.Exit(1)
	} else {
		fmt.Printf("agentMap YAML written to %s\n", outputFile)
	}
}

func redactKey(k string) bool {
	// "routekey" shouldn't be redacted.
	// Add any other exceptions here.
	if k == "routekey" {
		return false
	}

	k = strings.ToLower(k)
	return strings.Contains(k, "auth") ||
		strings.Contains(k, "certificate") ||
		strings.Contains(k, "passphrase") ||
		strings.Contains(k, "password") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "key") ||
		strings.Contains(k, "secret")
}

func redactWithMarker[K comparable](inputMap map[K]interface{}, marker string, keyFound bool) map[K]interface{} {
	keyToRedact := strings.TrimPrefix(marker, "mark_redact_")
	fmt.Println("keyToRedact: ", keyToRedact)
	for rootKey, rootValue := range inputMap {
		keyString, ok := any(rootKey).(string)
		if ok {
			if keyString == keyToRedact {
				keyFound = true
			}
		}

		fmt.Printf("keyString: %s, keyToRedact: %s\n", keyString, keyToRedact)
		switch cast := rootValue.(type) {
		case map[string]interface{}:
			redactWithMarker(cast, marker, keyFound)
		case map[interface{}]interface{}:
			redactWithMarker(cast, marker, keyFound)
		case map[int]interface{}:
			redactWithMarker(cast, marker, keyFound)
		case []interface{}:
			for i, value := range cast {
				switch m := value.(type) {
				case map[string]interface{}:
					cast[i] = redactWithMarker(m, marker, keyFound)
				case map[interface{}]interface{}:
					cast[i] = redactWithMarker(m, marker, keyFound)
				case map[int]interface{}:
					cast[i] = redactWithMarker(m, marker, keyFound)
				}
			}
		case string:
			if keyFound {
				inputMap[rootKey] = "REDACTED"
			}
		}
		if keyFound {
			break
		}
	}
	return inputMap
}

func redactMap[K comparable](errOut io.Writer, inputMap map[K]interface{}, sliceElem bool) map[K]interface{} {
	if inputMap == nil {
		return nil
	}

	redactionMarkers := []string{}
	for rootKey, rootValue := range inputMap {
		if keyString, ok := any(rootKey).(string); ok {
			// Find siblings that have the redaction marker.
			if strings.Contains(keyString, "mark_redact_") {
				redactionMarkers = append(redactionMarkers, keyString)
			}
		}
		if rootValue != nil {
			switch cast := rootValue.(type) {
			case map[string]interface{}:
				rootValue = redactMap(errOut, cast, sliceElem)
			case map[interface{}]interface{}:
				rootValue = redactMap(errOut, cast, sliceElem)
			case map[int]interface{}:
				rootValue = redactMap(errOut, cast, sliceElem)
			case []interface{}:
				// Recursively process each element in the slice so that we also walk
				// through lists (e.g. inputs[4].streams[0]). This is required to
				// reach redaction markers that are inside array items. Set SliceElem to true
				// to avoid global redaction of array elements.
				for i, value := range cast {
					switch m := value.(type) {
					case map[string]interface{}:
						cast[i] = redactMap(errOut, m, true)
					case map[interface{}]interface{}:
						cast[i] = redactMap(errOut, m, true)
					case map[int]interface{}:
						cast[i] = redactMap(errOut, m, true)
					}
				}
				rootValue = cast
			case string:
				if keyString, ok := any(rootKey).(string); ok {
					if redactKey(keyString) && !sliceElem {
						rootValue = "REDACTED"
					}
				}
			default:
				// in cases where we got some weird kind of map we couldn't parse, print a warning
				if reflect.TypeOf(rootValue).Kind() == reflect.Map {
					fmt.Fprintf(errOut, "[WARNING]: file may be partly redacted, could not cast value %v of type %T", rootKey, rootValue)
				}

			}
		}
		inputMap[rootKey] = rootValue
	}

	cfgToRedact := ucfg.MustNewFrom(inputMap, ucfg.PathSep("."))
	for _, redactionMarker := range redactionMarkers {
		keyToRedact := strings.TrimPrefix(redactionMarker, "mark_redact_")
		sourcePath := keyToRedact + ".kind.stringvalue"               // structure in unpacked ucfg mapstr
		ok, err := cfgToRedact.Has(sourcePath, -1, ucfg.PathSep(".")) // first check if the nested field exists
		if err != nil {
			fmt.Fprintf(errOut, "failed to check if %s exists: %v\n", sourcePath, err)
		}
		if ok {
			cfgToRedact.SetString(sourcePath, -1, "REDACTED", ucfg.PathSep(".")) // if the nested field exists, redact it
		} else {
			cfgToRedact.SetString(keyToRedact, -1, "REDACTED", ucfg.PathSep(".")) // if the nested field does not exist, then the value is in the parent field
		}
	}

	cfgToRedact.Unpack(&inputMap)

	return inputMap
}

type SecretsRedactor struct {
}

func (r *SecretsRedactor) AddSecretMarkers(cfg *config.Config) error {
	secretPaths, err := r.getSecretPaths(cfg)
	if err != nil {
		return err
	}

	return r.addSecretMarkers(cfg, secretPaths)
}

func (r *SecretsRedactor) getSecretPaths(cfg *config.Config) ([]string, error) {
	if !cfg.Agent.HasField("secret_paths") {
		return nil, errors.New("secret_paths field not found")
	}

	secretPaths, err := cfg.Agent.Child("secret_paths", -1)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret_paths: %w", err)
	}

	if !secretPaths.IsArray() {
		return nil, fmt.Errorf("secret_paths is not an array: %v", secretPaths)
	}

	res := []string{}
	if err := secretPaths.Unpack(&res); err != nil {
		return nil, fmt.Errorf("failed to unpack secret_paths: %w", err)
	}

	return res, nil
}

func (r *SecretsRedactor) addSecretMarkers(cfg *config.Config, secretPaths []string) error {
	var aggregateError error

	for _, sp := range secretPaths {
		ok, err := cfg.Agent.Has(sp, -1, ucfg.PathSep("."))
		if err != nil {
			aggregateError = errors.Join(aggregateError, fmt.Errorf("failed to check if %s exists: %w", sp, err))
			continue
		}

		if !ok {
			aggregateError = errors.Join(aggregateError, fmt.Errorf("secret path %s does not exist", sp))
			continue
		}

		lastPathSep := strings.LastIndex(sp, ".")
		parentPath := sp[:lastPathSep]
		keyName := sp[lastPathSep+1:]

		secretKeyName := "mark_redact_" + keyName
		secretKeyPath := parentPath + "." + secretKeyName

		if err := cfg.Agent.SetBool(secretKeyPath, -1, true, ucfg.PathSep(".")); err != nil {
			aggregateError = errors.Join(aggregateError, fmt.Errorf("failed to set %s: %w", secretKeyPath, err))
			continue
		}
	}

	return aggregateError
}
