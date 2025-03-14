// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package transpiler

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/mapstr"
	corecomp "github.com/elastic/elastic-agent/internal/pkg/core/composable"
)

func TestVars_Replace(t *testing.T) {
	vars := mustMakeVarsWithDefault(map[string]interface{}{
		"un-der_score": map[string]interface{}{
			"key1":      "data1",
			"key2":      "data2",
			"with-dash": "dash-value",
			"list": []string{
				"array1",
				"array2",
			},
			"with/slash": "some/path",
			"dict": map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
			},
		},
		"other": map[string]interface{}{
			"data": "info",
		},
		"special": map[string]interface{}{
			"key1": "$1$$2",
			"key2": "1$2$$",
			"key3": "${abcd}",
			"key4": "$${abcd}",
			"key5": "${",
			"key6": "$${",
		},
	}, "other")
	tests := []struct {
		Input   string
		Result  Node
		Error   bool
		NoMatch bool
	}{
		{
			"${un-der_score.key1}",
			NewStrVal("data1"),
			false,
			false,
		},
		{
			"${un-der_score.with-dash}",
			NewStrVal("dash-value"),
			false,
			false,
		},
		{
			"${un-der_score.missing}",
			NewStrVal(""),
			false,
			true,
		},
		{
			"${un-der_score.missing|un-der_score.key2}",
			NewStrVal("data2"),
			false,
			false,
		},
		{
			"${un-der_score.missing|un-der_score.missing2|other.data}",
			NewStrVal("info"),
			false,
			false,
		},
		{
			// data will be resolved to other.data since 'other' is the default provider
			// set at variable creation (see mustMakeVarsWithDefault call)
			"${un-der_score.missing|un-der_score.missing2|data}",
			NewStrVal("info"),
			false,
			false,
		},
		{
			"${un-der_score.missing|'fallback'}",
			NewStrVal("fallback"),
			false,
			false,
		},
		{
			`${un-der_score.missing|||||||||"fallback"}`,
			NewStrVal("fallback"),
			false,
			false,
		},
		{
			`${"with:colon"}`,
			NewStrVal("with:colon"),
			false,
			false,
		},
		{
			`${"direct"}`,
			NewStrVal("direct"),
			false,
			false,
		},
		{
			`${un-der_score.missing|'with:colon'}`,
			NewStrVal("with:colon"),
			false,
			false,
		},
		{
			`${un-der_score.}`,
			NewStrVal(""),
			true,
			false,
		},
		{
			`${un-der_score.missing|"oth}`,
			NewStrVal(""),
			true,
			false,
		},
		{
			`${un-der_score.missing`,
			NewStrVal(""),
			true,
			false,
		},
		{
			`${un-der_score.missing  ${other}`,
			NewStrVal(""),
			true,
			false,
		},
		{
			`${}`,
			NewStrVal(""),
			true,
			false,
		},
		{
			"around ${un-der_score.key1} the var",
			NewStrVal("around data1 the var"),
			false,
			false,
		},
		{
			"multi ${un-der_score.key1} var ${ un-der_score.missing |     un-der_score.key2      } around",
			NewStrVal("multi data1 var data2 around"),
			false,
			false,
		},
		{
			`multi ${un-der_score.key1} var ${  un-der_score.missing|  'other"s with space'  } around`,
			NewStrVal(`multi data1 var other"s with space around`),
			false,
			false,
		},
		{
			`start ${  un-der_score.missing|  'others | with space'  } end`,
			NewStrVal(`start others | with space end`),
			false,
			false,
		},
		{
			`start ${  un-der_score.missing|  'other\'s with space'  } end`,
			NewStrVal(`start other's with space end`),
			false,
			false,
		},
		{
			`${un-der_score.list}`,
			NewList([]Node{
				NewStrVal("array1"),
				NewStrVal("array2"),
			}),
			false,
			false,
		},
		{
			`${un-der_score.with/slash}`,
			NewStrVal(`some/path`),
			false,
			false,
		},
		{
			`list inside string ${un-der_score.list} strings array`,
			NewStrVal(`list inside string [array1,array2] strings array`),
			false,
			false,
		},
		{
			`${un-der_score.dict}`,
			NewDict([]Node{
				NewKey("key1", NewStrVal("value1")),
				NewKey("key2", NewStrVal("value2")),
			}),
			false,
			false,
		},
		{
			`dict inside string ${un-der_score.dict} strings dict`,
			NewStrVal(`dict inside string {key1:value1},{key2:value2} strings dict`),
			false,
			false,
		},
		{
			`start $${keep} ${un-der_score.key1} $${un-der_score.key1}`,
			NewStrVal(`start ${keep} data1 ${un-der_score.key1}`),
			false,
			false,
		},
		{
			`${special.key1}`,
			NewStrVal("$1$$2"),
			false,
			false,
		},
		{
			`${special.key2}`,
			NewStrVal("1$2$$"),
			false,
			false,
		},
		{
			`${special.key3}`,
			NewStrVal("${abcd}"),
			false,
			false,
		},
		{
			`${special.key4}`,
			NewStrVal("$${abcd}"),
			false,
			false,
		},
		{
			`${special.key5}`,
			NewStrVal("${"),
			false,
			false,
		},
		{
			`${special.key6}`,
			NewStrVal("$${"),
			false,
			false,
		},
	}
	for _, test := range tests {
		t.Run(test.Input, func(t *testing.T) {
			res, err := vars.Replace(test.Input)
			if test.Error {
				assert.Error(t, err)
			} else if test.NoMatch {
				assert.ErrorIs(t, err, ErrNoMatch)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.Result, res)
			}
		})
	}
}

func TestVars_ReplaceWithProcessors(t *testing.T) {
	processers := Processors{
		{
			"add_fields": map[string]interface{}{
				"dynamic": "added",
			},
		},
	}
	vars, err := NewVarsWithProcessors(
		"",
		map[string]interface{}{
			"testing": map[string]interface{}{
				"key1": "data1",
			},
			"dynamic": map[string]interface{}{
				"key1": "dynamic1",
				"list": []string{
					"array1",
					"array2",
				},
				"dict": map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			},
		},
		"dynamic",
		processers,
		nil, "testing")
	require.NoError(t, err)

	res, err := vars.Replace("${testing.key1}")
	require.NoError(t, err)
	assert.Equal(t, NewStrVal("data1"), res)

	res, err = vars.Replace("${key1}")
	require.NoError(t, err)
	assert.Equal(t, NewStrVal("data1"), res)

	res, err = vars.Replace("${dynamic.key1}")
	require.NoError(t, err)
	assert.Equal(t, NewStrValWithProcessors("dynamic1", processers), res)

	res, err = vars.Replace("${other.key1|dynamic.key1}")
	require.NoError(t, err)
	assert.Equal(t, NewStrValWithProcessors("dynamic1", processers), res)

	res, err = vars.Replace("${dynamic.list}")
	require.NoError(t, err)
	assert.Equal(t, processers, res.Processors())
	assert.Equal(t, NewListWithProcessors([]Node{
		NewStrVal("array1"),
		NewStrVal("array2"),
	}, processers), res)

	res, err = vars.Replace("${dynamic.dict}")
	require.NoError(t, err)
	assert.Equal(t, processers, res.Processors())
	assert.Equal(t, NewDictWithProcessors([]Node{
		NewKey("key1", NewStrVal("value1")),
		NewKey("key2", NewStrVal("value2")),
	}, processers), res)
}

func TestVars_ReplaceWithFetchContextProvider(t *testing.T) {
	processers := Processors{
		{
			"add_fields": map[string]interface{}{
				"dynamic": "added",
			},
		},
	}

	mockFetchProvider, err := MockContextProviderBuilder()
	require.NoError(t, err)

	fetchContextProviders := mapstr.M{
		"kubernetes_secrets": mockFetchProvider,
	}
	vars, err := NewVarsWithProcessors(
		"id",
		map[string]interface{}{
			"testing": map[string]interface{}{
				"key1": "data1",
			},
			"dynamic": map[string]interface{}{
				"key1": "dynamic1",
				"list": []string{
					"array1",
					"array2",
				},
				"dict": map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			},
		},
		"dynamic",
		processers,
		fetchContextProviders, "")
	require.NoError(t, err)

	res, err := vars.Replace("${testing.key1}")
	require.NoError(t, err)
	assert.Equal(t, NewStrVal("data1"), res)

	res, err = vars.Replace("${dynamic.key1}")
	require.NoError(t, err)
	assert.Equal(t, NewStrValWithProcessors("dynamic1", processers), res)

	res, err = vars.Replace("${other.key1|dynamic.key1}")
	require.NoError(t, err)
	assert.Equal(t, NewStrValWithProcessors("dynamic1", processers), res)

	res, err = vars.Replace("${dynamic.list}")
	require.NoError(t, err)
	assert.Equal(t, processers, res.Processors())
	assert.Equal(t, NewListWithProcessors([]Node{
		NewStrVal("array1"),
		NewStrVal("array2"),
	}, processers), res)

	res, err = vars.Replace("${dynamic.dict}")
	require.NoError(t, err)
	assert.Equal(t, processers, res.Processors())
	assert.Equal(t, NewDictWithProcessors([]Node{
		NewKey("key1", NewStrVal("value1")),
		NewKey("key2", NewStrVal("value2")),
	}, processers), res)

	res, err = vars.Replace("${kubernetes_secrets.test_namespace.testing_secret.secret_value}")
	require.NoError(t, err)
	assert.Equal(t, NewStrVal("mockedFetchContent"), res)
}

type contextProviderMock struct {
}

// MockContextProviderBuilder builds the mock context provider.
func MockContextProviderBuilder() (corecomp.ContextProvider, error) {
	return &contextProviderMock{}, nil
}

func (p *contextProviderMock) Fetch(key string) (string, bool) {
	return "mockedFetchContent", true
}

func (p *contextProviderMock) Run(ctx context.Context, comm corecomp.ContextProviderComm) error {
	return nil
}
