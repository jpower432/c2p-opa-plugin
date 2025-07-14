package server

import (
	"testing"

	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
	"github.com/stretchr/testify/require"
)

func Test_Results2Subject(t *testing.T) {
	normalizedResults := NormalizedOPAResult{
		Allowed:               false,
		Reason:                "Policy denied due to violations.",
		EvaluatedResourceType: "resource",
		EvaluatedResourceID:   "github.com/example/demo@main",
		EvaluatedResourceName: "github.com/example/demo@main",
		Violations: []string{
			"Branch protection for 'main' requires pull request reviews but has less than the configured minimum of 1 required approving reviews.",
		},
		RawResult: "",
	}

	expectedSubj := policy.Subject{
		Title:      "github.com/example/demo@main",
		Type:       "resource",
		ResourceID: "github.com/example/demo@main",
		Result:     policy.ResultFail,
		Reason: "Policy denied due to violations. Violations: Branch protection for 'main' requires pull request reviews " +
			"but has less than the configured minimum of 1 required approving reviews.",
	}

	subject := results2Subject(normalizedResults)
	require.Equal(t, expectedSubj.Type, subject.Type)
	require.Equal(t, expectedSubj.Reason, subject.Reason)
	require.Equal(t, expectedSubj.Title, subject.Title)
	require.Equal(t, expectedSubj.Result, subject.Result)
}
