package server

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_NormalizedOPAResults(t *testing.T) {
	exmpResults := `{
  "result": [
    {
      "expressions": [
        {
          "value": {
            "allow": false,
            "evaluation_resource_id": "github.com/example/demo@main",
            "evaluation_resource_name": "github.com/example/demo@main",
            "evaluation_resource_type": "resource",
            "policy_id": "my-policy",
            "has_pull_request_rule": true,
            "main_branch_min_approvals": "1",
            "violation": {
              "Branch protection for 'main' requires pull request reviews but has less than the configured minimum of 1 required approving reviews.": true
            }
          },
          "text": "data.branch_protection",
          "location": {
            "row": 1,
            "col": 1
          }
        }
      ]
    }
  ]
}
`
	var opaResult output
	err := json.Unmarshal([]byte(exmpResults), &opaResult)
	require.NoError(t, err)

	expectedResults := []NormalizedOPAResult{
		{
			Allowed:               false,
			PolicyId:              "my-policy",
			Reason:                "Policy denied due to violations.",
			EvaluatedResourceType: "resource",
			EvaluatedResourceID:   "github.com/example/demo@main",
			EvaluatedResourceName: "github.com/example/demo@main",
			Violations: []string{
				"Branch protection for 'main' requires pull request reviews but has less than the configured minimum of 1 required approving reviews.",
			},
			RawResult: opaResult.Result,
		},
	}

	results := NormalizeOPAResult(opaResult.Result)
	require.Equal(t, expectedResults, results)

}
