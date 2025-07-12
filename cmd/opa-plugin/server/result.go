package server

import (
	"fmt"
	"strings"

	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

// Assisted by: Gemini 2.5 Flash

// NormalizedOPAResult represents the consistent structure your application expects
// from any OPA policy decision.
type normalizedOPAResult struct {
	Allowed         bool     `json:"allowed"`
	Reason          string   `json:"reason,omitempty"`
	Violations      []string `json:"violations,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"` // Example: for audit policies

	// New fields for evaluated resource information
	EvaluatedResourceID   string `json:"evaluated_resource_id,omitempty"`
	EvaluatedResourceType string `json:"evaluated_resource_type,omitempty"`
	EvaluatedResourceName string `json:"evaluated_resource_name,omitempty"`

	// Add any other fields you want to standardize
	Metadata  map[string]interface{} `json:"metadata,omitempty"` // For any extra, unstructured info
	Error     string                 `json:"error,omitempty"`
	RawResult interface{}            `json:"-"` // Keep original for debugging/logging, but don't marshal
}

// NormalizeOPAResult converts an OPA decision.Result (interface{}) into a consistent NormalizedOPAResult struct.
func normalizeOPAResult(rawResult map[string]interface{}) []normalizedOPAResult {
	normalized := normalizedOPAResult{
		Allowed:   false, // Default to denied/not allowed
		Reason:    "No decision or explicitly denied by policy.",
		RawResult: rawResult,
	}

	if rawResult == nil {
		normalized.Reason = "OPA query returned no result (undefined)."
		return []normalizedOPAResult{normalized}
	}

	var normalizedResults []normalizedOPAResult
	expressions := rawResult["results"]
	for _, expression := range expressions.([]interface{}) {
		expressionMap, ok := expression.(map[string]interface{})
		if !ok {
			continue
		}
		value := expressionMap["value"]
		valueMap, ok := value.(map[string]interface{})
		if !ok {
			continue
		}
		if allowed, ok := valueMap["allowed"].(bool); ok {
			normalized.Allowed = allowed
			if allowed {
				normalized.Reason = "Policy allowed access."
			} else {
				normalized.Reason = "Policy explicitly denied access."
			}
		}

		if violations, ok := valueMap["violation"].([]interface{}); ok {
			normalized.Violations = make([]string, len(violations))
			for i, v := range violations {
				if s, isString := v.(string); isString {
					normalized.Violations[i] = s
				} else {
					normalized.Violations[i] = fmt.Sprintf("%v", v) // Convert non-strings to string
				}
			}
			if len(normalized.Violations) > 0 {
				normalized.Allowed = false                             // If violations exist, typically not allowed
				if !strings.Contains(normalized.Reason, "violation") { // Avoid redundant messages
					normalized.Reason = "Policy denied due to violations."
				}
			}
		}

		if errorMsg, ok := valueMap["error"].(string); ok {
			normalized.Error = errorMsg
			normalized.Allowed = false // An explicit error usually means not allowed
			normalized.Reason = fmt.Sprintf("Policy reported an error: %s", errorMsg)
		}

		// Optionally gave resource information if available
		if resourceID, ok := valueMap["evaluated_resource_id"].(string); ok {
			normalized.EvaluatedResourceID = resourceID
		}
		if resourceType, ok := valueMap["evaluated_resource_type"].(string); ok {
			normalized.EvaluatedResourceType = resourceType
		}
		if resourceName, ok := valueMap["evaluated_resource_name"].(string); ok {
			normalized.EvaluatedResourceName = resourceName
		}

		// Capture any other fields into Metadata
		normalized.Metadata = make(map[string]interface{})
		for k, v := range rawResult {
			switch k {
			case "allowed", "reason", "violations", "recommendations":
				// These are already handled
			default:
				normalized.Metadata[k] = v
			}
		}

		// If we found 'allowed' in the map, and no violations, default reason is "allowed"
		if normalized.Allowed && len(normalized.Violations) == 0 && normalized.Reason == "No decision or explicitly denied by policy." {
			normalized.Reason = "Policy allowed access."
		}
		normalizedResults = append(normalizedResults, normalized)
	}

	return normalizedResults
}

func mapResults(results normalizedOPAResult) policy.Result {
	if len(results.Violations) == 0 && results.Allowed && results.Error != "" {
		return policy.ResultPass
	}

	if results.Error != "" {
		return policy.ResultError
	}
	return policy.ResultFail
}
