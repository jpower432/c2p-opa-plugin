package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	cp "github.com/otiai10/copy"

	"github.com/oscal-compass/compliance-to-policy-go/v2/logging"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

var (
	_      policy.Provider = (*Plugin)(nil)
	logger hclog.Logger    = logging.NewPluginLogger()
)

func Logger() hclog.Logger {
	return logger
}

type Plugin struct {
	config Config
}

func NewPlugin() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Configure(m map[string]string) error {
	if err := mapstructure.Decode(m, &p.config); err != nil {
		return errors.New("error decoding configuration")
	}
	return p.config.Validate()
}

func (p *Plugin) Generate(pl policy.Policy) error {
	policyConfig := map[string]map[string]string{}
	outputDir := p.config.PolicyOutput
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}

	for _, rule := range pl {
		parameterMap := make(map[string]string)
		for _, prm := range rule.Rule.Parameters {
			parameterMap[prm.ID] = prm.Value
		}
		policyConfig[rule.Rule.ID] = parameterMap
		// Copy over in-scope policies checks for the assessment
		for _, check := range rule.Checks {
			origfilePath := filepath.Join(p.config.PolicyTemplates, fmt.Sprintf("%s.rego", check.ID))
			destfilePath := filepath.Join(p.config.PolicyOutput, fmt.Sprintf("%s.rego", check.ID))
			if err := cp.Copy(origfilePath, destfilePath); err != nil {
				return err
			}
		}
	}

	policyConfigData, err := json.MarshalIndent(policyConfig, "", " ")
	if err != nil {
		return err
	}

	configFileName := filepath.Join(p.config.PolicyOutput, "config.json")
	if err := os.WriteFile(configFileName, policyConfigData, 0644); err != nil {
		return fmt.Errorf("failed to write policy config to %s: %w", configFileName, err)
	}

	return nil
}

func (p *Plugin) GetResults(pl policy.Policy) (policy.PVPResult, error) {
	var observations []policy.ObservationByCheck
	for _, rule := range pl {
		for _, check := range rule.Checks {
			name := check.ID
			resultsFilePath := filepath.Join(p.config.PolicyResults, fmt.Sprintf("%s.json", name))
			file, err := os.ReadFile(resultsFilePath)
			if err != nil {
				return policy.PVPResult{}, err
			}
			var opaResults map[string]interface{}
			if err := json.Unmarshal(file, &opaResults); err != nil {
				return policy.PVPResult{}, fmt.Errorf("failed to unmarshal opa results for %s: %w", name, err)
			}

			observation := policy.ObservationByCheck{
				Title:       rule.Rule.ID,
				CheckID:     name,
				Description: fmt.Sprintf("Observation of check %s", name),
				Methods:     []string{"TEST-AUTOMATED"},
				Collected:   time.Now(),
				Subjects:    []policy.Subject{},
			}
			normalizedOPAResults := normalizeOPAResult(opaResults)
			for _, result := range normalizedOPAResults {
				observation.Subjects = append(observation.Subjects, results2Subject(result))
			}
			observations = append(observations, observation)
		}
	}
	result := policy.PVPResult{
		ObservationsByCheck: observations,
	}
	return result, nil
}

func results2Subject(results normalizedOPAResult) policy.Subject {
	subject := policy.Subject{
		Title:       results.EvaluatedResourceName,
		ResourceID:  results.EvaluatedResourceID,
		Type:        results.EvaluatedResourceType,
		Result:      mapResults(results),
		EvaluatedOn: time.Now(),
		Reason:      results.Reason,
	}
	return subject
}
