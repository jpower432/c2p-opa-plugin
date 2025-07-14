package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/go-hclog"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/oscal-compass/compliance-to-policy-go/v2/logging"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
)

var (
	_           policy.Provider = (*Plugin)(nil)
	logger      hclog.Logger    = logging.NewPluginLogger()
	regoVersion                 = ast.RegoV1
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
	composer := NewComposer(p.config.PolicyTemplates, p.config.PolicyOutput)
	if err := composer.GeneratePolicySet(pl); err != nil {
		return fmt.Errorf("error generating policies: %w", err)
	}

	if p.config.Bundle != "" {
		logger.Info(fmt.Sprintf("Creating policy bundle at %s", p.config.Bundle))
		if err := composer.Bundle(context.Background(), p.config); err != nil {
			return fmt.Errorf("error creating policy bundle: %w", err)
		}
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

			var opaResult output
			if err := json.Unmarshal(file, &opaResult); err != nil {
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
			normalizedOPAResults := NormalizeOPAResult(opaResult.Result)
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

func results2Subject(results NormalizedOPAResult) policy.Subject {
	subject := policy.Subject{
		Title:      results.EvaluatedResourceName,
		ResourceID: results.EvaluatedResourceID,
		Type:       results.EvaluatedResourceType,
		Result:     mapResults(results),
		// TODO: This is not really representative of when the policy was executing.
		// It may require additional decision metadata to accomplish this.
		EvaluatedOn: time.Now(),
		Reason:      results.Reason,
	}

	if len(results.Violations) > 0 {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("%s\nViolations:", subject.Reason))
		for _, violation := range results.Violations {
			sb.WriteString(fmt.Sprintf("\n%s", violation))
		}
		subject.Reason = sb.String()
	}

	return subject
}
