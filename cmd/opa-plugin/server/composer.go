package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/v1/compile"
	"github.com/oscal-compass/compliance-to-policy-go/v2/policy"
	cp "github.com/otiai10/copy"
)

type Composer struct {
	policiesTemplates string
	policyOutput      string
}

func NewComposer(policiesTemplates string, output string) *Composer {
	return &Composer{
		policiesTemplates: policiesTemplates,
		policyOutput:      output,
	}
}

func (c *Composer) GetPoliciesDir() string {
	return c.policiesTemplates
}

func (c *Composer) Bundle(ctx context.Context, config Config) error {
	buf := bytes.NewBuffer(nil)

	compiler := compile.New().
		WithRevision(config.BundleRevision).
		WithOutput(buf).
		WithPaths(config.PolicyOutput)

	compiler = compiler.WithRegoVersion(regoVersion)

	err := compiler.Build(ctx)
	if err != nil {
		return err
	}

	out, err := os.Create(config.Bundle)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, buf)
	if err != nil {
		return err
	}
	return nil
}

func (c *Composer) GeneratePolicySet(pl policy.Policy) error {
	parameterMap := map[string]string{}
	outputDir := c.policyOutput
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}

	for _, rule := range pl {
		for _, prm := range rule.Rule.Parameters {
			parameterMap[prm.ID] = prm.Value
		}
		// Copy over in-scope policies checks for the assessment
		for _, check := range rule.Checks {
			origfilePath := filepath.Join(c.policiesTemplates, fmt.Sprintf("%s.rego", check.ID))
			destfilePath := filepath.Join(outputDir, fmt.Sprintf("%s.rego", check.ID))
			if err := cp.Copy(origfilePath, destfilePath); err != nil {
				return err
			}
		}
	}

	policyConfigData, err := json.MarshalIndent(parameterMap, "", " ")
	if err != nil {
		return err
	}

	configFileName := filepath.Join(outputDir, "data.json")
	if err := os.WriteFile(configFileName, policyConfigData, 0644); err != nil {
		return fmt.Errorf("failed to write policy config to %s: %w", configFileName, err)
	}

	return nil
}
