package mozillaEvaluationWorker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/mozilla/nothing/connection"
)

type ComplianceOutput struct {
	Target       string    `json:"target"`
	Utctimestamp time.Time `json:"utctimestamp"`
	Level        string    `json:"level"`
	Compliance   bool      `json:"compliance"`
	Failures     struct {
		Modern       []string `json:"modern"`
		Intermediate []string `json:"intermediate"`
		Old          []string `json:"old"`
		Fubar        []string `json:"fubar"`
	} `json:"failures"`
	TargetLevel string `json:"target_level"`
}

func TestOutput(t *testing.T) {
	target := "www.mozilla.org"
	cipherscanpath := "../../cipherscan/cipherscan"

	goodOut, err := getAnalyzeScriptOutput(target)
	if err != nil {
		t.Error("Could not get Analyze script output")
		t.Error(err)
		t.Fail()
	}

	out, err := connection.Connect(target, cipherscanpath)
	if err != nil {
		t.Error("Could not get cipherscan output")
		t.Error(err)
		t.Fail()
	}

	out, err = Evaluate(out)
	if err != nil {
		t.Error("Could not evaluate cipherscan output.")
		t.Error(err)
		t.Fail()
	}

	var results EvaluationResults

	err = json.Unmarshal(out, &results)
	if err != nil {
		t.Error("Could not unmarshal results from json")
		t.Error(err)
		t.Fail()
	}

	if results.Level != goodOut.Level {
		t.Error(fmt.Sprintf("Got %s compliance level instead of expected %s level", results.Level, goodOut.Level))
		t.Fail()
	}
}

func getAnalyzeScriptOutput(target string) (ComplianceOutput, error) {

	var out ComplianceOutput

	cmd := "../../cipherscan/analyze.py -t " + target + " -j"
	fmt.Println(cmd)
	comm := exec.Command("bash", "-c", cmd)
	var outb bytes.Buffer
	var stderr bytes.Buffer
	comm.Stdout = &outb
	comm.Stderr = &stderr
	err := comm.Run()
	// if err != nil {
	// 	return ComplianceOutput{}, err
	// }

	err = json.Unmarshal([]byte(outb.String()), &out)
	if err != nil {
		return ComplianceOutput{}, err
	}

	return out, nil
}
