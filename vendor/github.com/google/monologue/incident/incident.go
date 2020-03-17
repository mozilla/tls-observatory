// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package incident provides access to functionality for recording and
// classifying compliance incidents.
package incident

import (
	"context"
	"fmt"

	"github.com/golang/glog"
)

// Reporter describes a mechanism for recording compliance incidents.
type Reporter interface {
	// LogUpdate records a non-violation incident with the given parameters.
	// The baseURL, summary and category fields should be stable across
	// multiple similar incidents to allow aggregation. Information that
	// varies between instances of the 'same' incident should be included in
	// the fullURL or details field.
	LogUpdate(ctx context.Context, baseURL, summary, fullURL, details string)
	LogUpdatef(ctx context.Context, baseURL, summary, fullURL, detailsFmt string, args ...interface{})

	// LogViolation records a RFC/Policy violation incident with the given parameters.
	LogViolation(ctx context.Context, baseURL, summary, fullURL, details string)
	LogViolationf(ctx context.Context, baseURL, summary, fullURL, detailsFmt string, args ...interface{})
}

// LoggingReporter implements the Reporter interface by simply emitting
// log messages.
type LoggingReporter struct {
}

// LogUpdate emits a log message for the incident details.
func (l *LoggingReporter) LogUpdate(ctx context.Context, baseURL, summary, fullURL, details string) {
	glog.Infof("%s: %s (%s)\n  %s", baseURL, summary, fullURL, details)
}

// LogViolation emits a log message for the incident details.
func (l *LoggingReporter) LogViolation(ctx context.Context, baseURL, summary, fullURL, details string) {
	glog.Errorf("%s: %s (%s)\n  %s", baseURL, summary, fullURL, details)
}

// LogUpdatef emits a log message for the incident details, formatting parameters along the way.
func (l *LoggingReporter) LogUpdatef(ctx context.Context, baseURL, summary, fullURL, detailsFmt string, args ...interface{}) {
	glog.Infof("%s: %s (%s)\n  %s", baseURL, summary, fullURL, fmt.Sprintf(detailsFmt, args...))
}

// LogUpdatef emits a log message for the incident details, formatting parameters along the way.
func (l *LoggingReporter) LogViolationf(ctx context.Context, baseURL, summary, fullURL, detailsFmt string, args ...interface{}) {
	glog.Errorf("%s: %s (%s)\n  %s", baseURL, summary, fullURL, fmt.Sprintf(detailsFmt, args...))
}
