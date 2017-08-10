package metrics

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
)

type Sender struct {
	cloudwatchSvc *cloudwatch.CloudWatch
}

func NewSender() (*Sender, error) {
	sess, err := session.NewSession()
	if err != nil {
		return nil, fmt.Errorf("Could not create AWS session: %s", err)
	}
	return &Sender{cloudwatch.New(sess)}, nil
}

// NewScan informs Cloudwatch that a new scan has been created
func (sender *Sender) NewScan() {
	sender.cloudwatchSvc.PutMetricData(&cloudwatch.PutMetricDataInput{
		MetricData: []*cloudwatch.MetricDatum{
			&cloudwatch.MetricDatum{
				MetricName: aws.String("NewScans"),
				Unit:       aws.String(cloudwatch.StandardUnitNone),
				Value:      aws.Float64(1.0),
				Dimensions: []*cloudwatch.Dimension{},
			},
		},
		Namespace: aws.String("tls-observatory"),
	})
}

// NewCertificate informs Cloudwatch that a new certificate has been created
func (sender *Sender) NewCertificate() {
	sender.cloudwatchSvc.PutMetricData(&cloudwatch.PutMetricDataInput{
		MetricData: []*cloudwatch.MetricDatum{
			&cloudwatch.MetricDatum{
				MetricName: aws.String("NewCertificates"),
				Unit:       aws.String(cloudwatch.StandardUnitNone),
				Value:      aws.Float64(1.0),
				Dimensions: []*cloudwatch.Dimension{},
			},
		},
		Namespace: aws.String("tls-observatory"),
	})
}
