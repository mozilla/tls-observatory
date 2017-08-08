package metrics

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
)

// NewScan informs Cloudwatch that a new scan has been created
func NewScan(cloudwatchSvc *cloudwatch.CloudWatch) {
	cloudwatchSvc.PutMetricData(&cloudwatch.PutMetricDataInput{
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
func NewCertificate(cloudwatchSvc *cloudwatch.CloudWatch) {
	cloudwatchSvc.PutMetricData(&cloudwatch.PutMetricDataInput{
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
