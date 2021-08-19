package outputs

import (
	"context"
	"fmt"
	"log"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/falcosecurity/falcosidekick/types"
	"github.com/google/uuid"
	wgpolicy "github.com/kubernetes-sigs/wg-policy-prototypes/policy-report/kube-bench-adapter/pkg/apis/wgpolicyk8s.io/v1alpha2"
	crdClient "github.com/kubernetes-sigs/wg-policy-prototypes/policy-report/kube-bench-adapter/pkg/generated/v1alpha2/clientset/versioned"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	policyReportBaseName        = "falco-policy-report-"
	clusterPolicyReportBaseName = "falco-cluster-policy-report-"
	policyReportSource          = "Falco"
)

var policyReport *wgpolicy.PolicyReport = &wgpolicy.PolicyReport{
	ObjectMeta: metav1.ObjectMeta{
		Name: policyReportBaseName,
	},
	Summary: wgpolicy.PolicyReportSummary{
		Fail: 0,
		Warn: 0, //to-do
	},
}
var clusterPolicyReport *wgpolicy.ClusterPolicyReport = &wgpolicy.ClusterPolicyReport{
	ObjectMeta: metav1.ObjectMeta{
		Name: clusterPolicyReportBaseName,
	},
	Summary: wgpolicy.PolicyReportSummary{
		Fail: 0,
		Warn: 0, //to-do
	},
}

//in accordance with PolicyReport CRD
var (
	failbound   int
	repcount    int
	polrepcount int
)

func NewPolicyReportClient(config *types.Configuration, stats *types.Statistics, promStats *types.PromStatistics, statsdClient, dogstatsdClient *statsd.Client) (*Client, error) {
	restConfig, err := rest.InClusterConfig()
	if err != nil {
		restConfig, err = clientcmd.BuildConfigFromFlags("", config.PolicyReport.Kubeconfig)
		if err != nil {
			fmt.Printf("[ERROR] : Unable to load kube config file: %v", err)
		}
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}
	crdclient, err := crdClient.NewForConfig(restConfig)
	if err != nil {
		return nil, err
	}

	policyReport.ObjectMeta.Name += uuid.NewString()
	clusterPolicyReport.ObjectMeta.Name += uuid.NewString()

	failbound = config.PolicyReport.FailThreshold

	return &Client{
		OutputType:       "PolicyReport",
		Config:           config,
		Stats:            stats,
		PromStats:        promStats,
		StatsdClient:     statsdClient,
		DogstatsdClient:  dogstatsdClient,
		KubernetesClient: clientset,
		Crdclient:        crdclient,
	}, nil
}

// CreateReport creates Policy Report or Cluster Policy Report in Kubernetes
func (c *Client) CreateReport(falcopayload types.FalcoPayload) {
	r, namespaceScoped := newResult(falcopayload)

	if namespaceScoped != "" {
		policyReport.Results = append(policyReport.Results, r)
		updateOrCreatePolicyReport(c, namespaceScoped)
		if len(policyReport.Results) >= failbound {
			policyReport.ObjectMeta.Name = policyReportBaseName + uuid.NewString()
		}
	} else {
		updateOrCreatePolicyReport(c, namespaceScoped)
		if len(clusterPolicyReport.Results) >= failbound {
			clusterPolicyReport.ObjectMeta.Name = clusterPolicyReportBaseName + uuid.NewString()
		}
	}
}

func isPolicyReportExist(c *Client, namespace string) bool {
	_, err := getPolicyReport(c, namespace)
	if !errors.IsNotFound(err) {
		log.Printf("[Info]  : Policy Report %v doesn't exist\n", policyReport.Name)
		return false
	}
	return true
}

func getPolicyReport(c *Client, namespace string) (*wgpolicy.PolicyReport, error) {
	policyr := c.Crdclient.Wgpolicyk8sV1alpha2().PolicyReports(namespace)
	return policyr.Get(context.Background(), policyReport.Name, metav1.GetOptions{})
}

func createPolicyReport(c *Client, namespace string) {
	policyr := c.Crdclient.Wgpolicyk8sV1alpha2().PolicyReports(namespace)
	result, err := policyr.Create(context.TODO(), policyReport, metav1.CreateOptions{})
	if err != nil {
		log.Printf("[ERROR] : %v\n", err)
	}
	log.Printf("[INFO]  : Create policy report %q.\n", result.GetObjectMeta().GetName())
}

func updatePolicyReport(c *Client, namespace string) {
	policyr := c.Crdclient.Wgpolicyk8sV1alpha2().PolicyReports(namespace)
	existingReport, _ := getPolicyReport(c, namespace)
	policyReport.SetResourceVersion(existingReport.GetResourceVersion())
	result, err := policyr.Update(context.Background(), policyReport, metav1.UpdateOptions{})
	if err != nil {
		log.Printf("[ERROR] : %v\n", err)
	}
	log.Printf("[INFO]  : Update policy report %q.\n", result.GetObjectMeta().GetName())
}

func updateOrCreatePolicyReport(c *Client, namespace string) {
	if isPolicyReportExist(c, namespace) {
		updatePolicyReport(c, namespace)
		return
	}
	createPolicyReport(c, namespace)
}

func isClusterPolicyReportExist(c *Client) bool {
	_, err := getClusterPolicyReport(c)
	if !errors.IsNotFound(err) {
		log.Printf("[Info]  : Policy Report %v doesn't exist\n", clusterPolicyReport.Name)
		return false
	}
	return true
}

func getClusterPolicyReport(c *Client) (*wgpolicy.ClusterPolicyReport, error) {
	policyr := c.Crdclient.Wgpolicyk8sV1alpha2().ClusterPolicyReports()
	return policyr.Get(context.Background(), clusterPolicyReport.Name, metav1.GetOptions{})
}

func createClusterPolicyReport(c *Client) {
	policyr := c.Crdclient.Wgpolicyk8sV1alpha2().ClusterPolicyReports()
	result, err := policyr.Create(context.TODO(), clusterPolicyReport, metav1.CreateOptions{})
	if err != nil {
		log.Printf("[ERROR] : %v\n", err)
	}
	log.Printf("[INFO]  : Create cluster policy report %q.\n", result.GetObjectMeta().GetName())
}

func updateClusterPolicyReport(c *Client) {
	policyr := c.Crdclient.Wgpolicyk8sV1alpha2().ClusterPolicyReports()
	existingReport, _ := getClusterPolicyReport(c)
	clusterPolicyReport.SetResourceVersion(existingReport.GetResourceVersion())
	result, err := policyr.Update(context.Background(), clusterPolicyReport, metav1.UpdateOptions{})
	if err != nil {
		log.Printf("[ERROR] : %v\n", err)
	}
	log.Printf("[INFO]  : Update cluster policy report %q.\n", result.GetObjectMeta().GetName())
}

func updateOrCreateClusterPolicyReport(c *Client) {
	if isClusterPolicyReportExist(c) {
		updateClusterPolicyReport(c)
		return
	}
	createClusterPolicyReport(c)
}

//newResult creates a new entry for Reports
func newResult(FalcoPayload types.FalcoPayload) (result *wgpolicy.PolicyReportResult, namespace string) {
	namespace = ""

	result = &wgpolicy.PolicyReportResult{
		Policy:      FalcoPayload.Rule,
		Source:      policyReportSource,
		Scored:      false,
		Timestamp:   metav1.Timestamp{Seconds: int64(FalcoPayload.Time.Second()), Nanos: int32(FalcoPayload.Time.Nanosecond())},
		Result:      "fail",
		Description: FalcoPayload.Output,
	}

	var m = make(map[string]string)
	for index, element := range FalcoPayload.OutputFields {
		m[index] = fmt.Sprintf("%v", element)
		if index == "ka.target.namespace" || index == "k8s.ns.name" {
			namespace = fmt.Sprintf("%v", element)
		}
	}
	result.Properties = m

	prio := "medium"
	if FalcoPayload.Priority > types.PriorityType(failbound) {
		prio = "high"
	}
	if FalcoPayload.Priority < types.PriorityType(failbound) {
		prio = "low"
	}
	result.Severity = wgpolicy.PolicyResultSeverity(prio)

	switch {
	case prio == "high" && namespace != "":
		policyReport.Summary.Fail++
	case prio == "high" && namespace == "":
		clusterPolicyReport.Summary.Fail++
	case prio != "high" && namespace != "":
		policyReport.Summary.Fail++
	case prio != "high" && namespace == "":
		clusterPolicyReport.Summary.Fail++
	}

	return result, namespace
}

func checklow(result []*wgpolicy.PolicyReportResult) (swapint int) {
	for i, j := range result {
		if j.Severity == "medium" || j.Severity == "low" {
			return i
		}
	}
	return -1
}
