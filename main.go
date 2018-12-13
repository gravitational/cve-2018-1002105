/*
Copyright 2018 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gravitational/trace"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	fmt.Println("Please Note:")
	fmt.Println("  This test currently relies on the behaviour of apiserver/kubelet to check for the issue.")
	fmt.Println("  If you're connecting through a layer-7 load balancer, you may receive false positives in the test")

	fmt.Println("Attempting to locate and load kubeconfig file")
	var kubeconfig *string
	if home := homeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	fmt.Println("Loading:", *kubeconfig)
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	err = testUnauthenticated(config)
	if err != nil {
		fmt.Println(trace.DebugReport(err))
	}

	err = testEscalate(config)
	if err != nil {
		fmt.Println(trace.DebugReport(err))
	}
}

// testUnauthenticated does a simple HTTP request to the kubernetes API, to list the available API endpoints
// this should be able to detect most clusters that allow unauthenticated access
func testUnauthenticated(config *rest.Config) error {
	fmt.Println("Testing for unauthenticated access...")

	path := fmt.Sprint(config.Host, "/apis")
	if config.APIPath != "" {
		path = fmt.Sprint(config.Host, config.APIPath, "/apis")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}
	resp, err := client.Get(path)
	if err != nil {
		return trace.Wrap(err)
	}
	if resp.StatusCode == 200 {
		fmt.Println("> API allows unauthenticated access")
	}
	return nil
}

// testEscalate will try and find a pod running on the cluster, and ty to exec to the pod with an invalid websocket
// request. It will then test if the connection is still available after the invalid connection.
func testEscalate(config *rest.Config) error {
	fmt.Println("Testing for privilege escalation...")
	// Find a random pod on the cluster to run tests against
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	pod := findPod(clientset)

	// Build a TLS connection to the kube apiserver to test
	cfg, err := rest.TLSConfigFor(config)
	if err != nil {
		return trace.Wrap(err)
	}
	if cfg == nil {
		fmt.Println("> Unable to determine if cluster allows privilege escalation, only using TLS client certs is currently supported.")
		return nil
	}

	u, err := url.Parse(config.Host)
	if err != nil {
		return trace.Wrap(err)
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		host = fmt.Sprint(host, ":443")
	}

	conn, err := tls.Dial("tcp", host, cfg)
	if err != nil {
		return trace.Wrap(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// duplicate the unencrypted stream, allows echoing all traffic for debug purposes
	r, w := io.Pipe()
	go func() {
		for {
			b := make([]byte, 512)
			r.Read(b)
			//fmt.Println("echo: ", string(b))
		}
	}()

	// Build an invalid request, trying to hit the exec URI, but including invalid websocket upgrade requests
	request, err := http.NewRequest("GET", fmt.Sprintf("https://%v/api/v1/namespaces/%v/pods/%v/exec", u.Host, pod.Namespace, pod.Name), nil)
	if err != nil {
		return trace.Wrap(err)
	}
	request.Header.Add("Connection", "upgrade")
	request.Header.Add("Upgrade", "websocket")
	err = request.Write(io.MultiWriter(conn, w))
	if err != nil {
		return trace.Wrap(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(io.TeeReader(conn, w)), nil)
	if err != nil {
		return trace.Wrap(err)
	}
	// read and discard the response body
	var body bytes.Buffer
	body.ReadFrom(resp.Body)
	if !strings.Contains((body.String()), "you must specify at least 1 of stdin, stdout, stderr") {
		fmt.Println("> Unable to determine if cluster allows privilege escalation, unexpected response from server:")
		fmt.Println(body.String())
		return nil
	}
	err = resp.Body.Close()
	if err != nil {
		return trace.Wrap(err)
	}
	if resp.StatusCode == 403 {
		// if the request is specifically rejected for an authentication failure, we'll assume this is a failure on
		// the API server side
		fmt.Println("> Unable to determine if cluster allows privilege escalation, received unexpected authorization failure from apiserver.")
		fmt.Println(body.String())
		return nil
	}

	// See if the socket is still available to write to by sending a second request
	// use the /pods endpoint, which is an endpoint on kubelet but not the apiserver
	request, err = http.NewRequest("GET", fmt.Sprintf("https://%v/pods", u.Host), nil)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	request = request.WithContext(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	err = request.Write(io.MultiWriter(conn, w))
	if err != nil && trace.IsEOF(err) {
		// We expected the server to close the connection
		// so this is a good result
		return nil
	}
	if err != nil {
		return trace.Wrap(err)
	}

	resp, err = http.ReadResponse(bufio.NewReader(io.TeeReader(conn, w)), request)
	if err != nil && err == io.ErrUnexpectedEOF {
		// We expected the server to close the connection
		// so this is a good result
		return nil
	}
	if e, ok := err.(*net.OpError); ok {
		if e.Timeout() {
			// It's been noticed, that patched apiservers are timing out, instead of closing the connection
			// So, use this as an expected result, if we have just a hung connection with no answer to the second request
			return nil
		}
	}

	if err != nil {
		return trace.Wrap(err)
	}
	if resp.StatusCode == 404 {
		// A patched API server, will respond with a 404 to /pods
		return nil
	}
	if resp.StatusCode == 200 {
		fmt.Println("> API is vulnerable to CVE-2018-1002105")
		return nil
	}
	fmt.Println("> Unable to determine if cluster allows privilege escalation, received unexpected result to second request:", resp.StatusCode)

	return nil
}

func findPod(client *kubernetes.Clientset) v1.Pod {
	namespaces, err := client.CoreV1().Namespaces().List(metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	for _, namespace := range namespaces.Items {
		pods, err := client.CoreV1().Pods(namespace.Name).List(metav1.ListOptions{})
		if err != nil {
			panic(err.Error())
		}

		for _, pod := range pods.Items {
			if pod.Status.Phase != v1.PodRunning {
				continue
			}
			if len(pod.Spec.Containers) != 1 {
				continue
			}
			return pod
		}

	}
	panic("Unable to find any pods in cluster in running state")
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}
