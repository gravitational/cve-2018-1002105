# CVE-2018-1002105

Test utility that checks a cluster for the high severity kubernetes CVE published [here](https://github.com/kubernetes/kubernetes/issues/71411). A stakeholder-level writeup of the CVE-2018-1002105 may be found at [https://gravitational.com/blog/kubernetes-websocket-upgrade-security-vulnerability/](https://gravitational.com/blog/kubernetes-websocket-upgrade-security-vulnerability/) 

# Warning
Running this test through layer 7 load balancers or proxies in front of you're kubernetes apiserver may be unreliable and produce incorrect results.
This test operates by connecting to the apiserver, and checking for side effects of the apiserver that exhibit the bug in kubernetes.
Running this proof of concept through a layer 7 load balancer, may falsely indicate that the API is vulnerable to CVE-2018-1002105

# Managed Kubernetes (AKS, EKS, GKE) Note
This tool veers toward false-positives, if your Kubernetes API is provided by a major cloud provider (such as Amazon AWS EKS, Google Cloud GKE or Microsoft Azure AKS), that service provider has almost certainly already patched your apiserver and you are no longer affected by CVE-2018-1002105. We would welcome pull requests that improve the detection of non-vulnerable apiserver endpoints.

# Build and Run

```
go get github.com/gravitational/cve-2018-1002105
cd $GOPATH/src/github.com/gravitational/cve-2018-1002105
go run main.go
```

# Running as a container
```
docker run -it --rm -v $HOME/.kube/config:/kubeconfig: quay.io/gravitational/cve-2018-1002105:latest
```

# Testing a cluster

The tool will attempt to test for two things, whether the cluster allows unauthenticated access to the API, which will then allow unauthenticated access to aggregate API endpoint. It will also attempt to find a pod, and attempt to test whether the apiserver will leave the connection open on a malformed request, which indicates the cluster is susceptible to CVE-2018-1002105.

```
Testing for unauthenticated access...
> API allows unauthenticated access
Testing for privilege escalation...
> API is vulnerable to CVE-2018-1002105
```

If you see `API allows unauthenticated access` it indicates that the test was able to detect unauthenticated access to the cluster. This test is fairly basic, but should detect a default configuration where anonymous access to the cluster is allowed.


If you see `API is vulnerable to CVE-2018-1002105`, this means that using the provided kubeconfig, the tool was able to test and confirm your cluster is vulnerable. 
