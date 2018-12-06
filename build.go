//+build mage

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
	"fmt"
	"os"
	"time"

	"github.com/gravitational/trace"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var (
	// buildContainer is a docker container used to build go binaries
	buildContainer = "golang:1.11.1"

	// registryImage is the docker tag to use to push the container to the requested registry
	registryImage = env("REGISTRY_IMAGE", "quay.io/gravitational/cve-2018-1002105")
)

// env, loads a variable from the environment, or uses the provided default
func env(env, d string) string {
	if os.Getenv(env) != "" {
		return os.Getenv(env)
	}
	return d
}

// GoBuild builds go binaries
func Go() error {
	fmt.Println("\n=====> Building cve-2018-1002105 binary...\n")
	start := time.Now()

	volumeMount := fmt.Sprintf("--volume=%v:/go/src/github.com/gravitational/cve-2018-1002105:delegated", srcDir())
	//fmt.Println("Volume:", volumeMount)

	err := trace.Wrap(sh.RunV(
		"docker",
		"run",
		"-it",
		"--rm=true",
		volumeMount,
		`--env="GOCACHE=/go/src/github.com/gravitational/cve-2018-1002105/build/cache/go"`,
		buildContainer,
		"go",
		"--",
		"build",
		"-o",
		"/go/src/github.com/gravitational/cve-2018-1002105/build/cve-2018-1002105",
		"github.com/gravitational/cve-2018-1002105",
	))

	elapsed := time.Since(start)
	fmt.Println("Build completed in ", elapsed)

	return trace.Wrap(err)
}

// DockerBuild builds a docker image for this project
func Docker() error {
	mg.Deps(Go)
	fmt.Println("\n=====> Building cve-2018-1002105 docker image...\n")

	return trace.Wrap(sh.RunV(
		"docker",
		"build",
		"--pull",
		"--tag",
		"cve-2018-1002105:latest",
		"--build-arg",
		"ARCH=amd64",
		"-f",
		"Dockerfile",
		".",
	))
}

func Publish() error {
	mg.Deps(Docker)
	fmt.Println("\n=====> Publishing cve-2018-1002105 docker image...\n")

	err := sh.RunV(
		"docker",
		"tag",
		"cve-2018-1002105:latest",
		fmt.Sprint(registryImage, ":latest"),
	)
	if err != nil {
		return trace.Wrap(err)
	}

	return trace.Wrap(sh.RunV(
		"docker",
		"push",
		fmt.Sprint(registryImage, ":latest"),
	))
}

func Run() error {
	mg.Deps(Docker)
	fmt.Println("\n=====> Running cve-2018-1002105 docker image...\n")

	err := sh.RunV(
		"docker",
		"run",
		"-it",
		"--rm=true",
		fmt.Sprintf("--volume=%v/.kube/config:/kubeconfig", homeDir()),
		"cve-2018-1002105:latest",
	)
	if err != nil {
		return trace.Wrap(err)
	}
	return nil
}

func srcDir() string {
	if os.Getenv("ROOT_DIR") != "" {
		return os.Getenv("ROOT_DIR")
	}
	return os.Getenv("PWD")
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}
