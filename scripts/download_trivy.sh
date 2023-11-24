#!/bin/bash

case $(arch) in
"x86_64")
  echo "download para x86_64"
  wget "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" -O /tmp/trivy.tgz
  ;;
"aarch64")
  echo "download para arm"
  wget "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz" -O /tmp/trivy.tgz
  ;;
esac

tar -xvzf /tmp/trivy.tgz -C /tmp