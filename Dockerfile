FROM ubuntu:18.10
ADD build/cve-2018-1002105 /cve-2018-1002105
ENTRYPOINT [ "/cve-2018-1002105", "--kubeconfig", "/kubeconfig" ]