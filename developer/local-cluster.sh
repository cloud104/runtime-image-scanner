 create() {
  kind create cluster --name runtime --config=kind-cluster-config.yaml
  kind get kubeconfig --name runtime > kubeconfig.yaml
  export KUBECONFIG=$pwd/develop/kubeconfig.yaml
}

 delete(){
  kind delete cluster --name runtime
}

 install_ingress(){
  kubectl apply -f deploy-ingress-nginx.yaml
  echo "Waiting for the Ingress to become ready!"
  sleep 60
  echo "Applying ingress examples!!!"
  kubectl apply -f https://kind.sigs.k8s.io/examples/ingress/usage.yaml
}
$1
