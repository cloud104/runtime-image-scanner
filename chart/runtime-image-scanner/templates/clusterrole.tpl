apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: tks-image-scanner
rules:
- apiGroups:
  - ""
  resources:
  - secrets
  - endpoints
  - services
  - pods
  verbs:
  - list
  - get
- apiGroups:
  - extensions
  - networking.k8s.io
  resources:
  - ingresses
  verbs:
  - list
  - get