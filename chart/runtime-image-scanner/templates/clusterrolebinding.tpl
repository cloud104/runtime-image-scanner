apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: tks-image-scanner
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: tks-image-scanner
subjects:
- kind: ServiceAccount
  name: {{ template "runtime-image-scanner.serviceAccountName" . }}
  namespace: {{ .Release.Namespace }}