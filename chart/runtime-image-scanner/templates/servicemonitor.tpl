{{- if .Values.monitoring.serviceMonitor.enable -}}
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  labels:
{{ include "runtime-image-scanner.labels" . | indent 4 }}
    prometheus: tks
  name: {{ .Release.Name | trunc 63  }}
  namespace: {{ .Release.Namespace }}
spec:
  endpoints:
  - port: http
  jobLabel: image-scanner
  namespaceSelector:
    matchNames:
    - {{ .Release.Namespace }}
  selector:
    matchLabels:
{{ include "runtime-image-scanner.labels" . | indent 6 }}
{{ end }}