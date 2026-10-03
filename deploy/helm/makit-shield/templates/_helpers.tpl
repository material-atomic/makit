{{- define "makit.name" -}}{{ .Chart.Name }}{{- end -}}
{{- define "makit.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{- end -}}
{{- end -}}
{{- define "makit.labels" -}}
app.kubernetes.io/name: {{ include "makit.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}
{{- define "makit.selector" -}}
app.kubernetes.io/name: {{ include "makit.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "makit.clusterSecret" -}}{{ .Values.cluster.existingSecret | default (printf "%s-cluster" (include "makit.fullname" .)) }}{{- end -}}
{{/* shield.yaml: the config map, with cluster: filled in for the headless Service. */}}
{{- define "makit.shieldYAML" -}}
{{- $cfg := deepCopy .Values.config -}}
{{- if .Values.cluster.enabled -}}
{{- $peers := list (printf "dns:%s-headless.%s.svc.cluster.local:%v" (include "makit.fullname" .) .Release.Namespace .Values.cluster.port) -}}
{{- $_ := set $cfg "cluster" (dict "listen" (printf ":%v" .Values.cluster.port) "peers" $peers "sync" .Values.cluster.sync) -}}
{{- end -}}
{{- toYaml $cfg -}}
{{- end -}}
