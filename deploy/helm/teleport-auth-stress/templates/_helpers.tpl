{{- define "teleport-auth-stress.name" -}}
{{- .Chart.Name -}}
{{- end -}}

{{- define "teleport-auth-stress.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "teleport-auth-stress.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "teleport-auth-stress.labels" -}}
app.kubernetes.io/name: {{ include "teleport-auth-stress.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "teleport-auth-stress.image" -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}
