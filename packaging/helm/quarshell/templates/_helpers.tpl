{{/*
Expand the name of the chart.
*/}}
{{- define "quarshell.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "quarshell.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "quarshell.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "quarshell.labels" -}}
app.kubernetes.io/name: {{ include "quarshell.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "quarshell.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "quarshell.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
