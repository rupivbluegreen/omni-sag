{{- define "omni-sag.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "omni-sag.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "omni-sag.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "omni-sag.labels" -}}
app.kubernetes.io/name: {{ include "omni-sag.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "omni-sag.selectorLabels" -}}
app.kubernetes.io/name: {{ include "omni-sag.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "omni-sag.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
