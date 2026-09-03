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

{{/*
Whether to run the -fips image variant. Returns "true" or "" (Helm's truthy
convention for `if`). Derived from fips.mode unless fips.useFipsImage says
otherwise. mode is compared as a formatted string so a mis-typed non-string
value falls through to omni-sag.validateFips rather than erroring here.
*/}}
{{- define "omni-sag.useFipsImage" -}}
{{- if kindIs "invalid" .Values.fips.useFipsImage -}}
{{- if eq (printf "%v" .Values.fips.mode) "enforce" -}}true{{- end -}}
{{- else if .Values.fips.useFipsImage -}}true{{- end -}}
{{- end -}}

{{/*
Refuse to render a release that cannot boot, rather than letting the pod
crash-loop with the gateway's own enforce error. Called from every template
that depends on the posture, since Helm does not guarantee render order.
*/}}
{{- define "omni-sag.validateFips" -}}
{{- $mode := .Values.fips.mode -}}
{{- if not (kindIs "string" $mode) -}}
{{- fail (printf "omni-sag: fips.mode must be a quoted string \"off\", \"warn\" or \"enforce\" — got %v. YAML reads a bare off/on as a boolean, so quote it." $mode) -}}
{{- end -}}
{{- if not (has $mode (list "off" "warn" "enforce")) -}}
{{- fail (printf "omni-sag: fips.mode must be \"off\", \"warn\" or \"enforce\", got %q" $mode) -}}
{{- end -}}
{{- if and (eq $mode "enforce") (not (include "omni-sag.useFipsImage" .)) -}}
{{- fail "omni-sag: fips.mode \"enforce\" with fips.useFipsImage: false cannot start — enforce requires a process in FIPS mode (GODEBUG=fips140=on), which only the -fips image sets. Drop useFipsImage to let the chart pick the -fips tag, or point image.tag at an image that is already FIPS." -}}
{{- end -}}
{{- end -}}

{{/*
Image reference. The -fips suffix is appended (idempotently, so an image.tag
that already carries it is left alone) whenever the FIPS variant is wanted.
*/}}
{{- define "omni-sag.image" -}}
{{- include "omni-sag.validateFips" . -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- if and (include "omni-sag.useFipsImage" .) (not (hasSuffix "-fips" $tag)) -}}
{{- $tag = printf "%s-fips" $tag -}}
{{- end -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
