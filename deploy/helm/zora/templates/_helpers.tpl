{{- define "zora.name" -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}

{{- define "zora.agent" -}}
{{ include "zora.name" . }}-agent
{{- end -}}

{{- define "zora.labels" -}}
app.kubernetes.io/name: zora
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "zora.selectorLabels" -}}
app.kubernetes.io/name: zora
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: agent
{{- end -}}

{{- define "zora.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{/* The release's own namespace is always excluded, so zora's own pods
     (the uninstall hook among them) never depend on zora. */}}
{{- define "zora.excludeNamespaces" -}}
{{- append .Values.excludeNamespaces .Release.Namespace | uniq | join "," -}}
{{- end -}}
