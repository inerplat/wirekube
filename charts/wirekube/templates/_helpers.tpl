{{/*
Chart-wide labels. Component resource names are intentionally fixed
(wirekube-agent, wirekube-relay, ...) because the agent and the
relay-endpoint reconciler look Services up by name; see values.yaml.
*/}}
{{- define "wirekube.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/part-of: wirekube
app.kubernetes.io/version: {{ include "wirekube.imageTag" . | trunc 63 | trimSuffix "-" | quote }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end }}

{{- define "wirekube.imageTag" -}}
{{- .Values.image.tag | default .Chart.AppVersion -}}
{{- end }}

{{- define "wirekube.image" -}}
{{- printf "%s:%s" .Values.image.repository (include "wirekube.imageTag" .) -}}
{{- end }}

{{/* Selector labels per component; kept minimal and immutable. */}}
{{- define "wirekube.agent.selectorLabels" -}}
app: wirekube-agent
app.kubernetes.io/name: wirekube-agent
{{- end }}

{{- define "wirekube.relay.selectorLabels" -}}
app.kubernetes.io/name: wirekube-relay
{{- end }}

{{- define "wirekube.relayWs.selectorLabels" -}}
app.kubernetes.io/name: wirekube-relay-ws
{{- end }}
