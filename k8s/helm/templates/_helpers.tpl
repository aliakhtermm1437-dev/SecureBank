{{/*
Common labels.
*/}}
{{- define "securebank.labels" -}}
app.kubernetes.io/name: {{ .name }}
app.kubernetes.io/instance: {{ $.Release.Name }}
app.kubernetes.io/version: {{ $.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ $.Release.Service }}
helm.sh/chart: {{ $.Chart.Name }}-{{ $.Chart.Version }}
securebank.local/component: {{ .name }}
{{- end -}}

{{- define "securebank.image" -}}
{{ $.Values.global.imageRegistry }}/{{ .name }}:{{ $.Values.global.imageTag }}
{{- end -}}

{{- define "securebank.podSecurityContext" -}}
runAsNonRoot: {{ $.Values.securityContext.runAsNonRoot }}
runAsUser: {{ $.Values.securityContext.runAsUser }}
fsGroup: {{ $.Values.securityContext.fsGroup }}
seccompProfile:
  type: {{ $.Values.securityContext.seccompProfile.type }}
{{- end -}}

{{- define "securebank.containerSecurityContext" -}}
allowPrivilegeEscalation: {{ $.Values.securityContext.allowPrivilegeEscalation }}
readOnlyRootFilesystem: {{ $.Values.securityContext.readOnlyRootFilesystem }}
capabilities:
  drop: {{ $.Values.securityContext.capabilities.drop | toJson }}
{{- end -}}
