{{/* Release-scoped name prefix, e.g. "sentinelflow". */}}
{{- define "sf.fullname" -}}
{{- .Release.Name | trunc 40 | trimSuffix "-" -}}
{{- end -}}

{{- define "sf.labels" -}}
app.kubernetes.io/name: sentinelflow
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{/* Selector labels. Args: dict "root" $ "component" "<name>" */}}
{{- define "sf.selector" -}}
app.kubernetes.io/name: sentinelflow
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/* Image reference. Args: dict "root" $ "name" "<image>"
     A digest in image.digests.<name> pins the exact (signed) image instead of the tag. */}}
{{- define "sf.image" -}}
{{- $i := .root.Values.image -}}
{{- $repo := printf "%s%s%s" (ternary (printf "%s/" $i.registry) "" (ne $i.registry "")) $i.prefix .name -}}
{{- with (index ($i.digests | default dict) .name) -}}
{{ $repo }}@{{ . }}
{{- else -}}
{{ $repo }}:{{ $i.tag }}
{{- end -}}
{{- end -}}

{{/* imagePullSecrets for every pod (private registries). */}}
{{- define "sf.imagePullSecrets" -}}
{{- with .Values.image.pullSecrets }}
imagePullSecrets:
{{- range . }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "sf.secretName" -}}
{{- .Values.secrets.existingSecret | default (printf "%s-secrets" (include "sf.fullname" .)) -}}
{{- end -}}

{{/* Pod-level hardening; satisfies the "restricted" Pod Security Standard. */}}
{{- define "sf.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: {{ .uid | default 10001 }}
runAsGroup: {{ .uid | default 10001 }}
fsGroup: {{ .uid | default 10001 }}
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "sf.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end -}}

{{/* Database connection env. The password comes from the Secret and is
     interpolated by Kubernetes ($(VAR) syntax), never written into the manifest. */}}
{{- define "sf.databaseEnv" -}}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "sf.secretName" . }}
      key: postgres-password
- name: SENTINELFLOW_DATABASE_URL
  value: "postgresql+asyncpg://sentinelflow:$(POSTGRES_PASSWORD)@{{ include "sf.fullname" . }}-postgres:5432/sentinelflow"
{{- end -}}
