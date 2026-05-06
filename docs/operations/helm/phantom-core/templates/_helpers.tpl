{{/*
_helpers.tpl — Named template library for the phantom-core Helm chart.
Standard Helm 3 conventions; generated names follow the helm-create canonical set.
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "phantom-core.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec). If release name contains the chart name it will be used
as a full name to avoid duplication.
*/}}
{{- define "phantom-core.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart label, used in the "helm.sh/chart" annotation.
*/}}
{{- define "phantom-core.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels — applied to every resource.
Includes the chart version so resources can be tied to a specific chart release.
*/}}
{{- define "phantom-core.labels" -}}
helm.sh/chart: {{ include "phantom-core.chart" . }}
{{ include "phantom-core.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels — the minimal stable set used for Service / PDB / HPA selectors.
These MUST NOT change after initial install (selector is immutable on Deployments).
*/}}
{{- define "phantom-core.selectorLabels" -}}
app.kubernetes.io/name: {{ include "phantom-core.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Resolve the ServiceAccount name.
*/}}
{{- define "phantom-core.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "phantom-core.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Resolve the signing-key Secret name.
Priority: existingSecret > chart-managed secret (fullname + "-signing-key").
*/}}
{{- define "phantom-core.signingKeySecretName" -}}
{{- if .Values.signingKey.existingSecret }}
{{- .Values.signingKey.existingSecret }}
{{- else }}
{{- include "phantom-core.fullname" . }}-signing-key
{{- end }}
{{- end }}

{{/*
Image reference: repository:tag, where tag defaults to .Chart.AppVersion.
*/}}
{{- define "phantom-core.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}
