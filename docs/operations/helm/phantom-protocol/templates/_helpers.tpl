{{/*
_helpers.tpl — Named template library for the phantom-protocol Helm chart.
Standard Helm 3 conventions; generated names follow the helm-create canonical set.
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "phantom-protocol.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec). If release name contains the chart name it will be used
as a full name to avoid duplication.
*/}}
{{- define "phantom-protocol.fullname" -}}
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
{{- define "phantom-protocol.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels — applied to every resource.
Includes the chart version so resources can be tied to a specific chart release.
*/}}
{{- define "phantom-protocol.labels" -}}
helm.sh/chart: {{ include "phantom-protocol.chart" . }}
{{ include "phantom-protocol.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels — the minimal stable set used for Service / PDB / HPA selectors.
These MUST NOT change after initial install (selector is immutable on Deployments).
*/}}
{{- define "phantom-protocol.selectorLabels" -}}
app.kubernetes.io/name: {{ include "phantom-protocol.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Resolve the ServiceAccount name.
*/}}
{{- define "phantom-protocol.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "phantom-protocol.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Resolve the signing-key Secret name.
Priority: existingSecret > chart-managed secret (fullname + "-signing-key").
*/}}
{{- define "phantom-protocol.signingKeySecretName" -}}
{{- if .Values.signingKey.existingSecret }}
{{- .Values.signingKey.existingSecret }}
{{- else }}
{{- include "phantom-protocol.fullname" . }}-signing-key
{{- end }}
{{- end }}

{{/*
Image reference: repository:tag, where tag defaults to .Chart.AppVersion.
*/}}
{{- define "phantom-protocol.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}
