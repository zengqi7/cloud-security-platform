{{- define "cloudguard.name" -}}
{{- printf "%s-cloudguard" .Release.Name | trunc 48 | trimSuffix "-" -}}
{{- end -}}
{{- define "cloudguard.image" -}}
{{- printf "%s@%s" .Values.image.repository (required "image.digest is required" .Values.image.digest) -}}
{{- end -}}
{{- define "cloudguard.env" -}}
{{- range $key, $value := .Values.env }}
- name: {{ $key }}
  value: {{ $value | quote }}
{{- end }}
{{- end -}}
