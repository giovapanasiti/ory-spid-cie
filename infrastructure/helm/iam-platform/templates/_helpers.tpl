{{/* ------------------------------------------------------------ naming */}}
{{- define "iam.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 40 | trimSuffix "-" -}}
{{- end -}}

{{- define "iam.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 40 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 40 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* Resource name for a component: iam.res (dict "root" $ "name" "kratos") */}}
{{- define "iam.res" -}}
{{- printf "%s-%s" (include "iam.fullname" .root) .name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "iam.selectorLabels" -}}
app.kubernetes.io/name: {{ include "iam.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "iam.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "iam.selectorLabels" . }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
app.kubernetes.io/part-of: iam-platform
{{- end -}}

{{/* ------------------------------------------------------------ images */}}
{{/* iam.image (dict "root" $ "img" .Values.images.kratos) */}}
{{- define "iam.image" -}}
{{- $tag := default .root.Chart.AppVersion .img.tag -}}
{{- if .img.digest -}}
{{- printf "%s@%s" .img.repository .img.digest -}}
{{- else -}}
{{- printf "%s:%s" .img.repository $tag -}}
{{- end -}}
{{- end -}}

{{/* ------------------------------------------------------------ URLs */}}
{{- define "iam.https" -}}https://{{ . }}{{- end -}}
{{- define "iam.url.kratosPublic" -}}http://{{ include "iam.res" (dict "root" . "name" "kratos-public") }}:4433{{- end -}}
{{- define "iam.url.kratosAdmin" -}}http://{{ include "iam.res" (dict "root" . "name" "kratos-admin") }}:4434{{- end -}}
{{- define "iam.url.hydraPublic" -}}http://{{ include "iam.res" (dict "root" . "name" "hydra-public") }}:4444{{- end -}}
{{- define "iam.url.hydraAdmin" -}}http://{{ include "iam.res" (dict "root" . "name" "hydra-admin") }}:4445{{- end -}}
{{- define "iam.url.brokerPublic" -}}http://{{ include "iam.res" (dict "root" . "name" "federation-broker") }}:8090{{- end -}}
{{- define "iam.url.brokerAdmin" -}}http://{{ include "iam.res" (dict "root" . "name" "federation-broker-admin") }}:8091{{- end -}}
{{- define "iam.url.identity" -}}http://{{ include "iam.res" (dict "root" . "name" "identity-service") }}:4000{{- end -}}
{{- define "iam.url.audit" -}}http://{{ include "iam.res" (dict "root" . "name" "audit-service") }}:4100{{- end -}}
{{- define "iam.url.demoApi" -}}http://{{ include "iam.res" (dict "root" . "name" "demo-api") }}:5600{{- end -}}

{{/* ------------------------------------------------------------ secrets */}}
{{/* iam.secretName (dict "root" $ "v" .Values.kratos) */}}
{{- define "iam.secretName" -}}
{{- $n := "" -}}
{{- if and .v .v.existingSecret -}}{{- $n = .v.existingSecret -}}{{- else -}}{{- $n = .root.Values.secrets.existingSecret -}}{{- end -}}
{{- required "secrets.existingSecret (or <component>.existingSecret) is required" $n -}}
{{- end -}}

{{/* iam.secretEnv (dict "env" "DSN" "secret" "name" "key" "KRATOS_DSN") */}}
{{- define "iam.secretEnv" -}}
- name: {{ .env }}
  valueFrom:
    secretKeyRef:
      name: {{ .secret }}
      key: {{ .key }}
{{- end -}}

{{/* ------------------------------------------------------------ env */}}
{{- define "iam.otelEnv" -}}
{{- $o := .root.Values.observability.otel -}}
{{- if $o.endpoint }}
{{- if .ory }}
- name: TRACING_PROVIDER
  value: otel
- name: TRACING_SERVICE_NAME
  value: {{ .name | quote }}
- name: TRACING_PROVIDERS_OTLP_SERVER_URL
  value: {{ $o.endpoint | quote }}
- name: TRACING_PROVIDERS_OTLP_INSECURE
  value: {{ $o.insecure | quote }}
{{- else }}
- name: OTEL_SERVICE_NAME
  value: {{ .name | quote }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ printf "%s://%s" (ternary "http" "https" $o.insecure) $o.endpoint | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{/* ------------------------------------------------------------ pod spec pieces */}}
{{- define "iam.podSecurityContext" -}}
{{- $psc := deepCopy .root.Values.podSecurityContext -}}
{{- $_ := set $psc "runAsUser" (int .uid) -}}
{{- $_ := set $psc "runAsGroup" (int .uid) -}}
{{- $_ := set $psc "fsGroup" (int .uid) -}}
{{- toYaml $psc -}}
{{- end -}}

{{- define "iam.scheduling" -}}
{{- $v := .v | default dict -}}
{{- with (default .root.Values.nodeSelector $v.nodeSelector) }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with (default .root.Values.tolerations $v.tolerations) }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with (default .root.Values.affinity $v.affinity) }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- if .root.Values.topologySpread.enabled }}
topologySpreadConstraints:
  - maxSkew: {{ .root.Values.topologySpread.maxSkew }}
    topologyKey: {{ .root.Values.topologySpread.topologyKey }}
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        {{- include "iam.selectorLabels" (dict "root" .root "component" .name) | nindent 8 }}
{{- end }}
{{- end -}}

{{/*
iam.deployment — generic hardened Deployment.
dict keys: root, name, v (component values), image, uid, args (list), ports (list of {name,port}),
env (YAML string list), probes (YAML string), volumes / volumeMounts (YAML string lists),
podAnnotations (map), recreate (bool), ory (bool, for OTEL env)
*/}}
{{- define "iam.deployment" -}}
{{- $root := .root -}}
{{- $v := .v -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "iam.res" . }}
  labels:
    {{- include "iam.labels" (dict "root" $root "component" .name) | nindent 4 }}
spec:
  {{- if not (and $v.autoscaling $v.autoscaling.enabled) }}
  replicas: {{ $v.replicaCount | default 1 }}
  {{- end }}
  revisionHistoryLimit: 5
  strategy:
    {{- if .recreate }}
    type: Recreate
    {{- else }}
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 0
      maxSurge: 1
    {{- end }}
  selector:
    matchLabels:
      {{- include "iam.selectorLabels" (dict "root" $root "component" .name) | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "iam.selectorLabels" (dict "root" $root "component" .name) | nindent 8 }}
        app.kubernetes.io/part-of: iam-platform
      {{- $ann := merge (dict) (.podAnnotations | default dict) ($v.podAnnotations | default dict) }}
      {{- with $ann }}
      annotations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
    spec:
      serviceAccountName: {{ include "iam.res" . }}
      automountServiceAccountToken: false
      enableServiceLinks: false
      terminationGracePeriodSeconds: 30
      {{- with $root.Values.images.pullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      securityContext:
        {{- include "iam.podSecurityContext" (dict "root" $root "uid" .uid) | nindent 8 }}
      containers:
        - name: {{ .name }}
          image: {{ .image }}
          imagePullPolicy: {{ $root.Values.images.pullPolicy }}
          {{- with .args }}
          args:
            {{- toYaml . | nindent 12 }}
          {{- end }}
          {{- with .ports }}
          ports:
            {{- range . }}
            - name: {{ .name }}
              containerPort: {{ .port }}
              protocol: TCP
            {{- end }}
          {{- end }}
          env:
            {{- with .env }}
            {{- . | nindent 12 }}
            {{- end }}
            {{- include "iam.otelEnv" (dict "root" $root "name" .name "ory" .ory) | nindent 12 }}
            {{- with $v.extraEnv }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
          {{- with .probes }}
          {{- . | nindent 10 }}
          {{- end }}
          resources:
            {{- toYaml $v.resources | nindent 12 }}
          securityContext:
            {{- toYaml $root.Values.containerSecurityContext | nindent 12 }}
          volumeMounts:
            - name: tmp
              mountPath: /tmp
            {{- with .volumeMounts }}
            {{- . | nindent 12 }}
            {{- end }}
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 64Mi
        {{- with .volumes }}
        {{- . | nindent 8 }}
        {{- end }}
      {{- include "iam.scheduling" (dict "root" $root "v" $v "name" .name) | nindent 6 }}
{{- end -}}

{{/* iam.service (dict "root" $ "name" "kratos-public" "component" "kratos" "ports" (list (dict "name" "http" "port" 4433))) */}}
{{- define "iam.service" -}}
apiVersion: v1
kind: Service
metadata:
  name: {{ include "iam.res" (dict "root" .root "name" .name) }}
  labels:
    {{- include "iam.labels" (dict "root" .root "component" .component) | nindent 4 }}
    iam.enpam.it/service-role: {{ .role | default "public" }}
spec:
  type: ClusterIP
  selector:
    {{- include "iam.selectorLabels" (dict "root" .root "component" .component) | nindent 4 }}
  ports:
    {{- range .ports }}
    - name: {{ .name }}
      port: {{ .port }}
      targetPort: {{ .name }}
      protocol: TCP
    {{- end }}
{{- end -}}

{{- define "iam.serviceAccount" -}}
apiVersion: v1
kind: ServiceAccount
metadata:
  name: {{ include "iam.res" . }}
  labels:
    {{- include "iam.labels" (dict "root" .root "component" .name) | nindent 4 }}
automountServiceAccountToken: false
{{- end -}}

{{- define "iam.pdb" -}}
{{- if and .v.pdb .v.pdb.enabled }}
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ include "iam.res" . }}
  labels:
    {{- include "iam.labels" (dict "root" .root "component" .name) | nindent 4 }}
spec:
  maxUnavailable: {{ .v.pdb.maxUnavailable | default 1 }}
  selector:
    matchLabels:
      {{- include "iam.selectorLabels" (dict "root" .root "component" .name) | nindent 6 }}
{{- end }}
{{- end -}}

{{- define "iam.hpa" -}}
{{- if and .v.autoscaling .v.autoscaling.enabled }}
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {{ include "iam.res" . }}
  labels:
    {{- include "iam.labels" (dict "root" .root "component" .name) | nindent 4 }}
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {{ include "iam.res" . }}
  minReplicas: {{ .v.autoscaling.minReplicas }}
  maxReplicas: {{ .v.autoscaling.maxReplicas }}
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: {{ .v.autoscaling.targetCPUUtilizationPercentage }}
{{- end }}
{{- end -}}

{{/* Deployment + ServiceAccount + PDB + HPA for one component */}}
{{- define "iam.workload" -}}
{{ include "iam.serviceAccount" . }}
---
{{ include "iam.deployment" . }}
{{- $pdb := include "iam.pdb" . }}
{{- if trim $pdb }}
---
{{ trim $pdb }}
{{- end }}
{{- $hpa := include "iam.hpa" . }}
{{- if trim $hpa }}
---
{{ trim $hpa }}
{{- end }}
{{- end -}}

{{/*
iam.migrationJob — pre-install/pre-upgrade hook Job.
dict keys: root, name (component), image, uid, args (list), env (YAML string)
Uses the namespace default ServiceAccount with token automount disabled (hook
resources run before regular chart resources exist).
*/}}
{{- define "iam.migrationJob" -}}
{{- $root := .root -}}
apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "iam.res" (dict "root" $root "name" (printf "%s-migrate" .name)) }}
  labels:
    {{- include "iam.labels" (dict "root" $root "component" "migrate") | nindent 4 }}
    iam.enpam.it/migrates: {{ .name }}
  annotations:
    helm.sh/hook: pre-install,pre-upgrade
    helm.sh/hook-weight: "0"
    helm.sh/hook-delete-policy: before-hook-creation,hook-succeeded
spec:
  backoffLimit: {{ $root.Values.migrations.backoffLimit }}
  activeDeadlineSeconds: {{ $root.Values.migrations.activeDeadlineSeconds }}
  template:
    metadata:
      labels:
        {{- include "iam.selectorLabels" (dict "root" $root "component" "migrate") | nindent 8 }}
        iam.enpam.it/migrates: {{ .name }}
    spec:
      restartPolicy: Never
      automountServiceAccountToken: false
      enableServiceLinks: false
      {{- with $root.Values.images.pullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      securityContext:
        {{- include "iam.podSecurityContext" (dict "root" $root "uid" .uid) | nindent 8 }}
      containers:
        - name: migrate
          image: {{ .image }}
          imagePullPolicy: {{ $root.Values.images.pullPolicy }}
          args:
            {{- toYaml .args | nindent 12 }}
          env:
            {{- .env | nindent 12 }}
          resources:
            {{- toYaml $root.Values.migrations.resources | nindent 12 }}
          securityContext:
            {{- toYaml $root.Values.containerSecurityContext | nindent 12 }}
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 64Mi
      {{- with $root.Values.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $root.Values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
{{- end -}}

{{/* Standard HTTP probes: iam.httpProbes (dict "port" "http" "live" "/healthz" "ready" "/healthz") */}}
{{- define "iam.httpProbes" -}}
startupProbe:
  httpGet: {path: {{ .live }}, port: {{ .port }}}
  periodSeconds: 3
  failureThreshold: 40
livenessProbe:
  httpGet: {path: {{ .live }}, port: {{ .port }}}
  periodSeconds: 10
  timeoutSeconds: 3
  failureThreshold: 3
readinessProbe:
  httpGet: {path: {{ .ready }}, port: {{ .port }}}
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 3
{{- end -}}
