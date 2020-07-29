# Runtime Image Scanner Helm Chart

Faz o deploy de um scanner de imagem em um cluster.

## Pré-requisito

- Storage Class default ativa (caso o recurso de persistência esteja ativo).

## Configuração

Por padrão a exposição da api de vulnerabilidades encontradas está desativada.

Lista das opções ajustáveis do chart. Para maiores informações, veja o arquivo [values.yaml](runtime-image-scanner/values.yaml)

|Parâmetro|Descrição|Valor Padrão|
|---|---|---|
|image.repository|Repositório da imagem docker|gcr.io/totvs-kubernetes-service/runtime-image-scanner|
|image.tag|Tag da image docker|v0.0.21|
|image.pullPolicy|Politica de pull da imagem no deployment|IfNotPresent|
|imagePullSecrets|Secret com senha para baixar imagens do registry|- name: image-scanner-registry|
|Envs|Variáveis de ambiente repassadas para o app|veja o arquivo [values.yaml](runtime-image-scanner/values.yaml)|
|serviceAccount.name|Nome da service account que será usada para efetuar chamadas na api do kubernetes|image-scanner|
|service.type|Tipo do servico do kubernetes|ClusterIP|
|service.port|Porta do serviço|8080|
|ingress.enabled|Ativa o servico de ingress|false|
|ingress.annotations|Ingress annotations|{}|
|ingress.hosts[0].host|	Hostname para o ingress|chart-example.local|
|ingress.hosts[0].paths|Path que o ingress irá responder|/|
|volume.create|Cria o volume persistente?|true|
|volume.size|Tamanho do volume persistente|1Gi|
|volume.mountPath|Onde esse volume será montado|/output|
|monitorint.serviceMonitor.enable|Cria o service monitor do prometheus operator|true|
|resources.limits.cpu|Container max CPU|2|
|resources.limits.memory|Container max memory|1Gi|
|resources.requests.cpu|Container requested CPU|50m|
|resources.requests.memory|Container requested memory|128Mi|
|nodeSelector|Mapa com seletores de node|{}|
|tolerations|Lista com os node taints|[]|
|affinity|Mapa de node/pod affinity|{}|