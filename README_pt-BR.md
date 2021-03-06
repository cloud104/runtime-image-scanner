# Runtime Image Scanner
Esse scanner de imagens docker percorre todo o cluster procurando por pods, executando um scan de vulnerabilidades nas
imagens encontradas.

O resultado dos scans é fornecido pelo software [trivy](https://github.com/aquasecurity/trivy) e é convertido para formato Prometheus.

## Funcionamento
Quando o software inicia, ele efetua um "setup", que cria os diretórios necessário para o funcionamento;

Após isso, o servidor http é iniciado, porém sem informações.

Na sequência as threads de scan são iniciadas. Conforme os objetos da fila interna são consumidos, os resultados são 
armazenados em memória para os passos seguintes (geração dos pontos do prometheus e descoberta se o pod está disponível na internet via ingress).

O passo final é a execução de uma limpeza que remove todos os arquivos temporários gerados pelo trivy.

Depois de tudo, o script "dorme" (mas os endpoints http continuam funcionando), esperando a sua próxima execução.

## Identicação de pods expostas na internet
Depois da execução dos scans, no momento de consolidar os scans, é feito uma consulta em todos os ingresses do cluster.

No ingress, contém qual é o service que aquele path está associado;

Com o service, nós descobrimos qual é o selector que foi utilizado para a criação do endpoint (referente a aquele serviço);

Lendo o endpoint, temos as informações de quais pods fazem parte daquele endpoint.

Quando o pod é encontrado nos endpoints, uma marca é feita: `isPublic: true` 

## Registry com autenticação
Quando um pod tem em sua especificação a entrada
```yaml
  imagePullSecrets:
  - name: secret
```
O script lê o secret especificado e procura pela key `.dockerconfigjson`. Se não encontrar, um erro é informado e o 
scan para aquela imagem não acontece.
Caso não encontre o secret, o scan daquela imagem também não acontece.

## Métrica exportada para o Prometheus

 Metric name| Metric type | Labels/tags  |
| ---------- | ----------- | ----------- |
|pod_security_issue|Gauge|`PodName`=&lt;pod-name&gt; <br> `Namespace`=&lt;pod-namespace&gt;<br> `Image`=&lt;Imagem docker com tag&gt;<br> `IsPublic`=&lt;Está esposta no ingress?&gt;<br> `BaseOS`=&lt;SO Base da imagem&gt;<br> `VulnerabilityID`=&lt;CVE ID&gt;<br> `PkgName`=&lt;Nome do pacote vulnerável&gt;<br> `InstalledVersion`=&lt;Versão do pacote vulnerável&gt;<br> `FixedVersion`=&lt;Versão do pacote corrigida&gt;<br> `Severity`=&lt;Severidade do CVE&gt;|

## Variáveis de ambiente
Todos os parâmetros desse scanner são ajustáveis via variáveis de ambiente.

|Variável|Valor Padrão|Obrigatória|Descrição|
|---|---|---|---|
|LOG_LEVEL|info|não|Nível de log da app. Valores suportados: info, warning, debug, fatal, critical.|
|TRIVY_REPORT_DIR|/tmp/trivyreport|não|Local temporário onde os reports do trivy serão gravados|
|SCAN_INTERVAL|43200|não|Tempo em segundos do intervalo de execução|
|HTTP_PORT|8080|não|Porta onde o endpoint irá ouvir|
|TRIVY_BIN_PATH|./trivy|não|Path do binário do trivy|

## Executando testes unitários
Cobertura dos testes: ![](coverage.svg)
```bash
make tests
```
## Gerando uma nova versão

O build de produção é feito no Google Build

Criando uma nova tag, isso irá sensibilizar um novo build. (a trigger é `v.+`)

O Makefile usa o utilitário `bumpversion` para criar as tags e fazer o push para o repo git.

|Make Option|Action|
|---|---|
|patch|Gera uma versão patch (X.Y.**Z**).|
|minor|Gera uma versão minor (X.**Y**.Z).|
|major|Ger auma versão major (**X**.Y.Z).|
|build-dev|Build local|

## Erros conhecidos
- Scan de imagens hospedadas no quay.io. O quay não suporta a api v2 do registry então não é possível fazer o scan dessas imagens.
    
    Esse erro pode acontecer com qualquer outro registry que não implemente a api v2.
  
    Veja mais sobre esse erro em: https://github.com/google/go-containerregistry/issues/377