# Segurança do Docker

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Segurança Básica do Docker Engine**

O **Docker engine** utiliza os **Namespaces** e **Cgroups** do kernel Linux para isolar contêineres, oferecendo uma camada básica de segurança. Proteção adicional é fornecida por meio da **redução de Capacidades**, **Seccomp** e **SELinux/AppArmor**, aprimorando o isolamento do contêiner. Um **plugin de autenticação** pode restringir ainda mais as ações do usuário.

![Segurança do Docker](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Acesso Seguro ao Docker Engine

O Docker engine pode ser acessado localmente via um socket Unix ou remotamente usando HTTP. Para acesso remoto, é essencial empregar HTTPS e **TLS** para garantir confidencialidade, integridade e autenticação.

O Docker engine, por padrão, escuta no socket Unix em `unix:///var/run/docker.sock`. Em sistemas Ubuntu, as opções de inicialização do Docker são definidas em `/etc/default/docker`. Para habilitar o acesso remoto à API e ao cliente do Docker, exponha o daemon do Docker em um socket HTTP adicionando as seguintes configurações:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
No entanto, expor o daemon do Docker via HTTP não é recomendado devido a preocupações de segurança. É aconselhável garantir conexões usando HTTPS. Existem duas abordagens principais para garantir a conexão:

1. O cliente verifica a identidade do servidor.
2. Tanto o cliente quanto o servidor autenticam mutuamente a identidade um do outro.

Certificados são utilizados para confirmar a identidade de um servidor. Para exemplos detalhados de ambos os métodos, consulte [**este guia**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Segurança de Imagens de Contêiner

As imagens de contêiner podem ser armazenadas em repositórios privados ou públicos. O Docker oferece várias opções de armazenamento para imagens de contêiner:

* [**Docker Hub**](https://hub.docker.com): Um serviço de registro público do Docker.
* [**Docker Registry**](https://github.com/docker/distribution): Um projeto de código aberto que permite aos usuários hospedar seu próprio registro.
* [**Docker Trusted Registry**](https://www.docker.com/docker-trusted-registry): Oferta de registro comercial do Docker, com autenticação de usuário baseada em funções e integração com serviços de diretório LDAP.

### Verificação de Imagens

Os contêineres podem ter **vulnerabilidades de segurança** seja por causa da imagem base ou por causa do software instalado em cima da imagem base. O Docker está trabalhando em um projeto chamado **Nautilus** que faz a verificação de segurança dos Contêineres e lista as vulnerabilidades. O Nautilus funciona comparando cada camada da imagem do Contêiner com o repositório de vulnerabilidades para identificar falhas de segurança.

Para mais [**informações leia isso**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

O comando **`docker scan`** permite que você escaneie imagens Docker existentes usando o nome ou ID da imagem. Por exemplo, execute o seguinte comando para escanear a imagem hello-world:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <ontainer_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Assinatura de Imagem Docker

A assinatura de imagem Docker garante a segurança e integridade das imagens usadas em containers. Aqui está uma explicação resumida:

- **Confiança de Conteúdo Docker** utiliza o projeto Notary, baseado no The Update Framework (TUF), para gerenciar a assinatura de imagens. Para mais informações, consulte [Notary](https://github.com/docker/notary) e [TUF](https://theupdateframework.github.io).
- Para ativar a confiança de conteúdo do Docker, defina `export DOCKER_CONTENT_TRUST=1`. Este recurso está desativado por padrão no Docker versão 1.10 e posterior.
- Com este recurso habilitado, apenas imagens assinadas podem ser baixadas. O envio inicial da imagem requer a definição de frases-passe para as chaves raiz e de marcação, com o Docker também suportando Yubikey para segurança aprimorada. Mais detalhes podem ser encontrados [aqui](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Tentar baixar uma imagem não assinada com a confiança de conteúdo habilitada resulta em um erro "No trust data for latest".
- Para envios de imagens após o primeiro, o Docker solicita a frase-passe da chave do repositório para assinar a imagem.

Para fazer backup de suas chaves privadas, use o comando:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Ao trocar de hosts Docker, é necessário mover as chaves raiz e do repositório para manter as operações.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir facilmente e **automatizar fluxos de trabalho** com as ferramentas comunitárias mais avançadas do mundo.\
Acesse hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recursos de Segurança de Contêineres

<details>

<summary>Resumo dos Recursos de Segurança de Contêineres</summary>

#### Recursos Principais de Isolamento de Processos

Em ambientes containerizados, isolar projetos e seus processos é fundamental para a segurança e gerenciamento de recursos. Aqui está uma explicação simplificada dos conceitos-chave:

**Namespaces**

* **Propósito**: Garantir o isolamento de recursos como processos, rede e sistemas de arquivos. Especificamente no Docker, os namespaces mantêm os processos de um contêiner separados do host e de outros contêineres.
* **Uso de `unshare`**: O comando `unshare` (ou a chamada de sistema subjacente) é utilizado para criar novos namespaces, fornecendo uma camada adicional de isolamento. No entanto, enquanto o Kubernetes não bloqueia isso por padrão, o Docker o faz.
* **Limitação**: Criar novos namespaces não permite que um processo reverta para os namespaces padrão do host. Para penetrar nos namespaces do host, normalmente seria necessário acesso ao diretório `/proc` do host, usando `nsenter` para entrada.

**Grupos de Controle (CGroups)**

* **Função**: Principalmente usado para alocar recursos entre processos.
* **Aspecto de Segurança**: Os CGroups em si não oferecem segurança de isolamento, exceto pelo recurso `release_agent`, que, se configurado incorretamente, poderia ser potencialmente explorado para acesso não autorizado.

**Descarte de Capacidades**

* **Importância**: É um recurso de segurança crucial para o isolamento de processos.
* **Funcionalidade**: Restringe as ações que um processo raiz pode executar ao descartar certas capacidades. Mesmo que um processo seja executado com privilégios de root, a falta das capacidades necessárias impede a execução de ações privilegiadas, pois as chamadas de sistema falharão devido a permissões insuficientes.

Essas são as **capacidades restantes** após o processo descartar as outras:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

É ativado por padrão no Docker. Ajuda a **limitar ainda mais as syscalls** que o processo pode chamar.\
O **perfil Seccomp padrão do Docker** pode ser encontrado em [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

O Docker possui um modelo que você pode ativar: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Isso permitirá reduzir capacidades, syscalls, acesso a arquivos e pastas...

</details>

### Namespaces

**Namespaces** são um recurso do kernel Linux que **particiona recursos do kernel** de forma que um conjunto de **processos veja** um conjunto de **recursos** enquanto **outro** conjunto de **processos** vê um **conjunto diferente** de recursos. O recurso funciona tendo o mesmo namespace para um conjunto de recursos e processos, mas esses namespaces se referem a recursos distintos. Recursos podem existir em múltiplos espaços.

O Docker faz uso dos seguintes Namespaces do kernel Linux para alcançar o isolamento de Containers:

* namespace pid
* namespace mount
* namespace network
* namespace ipc
* namespace UTS

Para **mais informações sobre os namespaces** confira a seguinte página:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

O recurso do kernel Linux **cgroups** fornece a capacidade de **restringir recursos como cpu, memória, io, largura de banda de rede entre** um conjunto de processos. O Docker permite criar Containers usando o recurso cgroup que permite o controle de recursos para o Container específico.\
A seguir está um Container criado com a memória do espaço do usuário limitada a 500m, memória do kernel limitada a 50m, compartilhamento de cpu para 512, blkioweight para 400. O compartilhamento de CPU é uma proporção que controla o uso de CPU do Container. Tem um valor padrão de 1024 e varia entre 0 e 1024. Se três Containers têm o mesmo compartilhamento de CPU de 1024, cada Container pode usar até 33% da CPU em caso de contenção de recursos de CPU. blkio-weight é uma proporção que controla o IO do Container. Tem um valor padrão de 500 e varia entre 10 e 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Para obter o cgroup de um contêiner, você pode fazer:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Para mais informações, consulte:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capacidades

As capacidades permitem um **controle mais preciso das capacidades que podem ser permitidas** para o usuário root. O Docker utiliza o recurso de capacidade do kernel Linux para **limitar as operações que podem ser realizadas dentro de um contêiner** independentemente do tipo de usuário.

Quando um contêiner Docker é executado, o **processo descarta as capacidades sensíveis que o processo poderia usar para escapar do isolamento**. Isso tenta garantir que o processo não consiga realizar ações sensíveis e escapar:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp no Docker

Este é um recurso de segurança que permite ao Docker **limitar as chamadas de sistema** que podem ser usadas dentro do contêiner:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor no Docker

**AppArmor** é um aprimoramento do kernel para confinar **contêineres** a um **conjunto limitado** de **recursos** com **perfis por programa**.:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux no Docker

* **Sistema de Rotulagem**: O SELinux atribui um rótulo único a cada processo e objeto do sistema de arquivos.
* **Aplicação de Políticas**: Ele aplica políticas de segurança que definem quais ações um rótulo de processo pode executar em outros rótulos dentro do sistema.
* **Rótulos de Processos de Contêiner**: Quando os motores de contêiner iniciam processos de contêiner, eles são normalmente atribuídos a um rótulo SELinux confinado, comumente `container_t`.
* **Rotulagem de Arquivos dentro de Contêineres**: Arquivos dentro do contêiner geralmente são rotulados como `container_file_t`.
* **Regras de Política**: A política SELinux garante principalmente que processos com o rótulo `container_t` só possam interagir (ler, escrever, executar) com arquivos rotulados como `container_file_t`.

Esse mecanismo garante que mesmo que um processo dentro de um contêiner seja comprometido, ele está confinado a interagir apenas com objetos que possuem os rótulos correspondentes, limitando significativamente o potencial de danos desses comprometimentos.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

No Docker, um plugin de autorização desempenha um papel crucial na segurança ao decidir se permite ou bloqueia solicitações ao daemon do Docker. Essa decisão é tomada examinando dois contextos-chave:

* **Contexto de Autenticação**: Isso inclui informações abrangentes sobre o usuário, como quem são e como se autenticaram.
* **Contexto de Comando**: Isso compreende todos os dados pertinentes relacionados à solicitação sendo feita.

Esses contextos ajudam a garantir que apenas solicitações legítimas de usuários autenticados sejam processadas, aprimorando a segurança das operações do Docker.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS a partir de um contêiner

Se você não estiver limitando adequadamente os recursos que um contêiner pode usar, um contêiner comprometido poderia realizar um ataque de negação de serviço (DoS) no host onde está sendo executado.

* DoS de CPU
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* DoS de largura de banda
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Flags Interessantes do Docker

### --privileged flag

Na página a seguir, você pode aprender **o que implica a flag `--privileged`**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Se você estiver executando um contêiner onde um invasor consegue acessar como um usuário de baixo privilégio. Se você tiver um **binário suid mal configurado**, o invasor pode abusar dele e **elevar os privilégios internos** do contêiner. O que pode permitir que ele escape dele.

Executar o contêiner com a opção **`no-new-privileges`** habilitada irá **prevenir esse tipo de escalonamento de privilégios**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Outros
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Para mais opções de **`--security-opt`** verifique: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Outras Considerações de Segurança

### Gerenciamento de Segredos: Melhores Práticas

É crucial evitar embutir segredos diretamente em imagens Docker ou usar variáveis de ambiente, pois esses métodos expõem suas informações sensíveis a qualquer pessoa com acesso ao contêiner por meio de comandos como `docker inspect` ou `exec`.

**Volumes do Docker** são uma alternativa mais segura, recomendada para acessar informações sensíveis. Eles podem ser utilizados como um sistema de arquivos temporário na memória, mitigando os riscos associados ao `docker inspect` e ao logging. No entanto, usuários root e aqueles com acesso `exec` ao contêiner ainda podem acessar os segredos.

**Segredos do Docker** oferecem um método ainda mais seguro para lidar com informações sensíveis. Para casos que exigem segredos durante a fase de construção da imagem, o **BuildKit** apresenta uma solução eficiente com suporte para segredos de tempo de construção, aprimorando a velocidade de construção e fornecendo recursos adicionais.

Para aproveitar o BuildKit, ele pode ser ativado de três maneiras:

1. Através de uma variável de ambiente: `export DOCKER_BUILDKIT=1`
2. Prefixando comandos: `DOCKER_BUILDKIT=1 docker build .`
3. Habilitando-o por padrão na configuração do Docker: `{ "features": { "buildkit": true } }`, seguido por um reinício do Docker.

O BuildKit permite o uso de segredos de tempo de construção com a opção `--secret`, garantindo que esses segredos não sejam incluídos no cache de construção da imagem ou na imagem final, usando um comando como:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Para segredos necessários em um contêiner em execução, o **Docker Compose e o Kubernetes** oferecem soluções robustas. O Docker Compose utiliza uma chave `secrets` na definição do serviço para especificar arquivos secretos, conforme mostrado em um exemplo de `docker-compose.yml`:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Esta configuração permite o uso de segredos ao iniciar serviços com o Docker Compose.

Em ambientes Kubernetes, os segredos são suportados nativamente e podem ser gerenciados com ferramentas como [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Os Controles de Acesso Baseados em Função (RBAC) do Kubernetes aprimoram a segurança no gerenciamento de segredos, semelhante ao Docker Enterprise.

### gVisor

**gVisor** é um kernel de aplicativo, escrito em Go, que implementa uma parte substancial da superfície do sistema Linux. Ele inclui um tempo de execução [Open Container Initiative (OCI)](https://www.opencontainers.org) chamado `runsc` que fornece um **limite de isolamento entre o aplicativo e o kernel do host**. O tempo de execução `runsc` integra-se com o Docker e o Kubernetes, tornando simples a execução de contêineres isolados.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** é uma comunidade de código aberto que trabalha para construir um tempo de execução de contêiner seguro com máquinas virtuais leves que se comportam e executam como contêineres, mas fornecem **isolamento de carga de trabalho mais forte usando tecnologia de virtualização de hardware** como uma segunda camada de defesa.

{% embed url="https://katacontainers.io/" %}

### Dicas Resumidas

* **Não use a flag `--privileged` ou monte um** [**socket do Docker dentro do contêiner**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** O socket do Docker permite a criação de contêineres, sendo uma maneira fácil de assumir o controle total do host, por exemplo, executando outro contêiner com a flag `--privileged`.
* Não execute como root dentro do contêiner. Use um [**usuário diferente**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) e [**espaços de nomes de usuário**](https://docs.docker.com/engine/security/userns-remap/). O root no contêiner é o mesmo que no host, a menos que seja remapeado com espaços de nomes de usuário. Ele é apenas levemente restrito, principalmente, por espaços de nomes do Linux, capacidades e cgroups.
* [**Revogue todas as capacidades**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) e habilite apenas as necessárias** (`--cap-add=...`). Muitas cargas de trabalho não precisam de nenhuma capacidade e adicioná-las aumenta o escopo de um possível ataque.
* [**Use a opção de segurança “no-new-privileges”**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) para evitar que processos obtenham mais privilégios, por exemplo, através de binários suid.
* [**Limite os recursos disponíveis para o contêiner**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Os limites de recursos podem proteger a máquina de ataques de negação de serviço.
* **Ajuste os perfis de** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(ou SELinux)** para restringir as ações e chamadas de sistema disponíveis para o contêiner ao mínimo necessário.
* **Use** [**imagens oficiais do Docker**](https://docs.docker.com/docker-hub/official_images/) **e exija assinaturas** ou construa suas próprias com base nelas. Não herde ou use imagens [comprometidas](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Armazene também chaves raiz, frases secretas em um local seguro. O Docker tem planos para gerenciar chaves com UCP.
* **Reconstrua regularmente** suas imagens para **aplicar patches de segurança ao host e imagens**.
* Gerencie seus **segredos com sabedoria** para dificultar o acesso do atacante a eles.
* Se **expor o daemon do Docker, use HTTPS** com autenticação de cliente e servidor.
* Em seu Dockerfile, **prefira COPY em vez de ADD**. ADD extrai automaticamente arquivos compactados e pode copiar arquivos de URLs. COPY não possui essas capacidades. Sempre que possível, evite usar ADD para não ficar suscetível a ataques por meio de URLs remotos e arquivos Zip.
* Tenha **contêineres separados para cada microsserviço**.
* **Não coloque ssh** dentro do contêiner, o “docker exec” pode ser usado para ssh no Contêiner.
* Tenha **imagens de contêiner menores**

## Fuga / Escalação de Privilégios do Docker

Se você está **dentro de um contêiner do Docker** ou tem acesso a um usuário no **grupo docker**, você pode tentar **escapar e escalar privilégios**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Bypass de Plugin de Autenticação do Docker

Se você tem acesso ao socket do Docker ou tem acesso a um usuário no **grupo docker, mas suas ações estão sendo limitadas por um plugin de autenticação do docker**, verifique se você pode **burlá-lo:**

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Reforçando o Docker

* A ferramenta [**docker-bench-security**](https://github.com/docker/docker-bench-security) é um script que verifica dezenas de práticas recomendadas comuns ao implantar contêineres Docker em produção. Os testes são todos automatizados e baseados no [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Você precisa executar a ferramenta no host que executa o Docker ou em um contêiner com privilégios suficientes. Saiba **como executá-lo no README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Referências

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux\_namespaces](https://en.wikipedia.org/wiki/Linux\_namespaces)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://www.redhat.com/sysadmin/privileged-flag-container-engines](https://www.redhat.com/sysadmin/privileged-flag-container-engines)
* [https://docs.docker.com/engine/extend/plugins\_authorization](https://docs.docker.com/engine/extend/plugins\_authorization)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)
* [https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/](https://resources.experfy.com/bigdata-cloud/top-20-docker-security-tips/)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com facilidade, alimentados pelas ferramentas comunitárias mais avançadas do mundo.\
Tenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>
Outras maneiras de apoiar o HackTricks:

- Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
- Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
- Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
- **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
- **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) do Github.

</details>
