# Segurança do Docker

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e **automatizar fluxos de trabalho** facilmente, com as ferramentas comunitárias **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Segurança Básica do Motor Docker**

O motor Docker realiza o trabalho pesado de executar e gerenciar Containers. O motor Docker utiliza recursos do kernel Linux como **Namespaces** e **Cgroups** para fornecer **isolamento** básico entre Containers. Ele também usa recursos como **Capabilities dropping**, **Seccomp**, **SELinux/AppArmor para alcançar um isolamento melhor**.

Por fim, um **plugin de autenticação** pode ser usado para **limitar as ações** que os usuários podem executar.

![](<../../../.gitbook/assets/image (625) (1) (1).png>)

### **Acesso seguro ao motor Docker**

O cliente Docker pode acessar o motor Docker **localmente usando socket Unix ou remotamente usando o mecanismo http**. Para usá-lo remotamente, é necessário utilizar https e **TLS** para que a confidencialidade, integridade e autenticação possam ser garantidas.

Por padrão, escuta no socket Unix `unix:///var/`\
`run/docker.sock` e nas distribuições Ubuntu, as opções de inicialização do Docker são especificadas em `/etc/default/docker`. Para permitir que a API do Docker e o cliente acessem o motor Docker remotamente, precisamos **expor o daemon Docker usando socket http**. Isso pode ser feito por:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H
tcp://192.168.56.101:2376" -> add this to /etc/default/docker
Sudo service docker restart -> Restart Docker daemon
```
Expondo o daemon Docker usando http não é uma boa prática e é necessário proteger a conexão usando https. Existem duas opções: a primeira opção é para o **cliente verificar a identidade do servidor** e na segunda opção **tanto o cliente quanto o servidor verificam a identidade um do outro**. Certificados estabelecem a identidade de um servidor. Para um exemplo de ambas as opções [**verifique esta página**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### **Segurança de imagem de contêiner**

Imagens de contêineres são armazenadas ou em repositório privado ou público. A seguir estão as opções que o Docker oferece para armazenar imagens de contêineres:

* [Docker hub](https://hub.docker.com) – Este é um serviço de registro público fornecido pelo Docker
* [Docker registry](https://github.com/%20docker/distribution) – Este é um projeto de código aberto que os usuários podem usar para hospedar seu próprio registro.
* [Docker trusted registry](https://www.docker.com/docker-trusted-registry) – Esta é a implementação comercial do Docker registry pelo Docker e oferece autenticação de usuário baseada em funções juntamente com integração de serviço de diretório LDAP.

### Varredura de Imagem

Contêineres podem ter **vulnerabilidades de segurança** tanto por causa da imagem base quanto por causa do software instalado em cima da imagem base. O Docker está trabalhando em um projeto chamado **Nautilus** que realiza varredura de segurança em Contêineres e lista as vulnerabilidades. O Nautilus funciona comparando cada camada da imagem do Contêiner com o repositório de vulnerabilidades para identificar falhas de segurança.

Para mais [**informações leia isto**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

O comando **`docker scan`** permite que você faça a varredura de imagens Docker existentes usando o nome ou ID da imagem. Por exemplo, execute o seguinte comando para fazer a varredura da imagem hello-world:
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

Imagens de Container Docker podem ser armazenadas em registro público ou privado. É necessário **assinar** imagens de **Container** para poder confirmar que as imagens não foram adulteradas. O **publicador** de conteúdo é responsável por **assinar** a imagem do Container e enviá-la para o registro.\
A seguir estão alguns detalhes sobre a confiança de conteúdo Docker:

* A confiança de conteúdo Docker é uma implementação do [projeto de código aberto Notary](https://github.com/docker/notary). O projeto de código aberto Notary é baseado no [projeto The Update Framework (TUF)](https://theupdateframework.github.io).
* A confiança de conteúdo Docker **é ativada** com `export DOCKER_CONTENT_TRUST=1`. A partir da versão 1.10 do Docker, a confiança de conteúdo **não é ativada por padrão**.
* **Quando** a confiança de conteúdo está **ativada**, só podemos **baixar imagens assinadas**. Quando a imagem é enviada, precisamos inserir a chave de etiquetagem.
* Quando o publicador **envia** a imagem pela **primeira** **vez** usando docker push, é necessário inserir uma **frase-senha** para a **chave raiz e chave de etiquetagem**. Outras chaves são geradas automaticamente.
* O Docker também adicionou suporte para chaves de hardware usando Yubikey e os detalhes estão disponíveis [aqui](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).

A seguir está o **erro** que recebemos quando **a confiança de conteúdo está ativada e a imagem não está assinada**.
```shell-session
$ docker pull smakam/mybusybox
Using default tag: latest
No trust data for latest
```
A saída a seguir mostra a **imagem do Container sendo enviada para o Docker hub com assinatura** ativada. Como esta não é a primeira vez, o usuário é solicitado a inserir apenas a frase secreta para a chave do repositório.
```shell-session
$ docker push smakam/mybusybox:v2
The push refers to a repository [docker.io/smakam/mybusybox]
a7022f99b0cc: Layer already exists
5f70bf18a086: Layer already exists
9508eff2c687: Layer already exists
v2: digest: sha256:8509fa814029e1c1baf7696b36f0b273492b87f59554a33589e1bd6283557fc9 size: 2205
Signing and pushing trust metadata
Enter passphrase for repository key with ID 001986b (docker.io/smakam/mybusybox):
```
É necessário armazenar a chave de root, a chave do repositório, bem como a frase secreta em um local seguro. O seguinte comando pode ser usado para fazer backup das chaves privadas:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Ao mudar o host do Docker, precisei mover as chaves raiz e as chaves do repositório para operar a partir do novo host.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) para construir e **automatizar fluxos de trabalho** com o apoio das ferramentas comunitárias **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Recursos de Segurança de Containers

<details>

<summary>Resumo dos Recursos de Segurança de Containers</summary>

**Namespaces**

Namespaces são úteis para isolar um projeto dos outros, isolando comunicações de processos, rede, montagens... É útil para isolar o processo do docker de outros processos (e até a pasta /proc) para que não possa escapar abusando de outros processos.

Poderia ser possível "escapar" ou mais exatamente **criar novos namespaces** usando o binário **`unshare`** (que usa a syscall **`unshare`**). O Docker por padrão previne isso, mas o kubernetes não (no momento desta escrita).\
De qualquer forma, isso é útil para criar novos namespaces, mas **não para voltar aos namespaces padrões do host** (a menos que você tenha acesso a algum `/proc` dentro dos namespaces do host, onde você poderia usar **`nsenter`** para entrar nos namespaces do host).

**CGroups**

Isso permite limitar recursos e não afeta a segurança do isolamento do processo (exceto pelo `release_agent` que poderia ser usado para escapar).

**Capabilities Drop**

Considero isso uma das características **mais importantes** em relação à segurança do isolamento de processos. Isso porque sem as capacidades, mesmo que o processo esteja sendo executado como root **você não será capaz de realizar algumas ações privilegiadas** (porque a syscall chamada **`syscall`** retornará erro de permissão porque o processo não tem as capacidades necessárias).

Estas são as **capacidades restantes** após o processo descartar as outras:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Está ativado por padrão no Docker. Ajuda a **limitar ainda mais os syscalls** que o processo pode chamar.\
O **perfil Seccomp padrão do Docker** pode ser encontrado em [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

O Docker possui um modelo que você pode ativar: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Isso permitirá reduzir capacidades, syscalls, acesso a arquivos e pastas...

</details>

### Namespaces

**Namespaces** são um recurso do kernel Linux que **particiona recursos do kernel** de tal forma que um conjunto de **processos** **vê** um conjunto de **recursos** enquanto **outro** conjunto de **processos** vê um **conjunto diferente** de recursos. O recurso funciona tendo o mesmo namespace para um conjunto de recursos e processos, mas esses namespaces referem-se a recursos distintos. Recursos podem existir em múltiplos espaços.

O Docker utiliza os seguintes Namespaces do kernel Linux para alcançar o isolamento de Containers:

* pid namespace
* mount namespace
* network namespace
* ipc namespace
* UTS namespace

Para **mais informações sobre os namespaces**, consulte a seguinte página:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

O recurso do kernel Linux **cgroups** fornece a capacidade de **restringir recursos como cpu, memória, io, largura de banda de rede entre** um conjunto de processos. O Docker permite criar Containers usando o recurso cgroup, o que permite o controle de recursos para o Container específico.\
A seguir, um Container criado com memória do espaço do usuário limitada a 500m, memória do kernel limitada a 50m, compartilhamento de cpu para 512, blkioweight para 400. O compartilhamento de CPU é uma proporção que controla o uso de CPU do Container. Tem um valor padrão de 1024 e varia entre 0 e 1024. Se três Containers têm o mesmo compartilhamento de CPU de 1024, cada Container pode usar até 33% da CPU em caso de contenção de recurso de CPU. blkio-weight é uma proporção que controla o IO do Container. Tem um valor padrão de 500 e varia entre 10 e 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Para obter o cgroup de um container, você pode fazer:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Para mais informações, verifique:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Capacidades

Capacidades permitem **um controle mais refinado das capacidades que podem ser permitidas** para o usuário root. O Docker utiliza o recurso de capacidades do kernel Linux para **limitar as operações que podem ser feitas dentro de um Container**, independentemente do tipo de usuário.

Quando um container Docker é executado, o **processo descarta capacidades sensíveis que o processo poderia usar para escapar do isolamento**. Isso tenta garantir que o processo não será capaz de realizar ações sensíveis e escapar:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp no Docker

Este é um recurso de segurança que permite ao Docker **limitar as chamadas de sistema** que podem ser usadas dentro do container:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor no Docker

**AppArmor** é um aprimoramento do kernel para confinar **containers** a um conjunto **limitado** de **recursos** com **perfis por programa**:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux no Docker

[SELinux](https://www.redhat.com/en/blog/latest-container-exploit-runc-can-be-blocked-selinux) é um **sistema de rotulagem**. Todo **processo** e cada objeto do **sistema de arquivos** tem um **rótulo**. As políticas do SELinux definem regras sobre o que um **rótulo de processo é permitido fazer com todos os outros rótulos** no sistema.

Os mecanismos de containers iniciam **processos de containers com um único rótulo confinado do SELinux**, geralmente `container_t`, e então definem que o interior do container seja rotulado como `container_file_t`. As regras das políticas do SELinux basicamente dizem que os processos **`container_t` só podem ler/escrever/executar arquivos rotulados como `container_file_t`**.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

Um plugin de autorização **aprova** ou **nega** **solicitações** ao **daemon** do Docker com base tanto no contexto de **autenticação** atual quanto no contexto do **comando**. O contexto de **autenticação** contém todos os **detalhes do usuário** e o **método de autenticação**. O contexto do **comando** contém todos os dados **relevantes** da **solicitação**.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS a partir de um container

Se você não está limitando adequadamente os recursos que um container pode usar, um container comprometido poderia realizar um DoS no host onde está sendo executado.

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Ataque de negação de serviço por consumo de largura de banda
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Flags Interessantes do Docker

### flag --privileged

Na página a seguir, você pode aprender **o que a flag `--privileged` implica**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Se você estiver executando um container onde um atacante consegue acessar como um usuário de baixo privilégio. Se você tiver um **binário suid mal configurado**, o atacante pode abusar dele e **escalar privilégios dentro** do container. O que pode permitir que ele escape dele.

Executar o container com a opção **`no-new-privileges`** habilitada irá **prevenir esse tipo de escalada de privilégios**.
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
Para mais opções de **`--security-opt`**, consulte: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Outras Considerações de Segurança

### Gerenciamento de Segredos

Primeiro de tudo, **não os coloque dentro da sua imagem!**

Além disso, **não use variáveis de ambiente** para suas informações sensíveis. Qualquer pessoa que possa executar `docker inspect` ou `exec` no container pode encontrar seu segredo.

Volumes do Docker são melhores. Eles são a maneira recomendada de acessar suas informações sensíveis na documentação do Docker. Você pode **usar um volume como um sistema de arquivos temporário mantido na memória**. Volumes removem o risco de `docker inspect` e de registro em logs. No entanto, **usuários root ainda podem ver o segredo, assim como qualquer um que possa executar `exec` no container**.

Ainda **melhor que volumes, use segredos do Docker**.

Se você precisa do **segredo na sua imagem**, você pode usar **BuildKit**. BuildKit reduz significativamente o tempo de construção e tem outras características interessantes, incluindo **suporte a segredos durante o tempo de construção**.

Existem três maneiras de especificar o backend do BuildKit para que você possa usar suas funcionalidades agora:

1. Defina como uma variável de ambiente com `export DOCKER_BUILDKIT=1`.
2. Inicie seu comando `build` ou `run` com `DOCKER_BUILDKIT=1`.
3. Ative o BuildKit por padrão. Configure em /_etc/docker/daemon.json_ para _true_ com: `{ "features": { "buildkit": true } }`. Depois, reinicie o Docker.
4. Então você pode usar segredos durante o tempo de construção com a flag `--secret` assim:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Onde seu arquivo especifica seus segredos como par chave-valor.

Esses segredos são excluídos do cache de construção da imagem e da imagem final.

Se você precisa do seu **segredo no seu contêiner em execução**, e não apenas durante a construção da sua imagem, use **Docker Compose ou Kubernetes**.

Com o Docker Compose, adicione o par chave-valor dos segredos a um serviço e especifique o arquivo de segredo. Agradecimento especial à [resposta do Stack Exchange](https://serverfault.com/a/936262/535325) pela dica de segredos do Docker Compose que o exemplo abaixo foi adaptado.

Exemplo de `docker-compose.yml` com segredos:
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
Então inicie o Compose como de costume com `docker-compose up --build my_service`.

Se você está usando [Kubernetes](https://kubernetes.io/docs/concepts/configuration/secret/), ele tem suporte para segredos. [Helm-Secrets](https://github.com/futuresimple/helm-secrets) pode ajudar a tornar o gerenciamento de segredos no K8s mais fácil. Além disso, o K8s tem Controles de Acesso Baseados em Funções (RBAC) — assim como o Docker Enterprise. RBAC torna o gerenciamento de Acesso a Segredos mais gerenciável e mais seguro para equipes.

### gVisor

**gVisor** é um kernel de aplicação, escrito em Go, que implementa uma parte substancial da superfície do sistema Linux. Inclui um runtime da [Iniciativa de Contêineres Abertos (OCI)](https://www.opencontainers.org) chamado `runsc` que fornece uma **fronteira de isolamento entre a aplicação e o kernel do host**. O runtime `runsc` integra-se com Docker e Kubernetes, facilitando a execução de contêineres em sandbox.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** é uma comunidade de código aberto trabalhando para construir um runtime de contêiner seguro com máquinas virtuais leves que se comportam e têm desempenho como contêineres, mas fornecem **isolamento de carga de trabalho mais forte usando tecnologia de virtualização de hardware** como uma segunda camada de defesa.

{% embed url="https://katacontainers.io/" %}

### Dicas Resumidas

* **Não use a flag `--privileged` ou monte um** [**socket do Docker dentro do contêiner**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** O socket do Docker permite a criação de contêineres, então é uma maneira fácil de assumir o controle total do host, por exemplo, executando outro contêiner com a flag `--privileged`.
* **Não execute como root dentro do contêiner. Use um** [**usuário diferente**](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user) **e** [**namespaces de usuário**](https://docs.docker.com/engine/security/userns-remap/)**.** O root no contêiner é o mesmo que no host, a menos que seja remapeado com namespaces de usuário. Ele é apenas levemente restrito, principalmente, por namespaces do Linux, capacidades e cgroups.
* [**Remova todas as capacidades**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) e habilite apenas aquelas que são necessárias** (`--cap-add=...`). Muitas cargas de trabalho não precisam de nenhuma capacidade e adicioná-las aumenta o escopo de um ataque potencial.
* [**Use a opção de segurança “no-new-privileges”**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) para impedir que processos ganhem mais privilégios, por exemplo, através de binários suid.
* [**Limite os recursos disponíveis para o contêiner**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Limites de recursos podem proteger a máquina contra ataques de negação de serviço.
* **Ajuste** [**perfis de seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(ou SELinux)** para restringir as ações e chamadas de sistema disponíveis para o contêiner ao mínimo necessário.
* **Use** [**imagens oficiais do docker**](https://docs.docker.com/docker-hub/official_images/) **e exija assinaturas** ou construa as suas próprias com base nelas. Não herde ou use imagens [comprometidas](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Além disso, armazene chaves raiz, frases de acesso em um local seguro. O Docker tem planos para gerenciar chaves com UCP.
* **Reconstrua regularmente** suas imagens para **aplicar patches de segurança ao host e imagens.**
* Gerencie seus **segredos com sabedoria** para que seja difícil para o atacante acessá-los.
* Se você **expõe o daemon do docker, use HTTPS** com autenticação de cliente e servidor.
* No seu Dockerfile, **prefira COPY em vez de ADD**. ADD extrai automaticamente arquivos compactados e pode copiar arquivos de URLs. COPY não tem essas capacidades. Sempre que possível, evite usar ADD para não estar suscetível a ataques através de URLs remotas e arquivos Zip.
* Tenha **contêineres separados para cada micro-serviço**
* **Não coloque ssh** dentro do contêiner, “docker exec” pode ser usado para acessar o Contêiner via ssh.
* Tenha **imagens de contêiner menores**

## Docker Breakout / Escalada de Privilégios

Se você está **dentro de um contêiner docker** ou tem acesso a um usuário no **grupo docker**, você pode tentar **escapar e escalar privilégios**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Bypass de Plugin de Autenticação do Docker

Se você tem acesso ao socket do docker ou tem acesso a um usuário no **grupo docker, mas suas ações estão sendo limitadas por um plugin de autenticação do docker**, verifique se você pode **burlá-lo:**

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Fortalecimento do Docker

* A ferramenta [**docker-bench-security**](https://github.com/docker/docker-bench-security) é um script que verifica dezenas de práticas recomendadas comuns ao implantar contêineres Docker em produção. Os testes são todos automatizados e baseiam-se no [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Você precisa executar a ferramenta a partir do host que executa o docker ou de um contêiner com privilégios suficientes. Descubra **como executá-lo no README:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Referências

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/_fel1x/status/1151487051986087936)
* [https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html](https://ajxchapman.github.io/containers/2020/11/19/privileged-container-escape.html)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-1overview/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/)
* [https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-4container-image/)
* [https://en.wikipedia.org/wiki/Linux_namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)
* [https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57](https://towardsdatascience.com/top-20-docker-security-tips-81c41dd06f57)

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Use [**Trickest**](https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks) para construir e **automatizar fluxos de trabalho** com facilidade, alimentados pelas ferramentas comunitárias **mais avançadas** do mundo.\
Obtenha Acesso Hoje:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas dicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
