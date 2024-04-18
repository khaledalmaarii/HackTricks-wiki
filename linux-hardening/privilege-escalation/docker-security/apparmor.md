# AppArmor

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares de roubo**.

O principal objetivo do WhiteIntel é combater a apropriação de contas e ataques de ransomware resultantes de malwares de roubo de informações.

Você pode verificar o site deles e experimentar o mecanismo gratuitamente em:

{% embed url="https://whiteintel.io" %}

---

## Informações Básicas

AppArmor é um **aperfeiçoamento do kernel projetado para restringir os recursos disponíveis para programas por meio de perfis por programa**, implementando efetivamente o Controle de Acesso Obrigatório (MAC) vinculando atributos de controle de acesso diretamente aos programas em vez de aos usuários. Este sistema opera **carregando perfis no kernel**, geralmente durante a inicialização, e esses perfis ditam quais recursos um programa pode acessar, como conexões de rede, acesso a soquetes brutos e permissões de arquivo.

Existem dois modos operacionais para perfis do AppArmor:

- **Modo de Execução**: Este modo aplica ativamente as políticas definidas dentro do perfil, bloqueando ações que violam essas políticas e registrando quaisquer tentativas de violá-las por meio de sistemas como syslog ou auditd.
- **Modo de Reclamação**: Ao contrário do modo de execução, o modo de reclamação não bloqueia ações que vão contra as políticas do perfil. Em vez disso, ele registra essas tentativas como violações de política sem impor restrições.

### Componentes do AppArmor

- **Módulo do Kernel**: Responsável pela aplicação das políticas.
- **Políticas**: Especificam as regras e restrições para o comportamento do programa e acesso a recursos.
- **Analisador**: Carrega políticas no kernel para aplicação ou relatório.
- **Utilitários**: São programas em modo de usuário que fornecem uma interface para interagir e gerenciar o AppArmor.

### Caminho dos Perfis

Os perfis do AppArmor geralmente são salvos em _**/etc/apparmor.d/**_\
Com `sudo aa-status` você poderá listar os binários que estão restritos por algum perfil. Se você substituir a barra "/" por um ponto do caminho de cada binário listado, obterá o nome do perfil do apparmor dentro da pasta mencionada.

Por exemplo, um perfil **apparmor** para _/usr/bin/man_ estará localizado em _/etc/apparmor.d/usr.bin.man_

### Comandos
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Criando um perfil

* Para indicar o executável afetado, são permitidos **caminhos absolutos e curingas** (para expansão de arquivos) para especificar arquivos.
* Para indicar o acesso que o binário terá sobre **arquivos**, os seguintes **controles de acesso** podem ser usados:
* **r** (leitura)
* **w** (escrita)
* **m** (mapeamento de memória como executável)
* **k** (bloqueio de arquivo)
* **l** (criação de links rígidos)
* **ix** (para executar outro programa com o novo programa herdando a política)
* **Px** (executar sob outro perfil, após limpar o ambiente)
* **Cx** (executar sob um perfil filho, após limpar o ambiente)
* **Ux** (executar sem restrições, após limpar o ambiente)
* **Variáveis** podem ser definidas nos perfis e podem ser manipuladas de fora do perfil. Por exemplo: @{PROC} e @{HOME} (adicionar #include \<tunables/global> ao arquivo de perfil)
* **Regras de negação são suportadas para substituir regras de permissão**.

### aa-genprof

Para começar a criar um perfil facilmente, o apparmor pode ajudar. É possível fazer o **apparmor inspecionar as ações realizadas por um binário e depois permitir que você decida quais ações deseja permitir ou negar**.\
Basta executar:
```bash
sudo aa-genprof /path/to/binary
```
Em seguida, em um console diferente, execute todas as ações que o binário costuma executar:
```bash
/path/to/binary -a dosomething
```
Em seguida, na primeira console pressione "**s**" e depois nas ações gravadas indique se deseja ignorar, permitir ou o que for. Quando terminar, pressione "**f**" e o novo perfil será criado em _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Usando as teclas de seta, você pode selecionar o que deseja permitir/negar/o que for
{% endhint %}

### aa-easyprof

Você também pode criar um modelo de perfil apparmor de um binário com:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
{% hint style="info" %}
Note que por padrão, em um perfil criado, nada é permitido, ou seja, tudo é negado. Você precisará adicionar linhas como `/etc/passwd r,` para permitir a leitura do binário `/etc/passwd`, por exemplo.
{% endhint %}

Você pode então **aplicar** o novo perfil com
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modificando um perfil a partir de logs

A seguinte ferramenta irá ler os logs e perguntar ao usuário se ele deseja permitir algumas das ações proibidas detectadas:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Usando as teclas de seta, você pode selecionar o que deseja permitir/negar/o que for
{% endhint %}

### Gerenciando um Perfil
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Registos

Exemplo de registos **AUDIT** e **DENIED** do ficheiro _/var/log/audit/audit.log_ do executável **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Você também pode obter essas informações usando:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor no Docker

Observe como o perfil **docker-profile** do docker é carregado por padrão:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
Por padrão, o perfil **Apparmor docker-default** é gerado a partir de [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Resumo do perfil docker-default**:

- **Acesso** a toda a **rede**
- **Nenhuma capacidade** é definida (No entanto, algumas capacidades virão da inclusão de regras básicas de base, ou seja, #include \<abstractions/base>)
- **Escrita** em qualquer arquivo **/proc** **não é permitida**
- Outros **subdiretórios**/**arquivos** de /**proc** e /**sys** têm acesso de leitura/escrita/bloqueio/link/execução **negado**
- **Montagem** **não é permitida**
- **Ptrace** só pode ser executado em um processo que está confinado pelo **mesmo perfil apparmor**

Uma vez que você **executa um contêiner docker**, você deve ver a seguinte saída:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Note que o **apparmor até mesmo bloqueará as permissões de capacidades** concedidas ao contêiner por padrão. Por exemplo, ele será capaz de **bloquear a permissão de escrita dentro de /proc mesmo que a capacidade SYS\_ADMIN seja concedida** porque, por padrão, o perfil apparmor do docker nega esse acesso:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Você precisa **desativar o apparmor** para contornar suas restrições:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Observe que por padrão o **AppArmor** também **proibirá o contêiner de montar** pastas de dentro, mesmo com a capacidade SYS\_ADMIN.

Observe que você pode **adicionar/remover** **capacidades** ao contêiner docker (isso ainda será restrito por métodos de proteção como **AppArmor** e **Seccomp**):

* `--cap-add=SYS_ADMIN` concede a capacidade `SYS_ADMIN`
* `--cap-add=ALL` concede todas as capacidades
* `--cap-drop=ALL --cap-add=SYS_PTRACE` remove todas as capacidades e concede apenas `SYS_PTRACE`

{% hint style="info" %}
Normalmente, quando você **descobre** que tem uma **capacidade privilegiada** disponível **dentro** de um **contêiner docker**, mas parte do **exploit não está funcionando**, isso ocorre porque o **apparmor do docker estará impedindo**.
{% endhint %}

### Exemplo

(Exemplo de [**aqui**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Para ilustrar a funcionalidade do AppArmor, criei um novo perfil Docker "mydocker" com a seguinte linha adicionada:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Para ativar o perfil, precisamos fazer o seguinte:
```
sudo apparmor_parser -r -W mydocker
```
Para listar os perfis, podemos executar o seguinte comando. O comando abaixo está listando meu novo perfil do AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Como mostrado abaixo, recebemos um erro ao tentar alterar "/etc/" pois o perfil do AppArmor está impedindo o acesso de escrita ao "/etc".
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### Bypass do AppArmor Docker1

Você pode descobrir qual **perfil do apparmor está sendo executado por um contêiner** usando:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Em seguida, você pode executar a seguinte linha para **encontrar o perfil exato sendo usado**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
### Bypass do Docker AppArmor

No caso estranho em que você pode **modificar o perfil do apparmor do docker e recarregá-lo**, você poderia remover as restrições e "burlá-las".

### Bypass do AppArmor

O **AppArmor é baseado em caminhos**, isso significa que mesmo que ele possa estar **protegendo** arquivos dentro de um diretório como **`/proc`**, se você puder **configurar como o contêiner será executado**, você poderia **montar** o diretório proc do host dentro de **`/host/proc`** e ele **não será mais protegido pelo AppArmor**.

### Bypass do Shebang do AppArmor

Neste [**bug**](https://bugs.launchpad.net/apparmor/+bug/1911431) você pode ver um exemplo de como **mesmo que você esteja impedindo o perl de ser executado com certos recursos**, se você simplesmente criar um script de shell **especificando** na primeira linha **`#!/usr/bin/perl`** e você **executar o arquivo diretamente**, você será capaz de executar o que quiser. Por exemplo:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
## WhiteIntel

<figure><img src=".gitbook/assets/image (1224).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) é um mecanismo de busca alimentado pela **dark web** que oferece funcionalidades **gratuitas** para verificar se uma empresa ou seus clientes foram **comprometidos** por **malwares ladrões**.

O principal objetivo do WhiteIntel é combater invasões de contas e ataques de ransomware resultantes de malwares que roubam informações.

Você pode acessar o site deles e experimentar o mecanismo gratuitamente em:

{% embed url="https://whiteintel.io" %}

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
