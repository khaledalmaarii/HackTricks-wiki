# CGroups

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

**Grupos de controle do Linux**, também conhecidos como cgroups, são um recurso do kernel do Linux que permite **limitar**, fiscalizar e priorizar **recursos do sistema** para um conjunto de processos. Cgroups oferecem uma maneira de **gerenciar e isolar o uso de recursos** (CPU, memória, E/S de disco, rede, etc.) de grupos de processos em um sistema. Isso pode ser útil para muitos propósitos, como limitar os recursos disponíveis para um grupo específico de processos, isolar certos tipos de cargas de trabalho de outros, ou priorizar o uso de recursos do sistema entre diferentes grupos de processos.

Existem **duas versões de cgroups**, 1 e 2, e ambas estão atualmente em uso e podem ser configuradas simultaneamente em um sistema. A **diferença mais significativa** entre a versão 1 dos cgroups e a **versão 2** é que a última introduziu uma nova organização hierárquica para os cgroups, onde os grupos podem ser organizados em uma **estrutura em árvore** com relações de pai-filho. Isso permite um controle mais flexível e detalhado sobre a alocação de recursos entre diferentes grupos de processos.

Além da nova organização hierárquica, a versão 2 dos cgroups também introduziu **várias outras mudanças e melhorias**, como suporte para **novos controladores de recursos**, melhor suporte para aplicações legadas e desempenho aprimorado.

No geral, a **versão 2 dos cgroups oferece mais recursos e melhor desempenho** do que a versão 1, mas a última ainda pode ser usada em certos cenários onde a compatibilidade com sistemas mais antigos é uma preocupação.

Você pode listar os cgroups v1 e v2 para qualquer processo olhando para o arquivo cgroup em /proc/\<pid>. Você pode começar olhando para os cgroups do seu shell com este comando:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
Não se alarme se o **output for significativamente mais curto** no seu sistema; isso apenas significa que você provavelmente **tem apenas cgroups v2**. Cada linha de output aqui começa com um número e é um cgroup diferente. Aqui estão algumas dicas sobre como lê-lo:

* **Números 2–12 são para cgroups v1**. Os **controladores** para esses estão listados ao lado do número.
* **Número 1** também é para **versão 1**, mas não tem um controlador. Este cgroup é apenas para **fins de gestão** (neste caso, systemd configurou-o).
* A última linha, **número 0**, é para **cgroups v2**. Não há controladores visíveis aqui. Em um sistema que não tem cgroups v1, esta será a única linha de output.
* **Nomes são hierárquicos e parecem partes de caminhos de arquivos**. Você pode ver neste exemplo que alguns dos cgroups são nomeados /user.slice e outros /user.slice/user-1000.slice/session-2.scope.
* O nome /testcgroup foi criado para mostrar que em cgroups v1, os cgroups para um processo podem ser completamente independentes.
* **Nomes sob user.slice** que incluem session são sessões de login, atribuídas pelo systemd. Você os verá quando estiver olhando para os cgroups de um shell. Os **cgroups** para os seus **serviços do sistema** estarão **sob system.slice**.

### Visualizando cgroups

Cgroups são tipicamente **acessados através do sistema de arquivos**. Isso contrasta com a interface tradicional de chamada de sistema Unix para interagir com o kernel.\
Para explorar a configuração de cgroup de um shell, você pode olhar no arquivo `/proc/self/cgroup` para encontrar o cgroup do shell, e então navegar até o diretório `/sys/fs/cgroup` (ou `/sys/fs/cgroup/unified`) e procurar por um **diretório com o mesmo nome do cgroup**. Mudar para este diretório e olhar ao redor permitirá que você veja as várias **configurações e informações de uso de recursos para o cgroup**.

<figure><img src="../../../.gitbook/assets/image (10) (2) (2).png" alt=""><figcaption></figcaption></figure>

Entre os muitos arquivos que podem estar aqui, **os principais arquivos de interface cgroup começam com `cgroup`**. Comece olhando para `cgroup.procs` (usar cat está bem), que lista os processos no cgroup. Um arquivo semelhante, `cgroup.threads`, também inclui threads.

<figure><img src="../../../.gitbook/assets/image (1) (1) (5).png" alt=""><figcaption></figcaption></figure>

A maioria dos cgroups usados para shells têm esses dois controladores, que podem controlar a **quantidade de memória** usada e o **número total de processos no cgroup**. Para interagir com um controlador, procure pelos **arquivos que correspondem ao prefixo do controlador**. Por exemplo, se você quiser ver o número de threads rodando no cgroup, consulte pids.current:

<figure><img src="../../../.gitbook/assets/image (3) (5).png" alt=""><figcaption></figcaption></figure>

Um valor de **max significa que este cgroup não tem um limite específico**, mas como os cgroups são hierárquicos, um cgroup mais abaixo na cadeia de subdiretórios pode limitá-lo.

### Manipulando e Criando cgroups

Para colocar um processo em um cgroup, **escreva seu PID no arquivo `cgroup.procs` como root:**
```shell-session
# echo pid > cgroup.procs
```
Assim é como muitas alterações em cgroups funcionam. Por exemplo, se você quiser **limitar o número máximo de PIDs de um cgroup** (para, digamos, 3.000 PIDs), faça da seguinte forma:
```shell-session
# echo 3000 > pids.max
```
**Criar cgroups é mais complicado**. Tecnicamente, é tão fácil quanto criar um subdiretório em algum lugar na árvore de cgroup; ao fazer isso, o kernel cria automaticamente os arquivos de interface. Se um cgroup não tem processos, você pode remover o cgroup com rmdir mesmo com os arquivos de interface presentes. O que pode confundir são as regras que regem os cgroups, incluindo:

* Você só pode colocar **processos em cgroups de nível externo ("folha")**. Por exemplo, se você tem cgroups chamados /my-cgroup e /my-cgroup/my-subgroup, você não pode colocar processos em /my-cgroup, mas /my-cgroup/my-subgroup está ok. (Uma exceção é se os cgroups não têm controladores, mas não vamos aprofundar.)
* Um cgroup **não pode ter um controlador que não esteja em seu cgroup pai**.
* Você deve **especificar explicitamente controladores para cgroups filhos**. Você faz isso através do arquivo `cgroup.subtree_control`; por exemplo, se você quer que um cgroup filho tenha os controladores cpu e pids, escreva +cpu +pids neste arquivo.

Uma exceção a essas regras é o **cgroup raiz** encontrado na base da hierarquia. Você pode **colocar processos neste cgroup**. Uma razão pela qual você pode querer fazer isso é para desvincular um processo do controle do systemd.

Mesmo sem controladores ativados, você pode ver o uso de CPU de um cgroup olhando para o seu arquivo cpu.stat:

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption></figcaption></figure>

Como este é o uso acumulado de CPU durante toda a vida útil do cgroup, você pode ver como um serviço consome tempo de processador mesmo que ele crie muitos subprocessos que eventualmente terminam.

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
