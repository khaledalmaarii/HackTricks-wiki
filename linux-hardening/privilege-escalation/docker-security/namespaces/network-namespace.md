# Espaço de Nomes de Rede

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Participe do grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou do grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

## Informações Básicas

Um espaço de nomes de rede é um recurso do kernel Linux que fornece isolamento da pilha de rede, permitindo que **cada espaço de nomes de rede tenha sua própria configuração de rede independente**, interfaces, endereços IP, tabelas de roteamento e regras de firewall. Esse isolamento é útil em vários cenários, como na contêinerização, onde cada contêiner deve ter sua própria configuração de rede, independente de outros contêineres e do sistema hospedeiro.

### Como funciona:

1. Quando um novo espaço de nomes de rede é criado, ele começa com uma **pilha de rede completamente isolada**, sem **nenhuma interface de rede** exceto a interface de loopback (lo). Isso significa que processos executados no novo espaço de nomes de rede não podem se comunicar com processos em outros espaços de nomes ou com o sistema hospedeiro por padrão.
2. **Interfaces de rede virtuais**, como pares veth, podem ser criadas e movidas entre espaços de nomes de rede. Isso permite estabelecer conectividade de rede entre espaços de nomes ou entre um espaço de nomes e o sistema hospedeiro. Por exemplo, uma extremidade de um par veth pode ser colocada no espaço de nomes de rede de um contêiner, e a outra extremidade pode ser conectada a uma **ponte** ou outra interface de rede no espaço de nomes do hospedeiro, fornecendo conectividade de rede ao contêiner.
3. Interfaces de rede dentro de um espaço de nomes podem ter seus **próprios endereços IP, tabelas de roteamento e regras de firewall**, independentes de outros espaços de nomes. Isso permite que processos em diferentes espaços de nomes de rede tenham configurações de rede diferentes e operem como se estivessem em sistemas em rede separados.
4. Processos podem se mover entre espaços de nomes usando a chamada de sistema `setns()`, ou criar novos espaços de nomes usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWNET`. Quando um processo se move para um novo espaço de nomes ou cria um, ele começará a usar a configuração de rede e interfaces associadas àquele espaço de nomes.

## Laboratório:

### Criar diferentes Espaços de Nomes

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Montando uma nova instância do sistema de arquivos `/proc` com o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações de processo específicas para aquele namespace**.

<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Se você executar a linha anterior sem `-f`, receberá esse erro.\
O erro é causado pelo processo PID 1 que sai no novo namespace.

Após o início do bash, o bash criará vários novos sub-processos para fazer algumas coisas. Se você executar unshare sem -f, o bash terá o mesmo pid que o processo "unshare" atual. O processo "unshare" atual chama a chamada de sistema unshare, cria um novo namespace de pid, mas o processo "unshare" atual não está no novo namespace de pid. É o comportamento desejado do kernel Linux: o processo A cria um novo namespace, o próprio processo A não será colocado no novo namespace, apenas os sub-processes do processo A serão colocados no novo namespace. Então, quando você executar:
```
unshare -p /bin/bash
```
```markdown
O processo unshare executará /bin/bash, e /bin/bash gerará vários subprocessos, o primeiro subprocesso do bash se tornará o PID 1 do novo namespace, e o subprocesso sairá após concluir seu trabalho. Assim, o PID 1 do novo namespace sai.

O processo PID 1 tem uma função especial: deve se tornar o processo pai de todos os processos órfãos. Se o processo PID 1 no namespace raiz sair, o kernel entrará em pânico. Se o processo PID 1 em um subnamespace sair, o kernel linux chamará a função disable\_pid\_allocation, que limpará a flag PIDNS\_HASH\_ADDING naquele namespace. Quando o kernel linux cria um novo processo, o kernel chamará a função alloc\_pid para alocar um PID em um namespace, e se a flag PIDNS\_HASH\_ADDING não estiver definida, a função alloc\_pid retornará um erro -ENOMEM. É por isso que você recebeu o erro "Cannot allocate memory".

Você pode resolver esse problema usando a opção '-f':
```
```
unshare -fp /bin/bash
```
```markdown
Se você executar unshare com a opção '-f', o unshare irá bifurcar um novo processo após criar o novo namespace de pid. E executar /bin/bash no novo processo. O novo processo será o pid 1 do novo namespace de pid. Então, o bash também irá bifurcar vários sub-processos para realizar algumas tarefas. Como o próprio bash é o pid 1 do novo namespace de pid, seus sub-processos podem sair sem nenhum problema.

Copiado de [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
# Run ifconfig or ip -a
```
### Verifique em qual namespace seu processo está
```bash
ls -l /proc/self/ns/net
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/net -> 'net:[4026531840]'
```
### Encontrar todos os namespaces de rede

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name net -exec readlink {} \; 2>/dev/null | sort -u | grep "net:"
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name net -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de um namespace de Rede
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Também, você só pode **entrar em outro namespace de processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/net`).

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
