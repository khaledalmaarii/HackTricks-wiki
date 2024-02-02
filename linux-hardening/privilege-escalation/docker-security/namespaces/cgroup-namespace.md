# Namespace CGroup

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

Um namespace CGroup é um recurso do kernel Linux que fornece **isolamento de hierarquias de cgroup para processos em execução dentro de um namespace**. Cgroups, abreviação de **control groups**, são um recurso do kernel que permite organizar processos em grupos hierárquicos para gerenciar e impor **limites nos recursos do sistema** como CPU, memória e I/O.

Embora os namespaces CGroup não sejam um tipo de namespace separado como os outros que discutimos anteriormente (PID, mount, network, etc.), eles estão relacionados ao conceito de isolamento de namespace. **Namespaces CGroup virtualizam a visão da hierarquia de cgroup**, de modo que processos em execução dentro de um namespace CGroup têm uma visão diferente da hierarquia em comparação com processos em execução no host ou em outros namespaces.

### Como funciona:

1. Quando um novo namespace CGroup é criado, **ele começa com uma visão da hierarquia de cgroup baseada no cgroup do processo criador**. Isso significa que processos em execução no novo namespace CGroup só verão um subconjunto da hierarquia de cgroup inteira, limitado à subárvore de cgroup na qual o cgroup do processo criador está enraizado.
2. Processos dentro de um namespace CGroup **verão seu próprio cgroup como a raiz da hierarquia**. Isso significa que, do ponto de vista dos processos dentro do namespace, seu próprio cgroup aparece como a raiz, e eles não podem ver ou acessar cgroups fora de sua própria subárvore.
3. Namespaces CGroup não fornecem diretamente isolamento de recursos; **eles apenas fornecem isolamento da visão da hierarquia de cgroup**. **O controle e isolamento de recursos ainda são aplicados pelos próprios subsistemas de cgroup** (por exemplo, cpu, memória, etc.).

Para mais informações sobre CGroups, confira:

{% content-ref url="../cgroups.md" %}
[cgroups.md](../cgroups.md)
{% endcontent-ref %}

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -C [--mount-proc] /bin/bash
```
Montando uma nova instância do sistema de arquivos `/proc` se você usar o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações de processo específicas para aquele namespace**.

<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Se você executar a linha anterior sem `-f`, você receberá esse erro.\
O erro é causado porque o processo PID 1 sai no novo namespace.

Após o início do bash, o bash criará vários novos sub-processos para fazer algumas coisas. Se você executar unshare sem -f, o bash terá o mesmo pid que o processo "unshare" atual. O processo "unshare" atual chama a chamada de sistema unshare, cria um novo namespace de pid, mas o processo "unshare" atual não está no novo namespace de pid. É o comportamento desejado do kernel Linux: o processo A cria um novo namespace, o próprio processo A não será colocado no novo namespace, apenas os sub-processes do processo A serão colocados no novo namespace. Então, quando você executar:
</details>
```
unshare -p /bin/bash
```
O processo unshare executará /bin/bash, e /bin/bash gerará vários sub-processos, o primeiro sub-processo do bash se tornará o PID 1 do novo namespace, e o subprocesso sairá após concluir seu trabalho. Assim, o PID 1 do novo namespace sai.

O processo PID 1 tem uma função especial: ele deve se tornar o processo pai de todos os processos órfãos. Se o processo PID 1 no namespace raiz sair, o kernel entrará em pânico. Se o processo PID 1 em um sub namespace sair, o kernel linux chamará a função disable\_pid\_allocation, que limpará a flag PIDNS\_HASH\_ADDING naquele namespace. Quando o kernel linux cria um novo processo, o kernel chamará a função alloc\_pid para alocar um PID em um namespace, e se a flag PIDNS\_HASH\_ADDING não estiver definida, a função alloc\_pid retornará um erro -ENOMEM. É por isso que você recebeu o erro "Cannot allocate memory".

Você pode resolver esse problema usando a opção '-f':
```
unshare -fp /bin/bash
```
Se você executar o unshare com a opção '-f', o unshare criará um novo processo após criar o novo namespace de pid. E executará o /bin/bash no novo processo. O novo processo será o pid 1 do novo namespace de pid. Então, o bash também criará vários sub-processos para realizar algumas tarefas. Como o próprio bash é o pid 1 do novo namespace de pid, seus sub-processos podem sair sem nenhum problema.

Copiado de [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Verifique em qual namespace seu processo está
```bash
ls -l /proc/self/ns/cgroup
lrwxrwxrwx 1 root root 0 Apr  4 21:19 /proc/self/ns/cgroup -> 'cgroup:[4026531835]'
```
### Encontrar todos os namespaces CGroup

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name cgroup -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name cgroup -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar em um namespace CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Também, você só pode **entrar em outro namespace de processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/cgroup`).

<details>

<summary><strong>Aprenda hacking em AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
