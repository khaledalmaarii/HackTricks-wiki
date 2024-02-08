# Namespace de CGroup

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Informações Básicas

Um namespace de cgroup é um recurso do kernel Linux que fornece **isolamento de hierarquias de cgroup para processos em execução dentro de um namespace**. Cgroups, abreviação de **control groups**, são um recurso do kernel que permite organizar processos em grupos hierárquicos para gerenciar e impor **limites em recursos do sistema** como CPU, memória e E/S.

Embora os namespaces de cgroup não sejam um tipo de namespace separado como os que discutimos anteriormente (PID, mount, network, etc.), eles estão relacionados ao conceito de isolamento de namespace. **Os namespaces de cgroup virtualizam a visualização da hierarquia de cgroup**, de modo que os processos em execução dentro de um namespace de cgroup têm uma visualização diferente da hierarquia em comparação com processos em execução no host ou em outros namespaces.

### Como funciona:

1. Quando um novo namespace de cgroup é criado, **ele começa com uma visualização da hierarquia de cgroup com base no cgroup do processo criador**. Isso significa que os processos em execução no novo namespace de cgroup verão apenas um subconjunto da hierarquia de cgroup inteira, limitada à subárvore de cgroup enraizada no cgroup do processo criador.
2. Processos dentro de um namespace de cgroup **veem seu próprio cgroup como a raiz da hierarquia**. Isso significa que, do ponto de vista dos processos dentro do namespace, seu próprio cgroup aparece como a raiz, e eles não podem ver ou acessar cgroups fora de sua própria subárvore.
3. Os namespaces de cgroup não fornecem isolamento direto de recursos; **eles fornecem apenas isolamento da visualização da hierarquia de cgroup**. **O controle e isolamento de recursos ainda são aplicados pelos subsistemas de cgroup** (por exemplo, cpu, memória, etc.) em si.

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
Ao montar uma nova instância do sistema de arquivos `/proc` usando o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações de processo específicas daquele namespace**.

<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Quando o `unshare` é executado sem a opção `-f`, um erro é encontrado devido à forma como o Linux lida com os novos namespaces de PID (Process ID). Os detalhes-chave e a solução são descritos abaixo:

1. **Explicação do Problema**:
- O kernel do Linux permite que um processo crie novos namespaces usando a chamada de sistema `unshare`. No entanto, o processo que inicia a criação de um novo namespace de PID (chamado de processo "unshare") não entra no novo namespace; apenas seus processos filhos o fazem.
- Executar `%unshare -p /bin/bash%` inicia `/bin/bash` no mesmo processo que `unshare`. Consequentemente, `/bin/bash` e seus processos filhos estão no namespace de PID original.
- O primeiro processo filho do `/bin/bash` no novo namespace se torna o PID 1. Quando esse processo sai, ele aciona a limpeza do namespace se não houver outros processos, pois o PID 1 tem o papel especial de adotar processos órfãos. O kernel do Linux então desabilitará a alocação de PID nesse namespace.

2. **Consequência**:
- A saída do PID 1 em um novo namespace leva à limpeza da flag `PIDNS_HASH_ADDING`. Isso resulta na função `alloc_pid` falhando ao alocar um novo PID ao criar um novo processo, produzindo o erro "Cannot allocate memory".

3. **Solução**:
- O problema pode ser resolvido usando a opção `-f` com o `unshare`. Essa opção faz com que o `unshare` bifurque um novo processo após criar o novo namespace de PID.
- Executar `%unshare -fp /bin/bash%` garante que o comando `unshare` em si se torne o PID 1 no novo namespace. `/bin/bash` e seus processos filhos são então seguramente contidos dentro desse novo namespace, evitando a saída prematura do PID 1 e permitindo a alocação normal de PID.

Ao garantir que o `unshare` seja executado com a flag `-f`, o novo namespace de PID é mantido corretamente, permitindo que `/bin/bash` e seus sub-processos operem sem encontrar o erro de alocação de memória.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Verifique em qual namespace está o seu processo
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
### Entrar dentro de um namespace CGroup
```bash
nsenter -C TARGET_PID --pid /bin/bash
```
Também, você só pode **entrar em outro namespace de processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/cgroup`).

## Referências
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
