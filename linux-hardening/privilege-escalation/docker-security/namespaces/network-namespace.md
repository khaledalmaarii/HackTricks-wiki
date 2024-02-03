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
3. Interfaces de rede dentro de um espaço de nomes podem ter seus **próprios endereços IP, tabelas de roteamento e regras de firewall**, independentes de outros espaços de nomes. Isso permite que processos em diferentes espaços de nomes de rede tenham configurações de rede diferentes e operem como se estivessem em sistemas de rede separados.
4. Processos podem se mover entre espaços de nomes usando a chamada de sistema `setns()`, ou criar novos espaços de nomes usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWNET`. Quando um processo se move para um novo espaço de nomes ou cria um, ele começará a usar a configuração de rede e interfaces associadas a esse espaço de nomes.

## Laboratório:

### Criar diferentes Espaços de Nomes

#### CLI
```bash
sudo unshare -n [--mount-proc] /bin/bash
# Run ifconfig or ip -a
```
Ao montar uma nova instância do sistema de arquivos `/proc` usando o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações de processo específicas para aquele namespace**.

<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Quando `unshare` é executado sem a opção `-f`, um erro é encontrado devido à forma como o Linux lida com novos namespaces de PID (ID de Processo). Os detalhes principais e a solução são descritos abaixo:

1. **Explicação do Problema**:
- O kernel do Linux permite que um processo crie novos namespaces usando a chamada de sistema `unshare`. No entanto, o processo que inicia a criação de um novo namespace de PID (referido como o processo "unshare") não entra no novo namespace; apenas seus processos filhos o fazem.
- Executar `%unshare -p /bin/bash%` inicia `/bin/bash` no mesmo processo que `unshare`. Consequentemente, `/bin/bash` e seus processos filhos estão no namespace de PID original.
- O primeiro processo filho de `/bin/bash` no novo namespace torna-se o PID 1. Quando este processo sai, ele aciona a limpeza do namespace se não houver outros processos, pois o PID 1 tem o papel especial de adotar processos órfãos. O kernel do Linux desativará então a alocação de PID naquele namespace.

2. **Consequência**:
- A saída do PID 1 em um novo namespace leva à limpeza da flag `PIDNS_HASH_ADDING`. Isso resulta na falha da função `alloc_pid` em alocar um novo PID ao criar um novo processo, produzindo o erro "Não é possível alocar memória".

3. **Solução**:
- O problema pode ser resolvido usando a opção `-f` com `unshare`. Esta opção faz com que `unshare` bifurque um novo processo após criar o novo namespace de PID.
- Executar `%unshare -fp /bin/bash%` garante que o próprio comando `unshare` se torne o PID 1 no novo namespace. `/bin/bash` e seus processos filhos são então contidos com segurança dentro deste novo namespace, prevenindo a saída prematura do PID 1 e permitindo a alocação normal de PID.

Ao garantir que `unshare` seja executado com a flag `-f`, o novo namespace de PID é corretamente mantido, permitindo que `/bin/bash` e seus sub-processos operem sem encontrar o erro de alocação de memória.

</details>

#### Docker
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
### Entrar dentro de um Namespace de Rede
```bash
nsenter -n TARGET_PID --pid /bin/bash
```
Também, você só pode **entrar em outro namespace de processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/net`).

# Referências
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
