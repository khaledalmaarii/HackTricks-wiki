# Namespace de Montagem

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira [**produtos oficiais PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Informações Básicas

Um namespace de montagem é um recurso do kernel do Linux que fornece isolamento dos pontos de montagem do sistema de arquivos vistos por um grupo de processos. Cada namespace de montagem possui seu próprio conjunto de pontos de montagem do sistema de arquivos, e **as alterações nos pontos de montagem em um namespace não afetam outros namespaces**. Isso significa que processos em diferentes namespaces de montagem podem ter visões diferentes da hierarquia do sistema de arquivos.

Os namespaces de montagem são particularmente úteis na containerização, onde cada contêiner deve ter seu próprio sistema de arquivos e configuração, isolados de outros contêineres e do sistema hospedeiro.

### Como funciona:

1. Quando um novo namespace de montagem é criado, ele é inicializado com uma **cópia dos pontos de montagem do namespace pai**. Isso significa que, na criação, o novo namespace compartilha a mesma visão do sistema de arquivos que seu pai. No entanto, quaisquer alterações subsequentes nos pontos de montagem dentro do namespace não afetarão o pai ou outros namespaces.
2. Quando um processo modifica um ponto de montagem dentro de seu namespace, como montar ou desmontar um sistema de arquivos, a **alteração é local a esse namespace** e não afeta outros namespaces. Isso permite que cada namespace tenha sua própria hierarquia de sistema de arquivos independente.
3. Os processos podem se mover entre namespaces usando a chamada de sistema `setns()`, ou criar novos namespaces usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWNS`. Quando um processo se move para um novo namespace ou cria um, ele começará a usar os pontos de montagem associados a esse namespace.
4. **Descritores de arquivo e inodes são compartilhados entre namespaces**, o que significa que se um processo em um namespace tiver um descritor de arquivo aberto apontando para um arquivo, ele pode **passar esse descritor de arquivo** para um processo em outro namespace, e **ambos os processos acessarão o mesmo arquivo**. No entanto, o caminho do arquivo pode não ser o mesmo em ambos os namespaces devido a diferenças nos pontos de montagem.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -m [--mount-proc] /bin/bash
```
Ao montar uma nova instância do sistema de arquivos `/proc` usando o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações de processo específicas daquele namespace**.

<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Quando o `unshare` é executado sem a opção `-f`, um erro é encontrado devido à forma como o Linux lida com os novos namespaces de PID (Process ID). Os detalhes-chave e a solução são descritos abaixo:

1. **Explicação do Problema**:
- O kernel do Linux permite que um processo crie novos namespaces usando a chamada de sistema `unshare`. No entanto, o processo que inicia a criação de um novo namespace de PID (referido como o processo "unshare") não entra no novo namespace; apenas seus processos filhos o fazem.
- Executar `%unshare -p /bin/bash%` inicia `/bin/bash` no mesmo processo que `unshare`. Consequentemente, `/bin/bash` e seus processos filhos estão no namespace de PID original.
- O primeiro processo filho do `/bin/bash` no novo namespace se torna o PID 1. Quando esse processo sai, ele desencadeia a limpeza do namespace se não houver outros processos, pois o PID 1 tem o papel especial de adotar processos órfãos. O kernel do Linux então desabilitará a alocação de PID nesse namespace.

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
ls -l /proc/self/ns/mnt
lrwxrwxrwx 1 root root 0 Apr  4 20:30 /proc/self/ns/mnt -> 'mnt:[4026531841]'
```
### Encontrar todos os namespaces de montagem

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name mnt -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name mnt -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de um namespace de montagem
```bash
nsenter -m TARGET_PID --pid /bin/bash
```
Também, você só pode **entrar em outro namespace de processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/mnt`).

Como novos mounts são acessíveis apenas dentro do namespace, é possível que um namespace contenha informações sensíveis que só podem ser acessadas a partir dele.

### Montar algo
```bash
# Generate new mount ns
unshare -m /bin/bash
mkdir /tmp/mount_ns_example
mount -t tmpfs tmpfs /tmp/mount_ns_example
mount | grep tmpfs # "tmpfs on /tmp/mount_ns_example"
echo test > /tmp/mount_ns_example/test
ls /tmp/mount_ns_example/test # Exists

# From the host
mount | grep tmpfs # Cannot see "tmpfs on /tmp/mount_ns_example"
ls /tmp/mount_ns_example/test # Doesn't exist
```
## Referências
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)


<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
