# Namespace de PID

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Informações Básicas

O namespace de PID (Process IDentifier) é um recurso no kernel do Linux que fornece isolamento de processos, permitindo que um grupo de processos tenha seu próprio conjunto de PIDs exclusivos, separados dos PIDs em outros namespaces. Isso é particularmente útil na containerização, onde o isolamento de processos é essencial para segurança e gerenciamento de recursos.

Quando um novo namespace de PID é criado, o primeiro processo nesse namespace é atribuído ao PID 1. Esse processo se torna o processo "init" do novo namespace e é responsável por gerenciar outros processos dentro do namespace. Cada processo subsequente criado dentro do namespace terá um PID único dentro desse namespace, e esses PIDs serão independentes dos PIDs em outros namespaces.

Do ponto de vista de um processo dentro de um namespace de PID, ele só pode ver outros processos no mesmo namespace. Ele não tem conhecimento de processos em outros namespaces e não pode interagir com eles usando ferramentas tradicionais de gerenciamento de processos (por exemplo, `kill`, `wait`, etc.). Isso fornece um nível de isolamento que ajuda a evitar que processos interfiram uns com os outros.

### Como funciona:

1. Quando um novo processo é criado (por exemplo, usando a chamada de sistema `clone()`), o processo pode ser atribuído a um namespace de PID novo ou existente. **Se um novo namespace for criado, o processo se torna o processo "init" desse namespace**.
2. O **kernel** mantém um **mapeamento entre os PIDs no novo namespace e os PIDs correspondentes** no namespace pai (ou seja, o namespace do qual o novo namespace foi criado). Esse mapeamento **permite que o kernel traduza os PIDs quando necessário**, como ao enviar sinais entre processos em diferentes namespaces.
3. **Processos dentro de um namespace de PID só podem ver e interagir com outros processos no mesmo namespace**. Eles não têm conhecimento de processos em outros namespaces, e seus PIDs são únicos dentro de seu namespace.
4. Quando um **namespace de PID é destruído** (por exemplo, quando o processo "init" do namespace sai), **todos os processos dentro desse namespace são terminados**. Isso garante que todos os recursos associados ao namespace sejam devidamente limpos.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Quando `unshare` é executado sem a opção `-f`, um erro é encontrado devido à forma como o Linux lida com os novos namespaces de PID (Process ID). Os detalhes-chave e a solução são descritos abaixo:

1. **Explicação do Problema**:
- O kernel do Linux permite que um processo crie novos namespaces usando a chamada de sistema `unshare`. No entanto, o processo que inicia a criação de um novo namespace de PID (referido como o processo "unshare") não entra no novo namespace; apenas seus processos filhos o fazem.
- Executar `%unshare -p /bin/bash%` inicia `/bin/bash` no mesmo processo que `unshare`. Consequentemente, `/bin/bash` e seus processos filhos estão no namespace PID original.
- O primeiro processo filho do `/bin/bash` no novo namespace se torna o PID 1. Quando este processo sai, ele desencadeia a limpeza do namespace se não houver outros processos, pois o PID 1 tem o papel especial de adotar processos órfãos. O kernel do Linux então desabilitará a alocação de PID nesse namespace.

2. **Consequência**:
- A saída do PID 1 em um novo namespace leva à limpeza da flag `PIDNS_HASH_ADDING`. Isso resulta na função `alloc_pid` falhando em alocar um novo PID ao criar um novo processo, produzindo o erro "Cannot allocate memory".

3. **Solução**:
- O problema pode ser resolvido usando a opção `-f` com `unshare`. Essa opção faz com que `unshare` bifurque um novo processo após criar o novo namespace de PID.
- Executar `%unshare -fp /bin/bash%` garante que o comando `unshare` em si se torne o PID 1 no novo namespace. `/bin/bash` e seus processos filhos são então seguramente contidos dentro desse novo namespace, evitando a saída prematura do PID 1 e permitindo a alocação normal de PID.

Ao garantir que `unshare` seja executado com a flag `-f`, o novo namespace de PID é mantido corretamente, permitindo que `/bin/bash` e seus sub-processos operem sem encontrar o erro de alocação de memória.

</details>

Ao montar uma nova instância do sistema de arquivos `/proc` se você usar o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações de processo específicas daquele namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Verifique em qual namespace estão seus processos
```bash
ls -l /proc/self/ns/pid
lrwxrwxrwx 1 root root 0 Apr  3 18:45 /proc/self/ns/pid -> 'pid:[4026532412]'
```
### Encontrar todos os namespaces de PID

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name pid -exec readlink {} \; 2>/dev/null | sort -u
```
{% endcode %}

Observe que o usuário root do namespace PID inicial (padrão) pode ver todos os processos, mesmo aqueles em novos namespaces PID, é por isso que podemos ver todos os namespaces PID.

### Entrar dentro de um namespace PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Quando você entra em um namespace PID a partir do namespace padrão, ainda será capaz de ver todos os processos. E o processo desse PID ns será capaz de ver o novo bash no PID ns.

Além disso, você só pode **entrar em outro namespace de PID se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/pid`)

## Referências
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
