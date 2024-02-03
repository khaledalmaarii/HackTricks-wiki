# PID Namespace

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) no github.

</details>

## Informações Básicas

O namespace PID (Process IDentifier) é um recurso no kernel Linux que proporciona isolamento de processos ao permitir que um grupo de processos tenha seu próprio conjunto de PIDs únicos, separados dos PIDs em outros namespaces. Isso é particularmente útil na contenerização, onde o isolamento de processos é essencial para segurança e gerenciamento de recursos.

Quando um novo namespace PID é criado, o primeiro processo nesse namespace recebe o PID 1. Esse processo se torna o processo "init" do novo namespace e é responsável por gerenciar outros processos dentro do namespace. Cada processo subsequente criado dentro do namespace terá um PID único dentro desse namespace, e esses PIDs serão independentes dos PIDs em outros namespaces.

Do ponto de vista de um processo dentro de um namespace PID, ele só pode ver outros processos no mesmo namespace. Ele não está ciente de processos em outros namespaces e não pode interagir com eles usando ferramentas tradicionais de gerenciamento de processos (por exemplo, `kill`, `wait`, etc.). Isso proporciona um nível de isolamento que ajuda a prevenir que processos interfiram uns com os outros.

### Como funciona:

1. Quando um novo processo é criado (por exemplo, usando a chamada de sistema `clone()`), o processo pode ser atribuído a um novo ou existente namespace PID. **Se um novo namespace é criado, o processo se torna o processo "init" desse namespace**.
2. O **kernel** mantém um **mapeamento entre os PIDs no novo namespace e os PIDs correspondentes** no namespace pai (ou seja, o namespace do qual o novo namespace foi criado). Esse mapeamento **permite que o kernel traduza PIDs quando necessário**, como ao enviar sinais entre processos em diferentes namespaces.
3. **Processos dentro de um namespace PID só podem ver e interagir com outros processos no mesmo namespace**. Eles não estão cientes de processos em outros namespaces, e seus PIDs são únicos dentro de seu namespace.
4. Quando um **namespace PID é destruído** (por exemplo, quando o processo "init" do namespace é encerrado), **todos os processos dentro desse namespace são terminados**. Isso garante que todos os recursos associados ao namespace sejam devidamente limpos.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Quando `unshare` é executado sem a opção `-f`, um erro é encontrado devido à forma como o Linux lida com novos namespaces de PID (ID de Processo). Os detalhes principais e a solução são descritos abaixo:

1. **Explicação do Problema**:
- O kernel do Linux permite que um processo crie novos namespaces usando a chamada de sistema `unshare`. No entanto, o processo que inicia a criação de um novo namespace de PID (referido como o processo "unshare") não entra no novo namespace; apenas seus processos filhos entram.
- Executar `%unshare -p /bin/bash%` inicia `/bin/bash` no mesmo processo que `unshare`. Consequentemente, `/bin/bash` e seus processos filhos estão no namespace de PID original.
- O primeiro processo filho de `/bin/bash` no novo namespace torna-se o PID 1. Quando este processo sai, ele aciona a limpeza do namespace se não houver outros processos, pois o PID 1 tem o papel especial de adotar processos órfãos. O kernel do Linux então desativa a alocação de PID naquele namespace.

2. **Consequência**:
- A saída do PID 1 em um novo namespace leva à limpeza da flag `PIDNS_HASH_ADDING`. Isso resulta na falha da função `alloc_pid` em alocar um novo PID ao criar um novo processo, produzindo o erro "Não é possível alocar memória".

3. **Solução**:
- O problema pode ser resolvido usando a opção `-f` com `unshare`. Esta opção faz com que `unshare` bifurque um novo processo após criar o novo namespace de PID.
- Executar `%unshare -fp /bin/bash%` garante que o próprio comando `unshare` se torne o PID 1 no novo namespace. `/bin/bash` e seus processos filhos são então contidos com segurança dentro deste novo namespace, prevenindo a saída prematura do PID 1 e permitindo a alocação normal de PID.

Ao garantir que `unshare` seja executado com a flag `-f`, o novo namespace de PID é mantido corretamente, permitindo que `/bin/bash` e seus sub-processos operem sem encontrar o erro de alocação de memória.

</details>

Ao montar uma nova instância do sistema de arquivos `/proc` se você usar o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações de processo específicas para aquele namespace**.

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
### Verifique em qual namespace seu processo está
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

Note que o usuário root do namespace PID inicial (padrão) pode ver todos os processos, até mesmo os que estão em novos namespaces de PID, por isso podemos ver todos os namespaces de PID.

### Entrar dentro de um namespace de PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Ao entrar em um namespace PID a partir do namespace padrão, você ainda poderá ver todos os processos. E o processo desse namespace PID poderá ver o novo bash no namespace PID.

Além disso, você só pode **entrar no namespace PID de outro processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/pid`)

# Referências
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
