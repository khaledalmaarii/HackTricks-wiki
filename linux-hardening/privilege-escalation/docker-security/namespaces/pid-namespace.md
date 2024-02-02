# Espaço de Nomes PID

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

O espaço de nomes PID (Identificador de Processo) é um recurso no kernel Linux que proporciona isolamento de processos ao permitir que um grupo de processos tenha seu próprio conjunto de PIDs únicos, separados dos PIDs em outros espaços de nomes. Isso é particularmente útil na contêinerização, onde o isolamento de processos é essencial para segurança e gerenciamento de recursos.

Quando um novo espaço de nomes PID é criado, o primeiro processo nesse espaço de nomes recebe o PID 1. Esse processo torna-se o processo "init" do novo espaço de nomes e é responsável por gerenciar outros processos dentro do espaço de nomes. Cada processo subsequente criado dentro do espaço de nomes terá um PID único dentro desse espaço de nomes, e esses PIDs serão independentes dos PIDs em outros espaços de nomes.

Do ponto de vista de um processo dentro de um espaço de nomes PID, ele só pode ver outros processos no mesmo espaço de nomes. Ele não está ciente de processos em outros espaços de nomes e não pode interagir com eles usando ferramentas tradicionais de gerenciamento de processos (por exemplo, `kill`, `wait`, etc.). Isso proporciona um nível de isolamento que ajuda a prevenir que processos interfiram uns com os outros.

### Como funciona:

1. Quando um novo processo é criado (por exemplo, usando a chamada de sistema `clone()`), o processo pode ser atribuído a um novo ou existente espaço de nomes PID. **Se um novo espaço de nomes é criado, o processo torna-se o processo "init" desse espaço de nomes**.
2. O **kernel** mantém um **mapeamento entre os PIDs no novo espaço de nomes e os PIDs correspondentes** no espaço de nomes pai (ou seja, o espaço de nomes do qual o novo foi criado). Esse mapeamento **permite que o kernel traduza PIDs quando necessário**, como ao enviar sinais entre processos em diferentes espaços de nomes.
3. **Processos dentro de um espaço de nomes PID só podem ver e interagir com outros processos no mesmo espaço de nomes**. Eles não estão cientes de processos em outros espaços de nomes, e seus PIDs são únicos dentro de seu espaço de nomes.
4. Quando um **espaço de nomes PID é destruído** (por exemplo, quando o processo "init" do espaço de nomes sai), **todos os processos dentro desse espaço de nomes são terminados**. Isso garante que todos os recursos associados ao espaço de nomes sejam adequadamente limpos.

## Laboratório:

### Criar diferentes Espaços de Nomes

#### CLI
```bash
sudo unshare -pf --mount-proc /bin/bash
```
<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Se você executar a linha anterior sem `-f`, você receberá esse erro.\
O erro é causado porque o processo PID 1 sai no novo namespace.

Após o início do bash, o bash irá criar vários novos sub-processos para fazer algumas coisas. Se você executar unshare sem -f, o bash terá o mesmo pid que o processo "unshare" atual. O processo "unshare" atual chama a chamada de sistema unshare, cria um novo pid namespace, mas o processo "unshare" atual não está no novo pid namespace. É o comportamento desejado do kernel linux: o processo A cria um novo namespace, o próprio processo A não será colocado no novo namespace, apenas os sub-processos do processo A serão colocados no novo namespace. Então, quando você executa:
</details>
```
unshare -p /bin/bash
```
```markdown
O processo unshare executará /bin/bash, e /bin/bash criará vários sub-processos. O primeiro sub-processo do bash se tornará o PID 1 do novo namespace e o subprocesso sairá após concluir seu trabalho. Assim, o PID 1 do novo namespace sai.

O processo PID 1 tem uma função especial: deve se tornar o processo pai de todos os processos órfãos. Se o processo PID 1 no namespace raiz sair, o kernel entrará em pânico. Se o processo PID 1 em um sub-namespace sair, o kernel do Linux chamará a função disable_pid_allocation, que limpará a flag PIDNS_HASH_ADDING naquele namespace. Quando o kernel do Linux cria um novo processo, o kernel chamará a função alloc_pid para alocar um PID em um namespace, e se a flag PIDNS_HASH_ADDING não estiver definida, a função alloc_pid retornará um erro -ENOMEM. É por isso que você recebeu o erro "Cannot allocate memory".

Você pode resolver esse problema usando a opção '-f':
```
```
unshare -fp /bin/bash
```
Se você executar o unshare com a opção '-f', o unshare irá bifurcar um novo processo após criar o novo namespace pid. E executar /bin/bash no novo processo. O novo processo será o pid 1 do novo namespace pid. Então, o bash também irá bifurcar vários sub-processos para realizar algumas tarefas. Como o próprio bash é o pid 1 do novo namespace pid, seus sub-processos podem sair sem nenhum problema.

Copiado de [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

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

Observe que o usuário root do namespace PID inicial (padrão) pode ver todos os processos, até mesmo os que estão em novos namespaces de PID, é por isso que podemos ver todos os namespaces de PID.

### Entrar dentro de um namespace de PID
```bash
nsenter -t TARGET_PID --pid /bin/bash
```
Ao entrar em um namespace PID a partir do namespace padrão, você ainda poderá ver todos os processos. E o processo desse namespace PID poderá ver o novo bash no namespace PID.

Além disso, você só pode **entrar no namespace PID de outro processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/pid`)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
