# Namespace de Usuário

<details>

<summary><strong>Aprenda hacking na AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Informações Básicas

Um namespace de usuário é um recurso do kernel do Linux que **fornece isolamento de mapeamentos de ID de usuário e grupo**, permitindo que cada namespace de usuário tenha seu **próprio conjunto de IDs de usuário e grupo**. Esse isolamento permite que processos em execução em diferentes namespaces de usuário tenham **privilégios e propriedades diferentes**, mesmo que compartilhem os mesmos IDs de usuário e grupo numericamente.

Os namespaces de usuário são particularmente úteis na containerização, onde cada contêiner deve ter seu próprio conjunto independente de IDs de usuário e grupo, permitindo uma melhor segurança e isolamento entre os contêineres e o sistema hospedeiro.

### Como funciona:

1. Quando um novo namespace de usuário é criado, ele **começa com um conjunto vazio de mapeamentos de IDs de usuário e grupo**. Isso significa que qualquer processo em execução no novo namespace de usuário **inicialmente não terá privilégios fora do namespace**.
2. Os mapeamentos de IDs podem ser estabelecidos entre os IDs de usuário e grupo no novo namespace e aqueles no namespace pai (ou hospedeiro). Isso **permite que processos no novo namespace tenham privilégios e propriedades correspondentes aos IDs de usuário e grupo no namespace pai**. No entanto, os mapeamentos de IDs podem ser restritos a intervalos específicos e subconjuntos de IDs, permitindo um controle detalhado sobre os privilégios concedidos aos processos no novo namespace.
3. Dentro de um namespace de usuário, **os processos podem ter privilégios de root completos (UID 0) para operações dentro do namespace**, enquanto ainda têm privilégios limitados fora do namespace. Isso permite que **contêineres executem com capacidades semelhantes às de root dentro de seu próprio namespace sem ter privilégios de root completos no sistema hospedeiro**.
4. Os processos podem se mover entre namespaces usando a chamada de sistema `setns()` ou criar novos namespaces usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWUSER`. Quando um processo se move para um novo namespace ou cria um, ele começará a usar os mapeamentos de IDs de usuário e grupo associados a esse namespace.

## Laboratório:

### Criar diferentes Namespaces

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Ao montar uma nova instância do sistema de arquivos `/proc` usando o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações de processo específicas daquele namespace**.

<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Quando o `unshare` é executado sem a opção `-f`, um erro é encontrado devido à forma como o Linux lida com os novos namespaces de PID (Identificador de Processo). Os detalhes-chave e a solução são descritos abaixo:

1. **Explicação do Problema**:
- O kernel do Linux permite que um processo crie novos namespaces usando a chamada de sistema `unshare`. No entanto, o processo que inicia a criação de um novo namespace de PID (referido como o processo "unshare") não entra no novo namespace; apenas seus processos filhos o fazem.
- Executar `%unshare -p /bin/bash%` inicia `/bin/bash` no mesmo processo que `unshare`. Consequentemente, `/bin/bash` e seus processos filhos estão no namespace de PID original.
- O primeiro processo filho do `/bin/bash` no novo namespace se torna o PID 1. Quando esse processo sai, ele desencadeia a limpeza do namespace se não houver outros processos, pois o PID 1 tem o papel especial de adotar processos órfãos. O kernel do Linux então desabilitará a alocação de PID nesse namespace.

2. **Consequência**:
- A saída do PID 1 em um novo namespace leva à limpeza da flag `PIDNS_HASH_ADDING`. Isso resulta na função `alloc_pid` falhando ao alocar um novo PID ao criar um novo processo, produzindo o erro "Cannot allocate memory".

3. **Solução**:
- O problema pode ser resolvido usando a opção `-f` com o `unshare`. Essa opção faz com que o `unshare` bifurque um novo processo após criar o novo namespace de PID.
- Executar `%unshare -fp /bin/bash%` garante que o comando `unshare` se torne o PID 1 no novo namespace. `/bin/bash` e seus processos filhos são então seguramente contidos dentro desse novo namespace, evitando a saída prematura do PID 1 e permitindo a alocação normal de PID.

Ao garantir que o `unshare` seja executado com a flag `-f`, o novo namespace de PID é mantido corretamente, permitindo que `/bin/bash` e seus sub-processos operem sem encontrar o erro de alocação de memória.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Para usar o namespace do usuário, o daemon do Docker precisa ser iniciado com **`--userns-remap=default`** (No Ubuntu 14.04, isso pode ser feito modificando `/etc/default/docker` e depois executando `sudo service docker restart`)

### &#x20;Verifique em qual namespace está o seu processo
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
É possível verificar o mapeamento de usuários do contêiner Docker com:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Ou a partir do host com:
```bash
cat /proc/<pid>/uid_map
```
### Encontrar todos os namespaces de usuário

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de um namespace de usuário
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Também, você só pode **entrar em outro namespace de processo se você for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/user`).

### Criar novo User namespace (com mapeamentos)

{% code overflow="wrap" %}
```bash
unshare -U [--map-user=<uid>|<name>] [--map-group=<gid>|<name>] [--map-root-user] [--map-current-user]
```
{% endcode %}
```bash
# Container
sudo unshare -U /bin/bash
nobody@ip-172-31-28-169:/home/ubuntu$ #Check how the user is nobody

# From the host
ps -ef | grep bash # The user inside the host is still root, not nobody
root       27756   27755  0 21:11 pts/10   00:00:00 /bin/bash
```
### Recuperando Capacidades

No caso dos namespaces de usuário, **quando um novo namespace de usuário é criado, o processo que entra no namespace recebe um conjunto completo de capacidades dentro desse namespace**. Essas capacidades permitem que o processo execute operações privilegiadas, como **montar sistemas de arquivos**, criar dispositivos ou alterar a propriedade de arquivos, mas **apenas no contexto de seu namespace de usuário**.

Por exemplo, quando você tem a capacidade `CAP_SYS_ADMIN` dentro de um namespace de usuário, você pode realizar operações que normalmente exigem essa capacidade, como montar sistemas de arquivos, mas apenas no contexto de seu namespace de usuário. Quaisquer operações que você execute com essa capacidade não afetarão o sistema host ou outros namespaces.

{% hint style="warning" %}
Portanto, mesmo que obter um novo processo dentro de um novo namespace de usuário **lhe devolva todas as capacidades** (CapEff: 000001ffffffffff), na verdade você só pode **usar aquelas relacionadas ao namespace** (como montagem), mas não todas. Portanto, isso por si só não é suficiente para escapar de um contêiner Docker.
{% endhint %}
```bash
# There are the syscalls that are filtered after changing User namespace with:
unshare -UmCpf  bash

Probando: 0x067 . . . Error
Probando: 0x070 . . . Error
Probando: 0x074 . . . Error
Probando: 0x09b . . . Error
Probando: 0x0a3 . . . Error
Probando: 0x0a4 . . . Error
Probando: 0x0a7 . . . Error
Probando: 0x0a8 . . . Error
Probando: 0x0aa . . . Error
Probando: 0x0ab . . . Error
Probando: 0x0af . . . Error
Probando: 0x0b0 . . . Error
Probando: 0x0f6 . . . Error
Probando: 0x12c . . . Error
Probando: 0x130 . . . Error
Probando: 0x139 . . . Error
Probando: 0x140 . . . Error
Probando: 0x141 . . . Error
Probando: 0x143 . . . Error
```
## Referências
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
