# Espaço de Nomes de Usuário

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs exclusivos**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Informações Básicas

Um espaço de nomes de usuário é um recurso do kernel Linux que **fornece isolamento de mapeamentos de ID de usuário e grupo**, permitindo que cada espaço de nomes de usuário tenha seu **próprio conjunto de IDs de usuário e grupo**. Esse isolamento permite que processos executados em diferentes espaços de nomes de usuário **tenham diferentes privilégios e propriedades**, mesmo que compartilhem os mesmos IDs de usuário e grupo numericamente.

Espaços de nomes de usuário são particularmente úteis na contêinerização, onde cada contêiner deve ter seu próprio conjunto independente de IDs de usuário e grupo, permitindo melhor segurança e isolamento entre contêineres e o sistema hospedeiro.

### Como funciona:

1. Quando um novo espaço de nomes de usuário é criado, ele **começa com um conjunto vazio de mapeamentos de ID de usuário e grupo**. Isso significa que qualquer processo executado no novo espaço de nomes de usuário **inicialmente não terá privilégios fora do espaço de nomes**.
2. Mapeamentos de ID podem ser estabelecidos entre os IDs de usuário e grupo no novo espaço de nomes e aqueles no espaço de nomes pai (ou hospedeiro). Isso **permite que processos no novo espaço de nomes tenham privilégios e propriedade correspondentes aos IDs de usuário e grupo no espaço de nomes pai**. No entanto, os mapeamentos de ID podem ser restritos a intervalos e subconjuntos específicos de IDs, permitindo um controle refinado sobre os privilégios concedidos aos processos no novo espaço de nomes.
3. Dentro de um espaço de nomes de usuário, **processos podem ter privilégios de root completos (UID 0) para operações dentro do espaço de nomes**, enquanto ainda têm privilégios limitados fora do espaço de nomes. Isso permite que **contêineres executem com capacidades semelhantes ao root dentro de seu próprio espaço de nomes sem ter privilégios de root completos no sistema hospedeiro**.
4. Processos podem se mover entre espaços de nomes usando a chamada de sistema `setns()` ou criar novos espaços de nomes usando as chamadas de sistema `unshare()` ou `clone()` com a flag `CLONE_NEWUSER`. Quando um processo se move para um novo espaço de nomes ou cria um, ele começará a usar os mapeamentos de ID de usuário e grupo associados a esse espaço de nomes.

## Laboratório:

### Criar diferentes Espaços de Nomes

#### CLI
```bash
sudo unshare -U [--mount-proc] /bin/bash
```
Ao montar uma nova instância do sistema de arquivos `/proc` usando o parâmetro `--mount-proc`, você garante que o novo namespace de montagem tenha uma **visão precisa e isolada das informações de processo específicas para aquele namespace**.

<details>

<summary>Erro: bash: fork: Não é possível alocar memória</summary>

Quando `unshare` é executado sem a opção `-f`, um erro é encontrado devido à maneira como o Linux lida com novos namespaces de PID (ID de Processo). Os detalhes principais e a solução são descritos abaixo:

1. **Explicação do Problema**:
- O kernel do Linux permite que um processo crie novos namespaces usando a chamada de sistema `unshare`. No entanto, o processo que inicia a criação de um novo namespace de PID (referido como o processo "unshare") não entra no novo namespace; apenas seus processos filhos o fazem.
- Executar `%unshare -p /bin/bash%` inicia `/bin/bash` no mesmo processo que `unshare`. Consequentemente, `/bin/bash` e seus processos filhos estão no namespace de PID original.
- O primeiro processo filho de `/bin/bash` no novo namespace torna-se o PID 1. Quando este processo sai, ele aciona a limpeza do namespace se não houver outros processos, pois o PID 1 tem o papel especial de adotar processos órfãos. O kernel do Linux então desativa a alocação de PID naquele namespace.

2. **Consequência**:
- A saída do PID 1 em um novo namespace leva à limpeza da flag `PIDNS_HASH_ADDING`. Isso resulta na falha da função `alloc_pid` em alocar um novo PID ao criar um novo processo, produzindo o erro "Não é possível alocar memória".

3. **Solução**:
- O problema pode ser resolvido usando a opção `-f` com `unshare`. Esta opção faz com que `unshare` bifurque um novo processo após criar o novo namespace de PID.
- Executar `%unshare -fp /bin/bash%` garante que o próprio comando `unshare` se torne o PID 1 no novo namespace. `/bin/bash` e seus processos filhos são então contidos com segurança dentro deste novo namespace, prevenindo a saída prematura do PID 1 e permitindo a alocação normal de PID.

Ao garantir que `unshare` seja executado com a bandeira `-f`, o novo namespace de PID é corretamente mantido, permitindo que `/bin/bash` e seus sub-processos operem sem encontrar o erro de alocação de memória.

</details>

#### Docker
```bash
docker run -ti --name ubuntu1 -v /usr:/ubuntu1 ubuntu bash
```
Para usar o namespace de usuário, o daemon do Docker precisa ser iniciado com **`--userns-remap=default`** (No Ubuntu 14.04, isso pode ser feito modificando `/etc/default/docker` e depois executando `sudo service docker restart`)

### &#x20;Verifique em qual namespace seu processo está
```bash
ls -l /proc/self/ns/user
lrwxrwxrwx 1 root root 0 Apr  4 20:57 /proc/self/ns/user -> 'user:[4026531837]'
```
É possível verificar o mapeamento de usuário do container docker com:
```bash
cat /proc/self/uid_map
0          0 4294967295  --> Root is root in host
0     231072      65536  --> Root is 231072 userid in host
```
Ou do host com:
```bash
cat /proc/<pid>/uid_map
```
### Encontrar todos os namespaces de Usuário

{% code overflow="wrap" %}
```bash
sudo find /proc -maxdepth 3 -type l -name user -exec readlink {} \; 2>/dev/null | sort -u
# Find the processes with an specific namespace
sudo find /proc -maxdepth 3 -type l -name user -exec ls -l  {} \; 2>/dev/null | grep <ns-number>
```
### Entrar dentro de um namespace de Usuário
```bash
nsenter -U TARGET_PID --pid /bin/bash
```
Também, você só pode **entrar no namespace de outro processo se for root**. E você **não pode** **entrar** em outro namespace **sem um descritor** apontando para ele (como `/proc/self/ns/user`).

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

No caso de namespaces de usuário, **quando um novo namespace de usuário é criado, o processo que entra no namespace recebe um conjunto completo de capacidades dentro desse namespace**. Essas capacidades permitem que o processo execute operações privilegiadas, como **montar** **sistemas de arquivos**, criar dispositivos ou alterar a propriedade de arquivos, mas **apenas dentro do contexto de seu namespace de usuário**.

Por exemplo, quando você tem a capacidade `CAP_SYS_ADMIN` dentro de um namespace de usuário, você pode realizar operações que normalmente requerem essa capacidade, como montar sistemas de arquivos, mas apenas dentro do contexto do seu namespace de usuário. Quaisquer operações que você realize com essa capacidade não afetarão o sistema hospedeiro ou outros namespaces.

{% hint style="warning" %}
Portanto, mesmo que colocar um novo processo dentro de um novo namespace de usuário **lhe devolva todas as capacidades** (CapEff: 000001ffffffffff), você na verdade pode **apenas usar as relacionadas ao namespace** (montar, por exemplo), mas não todas. Então, isso por si só não é suficiente para escapar de um contêiner Docker.
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
# Referências
* [https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory](https://stackoverflow.com/questions/44666700/unshare-pid-bin-bash-fork-cannot-allocate-memory)

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
