# CGroups

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras maneiras de apoiar o HackTricks:

* Se você quiser ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

## Informações Básicas

**Linux Control Groups**, ou **cgroups**, são um recurso do kernel Linux que permite a alocação, limitação e priorização de recursos do sistema como CPU, memória e E/S de disco entre grupos de processos. Eles oferecem um mecanismo para **gerenciar e isolar o uso de recursos** de coleções de processos, benéfico para fins como limitação de recursos, isolamento de carga de trabalho e priorização de recursos entre diferentes grupos de processos.

Existem **duas versões de cgroups**: versão 1 e versão 2. Ambas podem ser usadas simultaneamente em um sistema. A distinção principal é que **a versão 2 dos cgroups** introduz uma **estrutura hierárquica em forma de árvore**, permitindo uma distribuição de recursos mais sutil e detalhada entre grupos de processos. Além disso, a versão 2 traz várias melhorias, incluindo:

Além da nova organização hierárquica, a versão 2 dos cgroups também introduziu **outras mudanças e melhorias**, como suporte para **novos controladores de recursos**, melhor suporte para aplicativos legados e melhor desempenho.

No geral, os cgroups **versão 2 oferecem mais recursos e melhor desempenho** do que a versão 1, mas esta última ainda pode ser usada em determinados cenários onde a compatibilidade com sistemas mais antigos é uma preocupação.

Você pode listar os cgroups v1 e v2 para qualquer processo olhando para o arquivo cgroup em /proc/\<pid>. Você pode começar olhando para os cgroups do seu shell com este comando:
```shell-session
$ cat /proc/self/cgroup
12:rdma:/
11:net_cls,net_prio:/
10:perf_event:/
9:cpuset:/
8:cpu,cpuacct:/user.slice
7:blkio:/user.slice
6:memory:/user.slice 5:pids:/user.slice/user-1000.slice/session-2.scope 4:devices:/user.slice
3:freezer:/
2:hugetlb:/testcgroup
1:name=systemd:/user.slice/user-1000.slice/session-2.scope
0::/user.slice/user-1000.slice/session-2.scope
```
A estrutura de saída é a seguinte:

- **Números 2-12**: cgroups v1, com cada linha representando um cgroup diferente. Os controladores para estes são especificados ao lado do número.
- **Número 1**: Também cgroups v1, mas exclusivamente para fins de gerenciamento (definido, por exemplo, pelo systemd), e não possui um controlador.
- **Número 0**: Representa cgroups v2. Nenhum controlador é listado, e esta linha é exclusiva em sistemas que executam apenas cgroups v2.
- Os **nomes são hierárquicos**, assemelhando-se a caminhos de arquivos, indicando a estrutura e relação entre diferentes cgroups.
- Nomes como /user.slice ou /system.slice especificam a categorização de cgroups, com user.slice tipicamente para sessões de login gerenciadas pelo systemd e system.slice para serviços do sistema.

### Visualizando cgroups

O sistema de arquivos é tipicamente utilizado para acessar **cgroups**, divergindo da interface de chamada de sistema Unix tradicionalmente usada para interações com o kernel. Para investigar a configuração de cgroups de um shell, deve-se examinar o arquivo **/proc/self/cgroup**, que revela o cgroup do shell. Em seguida, navegando até o diretório **/sys/fs/cgroup** (ou **`/sys/fs/cgroup/unified`**) e localizando um diretório que compartilha o nome do cgroup, pode-se observar várias configurações e informações de uso de recursos pertinentes ao cgroup.

![Sistema de Arquivos Cgroup](../../../.gitbook/assets/image%20(10)%20(2)%20(2).png)

Os arquivos de interface chave para cgroups são prefixados com **cgroup**. O arquivo **cgroup.procs**, que pode ser visualizado com comandos padrão como cat, lista os processos dentro do cgroup. Outro arquivo, **cgroup.threads**, inclui informações sobre threads.

![Cgroup Procs](../../../.gitbook/assets/image%20(1)%20(1)%20(5).png)

Cgroups que gerenciam shells tipicamente englobam dois controladores que regulam o uso de memória e a contagem de processos. Para interagir com um controlador, deve-se consultar arquivos com o prefixo do controlador. Por exemplo, **pids.current** seria referenciado para verificar a contagem de threads no cgroup.

![Memória do Cgroup](../../../.gitbook/assets/image%20(3)%20(5).png)

A indicação de **max** em um valor sugere a ausência de um limite específico para o cgroup. No entanto, devido à natureza hierárquica dos cgroups, limites podem ser impostos por um cgroup em um nível inferior na hierarquia de diretórios.


### Manipulando e Criando cgroups

Processos são atribuídos a cgroups escrevendo seu ID de Processo (PID) no arquivo `cgroup.procs`. Isso requer privilégios de root. Por exemplo, para adicionar um processo:
```bash
echo [pid] > cgroup.procs
```
Da mesma forma, **modificar atributos do cgroup, como definir um limite de PID**, é feito escrevendo o valor desejado no arquivo relevante. Para definir um máximo de 3.000 PIDs para um cgroup:
```bash
echo 3000 > pids.max
```
**Criar novos cgroups** envolve criar um novo subdiretório dentro da hierarquia do cgroup, o que faz com que o kernel gere automaticamente os arquivos de interface necessários. Embora cgroups sem processos ativos possam ser removidos com `rmdir`, esteja ciente de certas restrições:

- **Os processos só podem ser colocados em cgroups folha** (ou seja, os mais aninhados em uma hierarquia).
- **Um cgroup não pode possuir um controlador ausente em seu pai**.
- **Controladores para cgroups filhos devem ser declarados explicitamente** no arquivo `cgroup.subtree_control`. Por exemplo, para habilitar os controladores de CPU e PID em um cgroup filho:
```bash
echo "+cpu +pids" > cgroup.subtree_control
```
O **cgroup raiz** é uma exceção a essas regras, permitindo o posicionamento direto de processos. Isso pode ser usado para remover processos do gerenciamento do systemd.

**Monitorar o uso da CPU** dentro de um cgroup é possível através do arquivo `cpu.stat`, exibindo o tempo total de CPU consumido, útil para rastrear o uso em subprocessos de um serviço:

<figure><img src="../../../.gitbook/assets/image (2) (6) (3).png" alt=""><figcaption>Estatísticas de uso da CPU conforme mostrado no arquivo cpu.stat</figcaption></figure>

## Referências
* **Livro: How Linux Works, 3ª Edição: O Que Todo Superusuário Deve Saber Por Brian Ward**
