# Injeção de Thread no macOS via porta de tarefa

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira [**produtos oficiais PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe seus truques de hacking enviando PRs para os repositórios do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Código

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Sequestro de Thread

Inicialmente, a função **`task_threads()`** é invocada na porta da tarefa para obter uma lista de threads da tarefa remota. Um thread é selecionado para sequestro. Esta abordagem difere dos métodos convencionais de injeção de código, pois a criação de um novo thread remoto é proibida devido à nova mitigação que bloqueia `thread_create_running()`.

Para controlar o thread, é chamado **`thread_suspend()`**, interrompendo sua execução.

As únicas operações permitidas no thread remoto envolvem **parar** e **iniciar** ele, **recuperar** e **modificar** seus valores de registro. Chamadas de função remotas são iniciadas configurando os registros `x0` a `x7` para os **argumentos**, configurando **`pc`** para a função desejada e ativando o thread. Garantir que o thread não falhe após o retorno requer a detecção do retorno.

Uma estratégia envolve **registrar um manipulador de exceção** para o thread remoto usando `thread_set_exception_ports()`, configurando o registro `lr` para um endereço inválido antes da chamada da função. Isso desencadeia uma exceção pós-execução da função, enviando uma mensagem para a porta de exceção, permitindo a inspeção do estado do thread para recuperar o valor de retorno. Alternativamente, como adotado do exploit triple\_fetch de Ian Beer, `lr` é configurado para fazer um loop infinito. Os registros do thread são então monitorados continuamente até que o **`pc` aponte para essa instrução**.

## 2. Portas Mach para comunicação

A fase subsequente envolve o estabelecimento de portas Mach para facilitar a comunicação com o thread remoto. Essas portas são instrumentais na transferência de direitos de envio e recebimento arbitrários entre tarefas.

Para comunicação bidirecional, são criados dois direitos de recebimento Mach: um na tarefa local e outro na tarefa remota. Posteriormente, um direito de envio para cada porta é transferido para a tarefa correspondente, permitindo a troca de mensagens.

Focando na porta local, o direito de recebimento é mantido pela tarefa local. A porta é criada com `mach_port_allocate()`. O desafio está em transferir um direito de envio para esta porta para a tarefa remota.

Uma estratégia envolve aproveitar `thread_set_special_port()` para colocar um direito de envio para a porta local no `THREAD_KERNEL_PORT` do thread remoto. Em seguida, instrui-se o thread remoto a chamar `mach_thread_self()` para recuperar o direito de envio.

Para a porta remota, o processo é essencialmente reverso. O thread remoto é direcionado a gerar uma porta Mach via `mach_reply_port()` (como `mach_port_allocate()` é inadequado devido ao seu mecanismo de retorno). Após a criação da porta, `mach_port_insert_right()` é invocado no thread remoto para estabelecer um direito de envio. Este direito é então armazenado no kernel usando `thread_set_special_port()`. De volta à tarefa local, `thread_get_special_port()` é usado no thread remoto para adquirir um direito de envio para a porta Mach recém-alocada na tarefa remota.

A conclusão dessas etapas resulta no estabelecimento de portas Mach, preparando o terreno para a comunicação bidirecional.

## 3. Primitivas Básicas de Leitura/Gravação de Memória

Nesta seção, o foco está em utilizar a primitiva de execução para estabelecer primitivas básicas de leitura e gravação de memória. Esses passos iniciais são cruciais para obter mais controle sobre o processo remoto, embora as primitivas nesta fase não sirvam para muitos propósitos. Em breve, elas serão atualizadas para versões mais avançadas.

### Leitura e Escrita de Memória Usando a Primitiva de Execução

O objetivo é realizar a leitura e escrita de memória usando funções específicas. Para ler memória, são usadas funções com a seguinte estrutura:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
```
E para escrever na memória, funções semelhantes a esta estrutura são usadas:
```c
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Estas funções correspondem às instruções de montagem fornecidas:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identificação de Funções Adequadas

Uma varredura de bibliotecas comuns revelou candidatos apropriados para essas operações:

1. **Lendo Memória:**
A função `property_getName()` da [biblioteca de tempo de execução Objective-C](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) é identificada como uma função adequada para ler memória. A função é descrita abaixo:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Esta função atua efetivamente como a `read_func` retornando o primeiro campo de `objc_property_t`.

2. **Escrevendo na Memória:**
Encontrar uma função pré-construída para escrever na memória é mais desafiador. No entanto, a função `_xpc_int64_set_value()` da libxpc é um candidato adequado com o seguinte desmontagem:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Para realizar uma escrita de 64 bits em um endereço específico, a chamada remota é estruturada da seguinte forma:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Com essas primitivas estabelecidas, o palco está montado para criar memória compartilhada, marcando uma progressão significativa no controle do processo remoto.

## 4. Configuração de Memória Compartilhada

O objetivo é estabelecer memória compartilhada entre tarefas locais e remotas, simplificando a transferência de dados e facilitando a chamada de funções com múltiplos argumentos. A abordagem envolve alavancar `libxpc` e seu tipo de objeto `OS_xpc_shmem`, que é construído sobre entradas de memória Mach.

### Visão Geral do Processo:

1. **Alocação de Memória**:
- Aloque a memória para compartilhamento usando `mach_vm_allocate()`.
- Use `xpc_shmem_create()` para criar um objeto `OS_xpc_shmem` para a região de memória alocada. Essa função gerenciará a criação da entrada de memória Mach e armazenará o direito de envio Mach no deslocamento `0x18` do objeto `OS_xpc_shmem`.

2. **Criando Memória Compartilhada no Processo Remoto**:
- Aloque memória para o objeto `OS_xpc_shmem` no processo remoto com uma chamada remota para `malloc()`.
- Copie o conteúdo do objeto `OS_xpc_shmem` local para o processo remoto. No entanto, essa cópia inicial terá nomes de entrada de memória Mach incorretos no deslocamento `0x18`.

3. **Corrigindo a Entrada de Memória Mach**:
- Utilize o método `thread_set_special_port()` para inserir um direito de envio para a entrada de memória Mach na tarefa remota.
- Corrija o campo de entrada de memória Mach no deslocamento `0x18` sobrescrevendo-o com o nome da entrada de memória remota.

4. **Finalizando a Configuração de Memória Compartilhada**:
- Valide o objeto `OS_xpc_shmem` remoto.
- Estabeleça o mapeamento de memória compartilhada com uma chamada remota para `xpc_shmem_remote()`.

Seguindo esses passos, a memória compartilhada entre as tarefas locais e remotas será configurada de forma eficiente, permitindo transferências de dados diretas e a execução de funções que requerem múltiplos argumentos.

## Trechos de Código Adicionais

Para alocação de memória e criação de objeto de memória compartilhada:
```c
mach_vm_allocate();
xpc_shmem_create();
```
Para criar e corrigir o objeto de memória compartilhada no processo remoto:
```c
malloc(); // for allocating memory remotely
thread_set_special_port(); // for inserting send right
```
## 5. Alcançando Controle Total

Após estabelecer com sucesso a memória compartilhada e obter capacidades de execução arbitrárias, essencialmente ganhamos controle total sobre o processo alvo. As principais funcionalidades que possibilitam esse controle são:

1. **Operações de Memória Arbitrárias**:
   - Realizar leituras de memória arbitrárias invocando `memcpy()` para copiar dados da região compartilhada.
   - Executar escritas de memória arbitrárias usando `memcpy()` para transferir dados para a região compartilhada.

2. **Manipulação de Chamadas de Função com Múltiplos Argumentos**:
   - Para funções que exigem mais de 8 argumentos, organize os argumentos adicionais na pilha em conformidade com a convenção de chamada.

3. **Transferência de Porta Mach**:
   - Transferir portas Mach entre tarefas por meio de mensagens Mach via portas previamente estabelecidas.

4. **Transferência de Descritor de Arquivo**:
   - Transferir descritores de arquivo entre processos usando fileports, uma técnica destacada por Ian Beer em `triple_fetch`.

Esse controle abrangente está encapsulado na biblioteca [threadexec](https://github.com/bazad/threadexec), fornecendo uma implementação detalhada e uma API amigável para interação com o processo vítima.

## Considerações Importantes:

- Garanta o uso adequado do `memcpy()` para operações de leitura/escrita de memória a fim de manter a estabilidade do sistema e a integridade dos dados.
- Ao transferir portas Mach ou descritores de arquivo, siga protocolos adequados e gerencie recursos de forma responsável para evitar vazamentos ou acessos não intencionais.

Ao aderir a essas diretrizes e utilizar a biblioteca `threadexec`, é possível gerenciar e interagir eficientemente com processos em um nível granular, alcançando controle total sobre o processo alvo.

## Referências
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)
