# macOS Thread Injection via Task port

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Confira os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga**-nos no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>
{% endhint %}

## Code

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Thread Hijacking

Inicialmente, a função **`task_threads()`** é invocada na porta da tarefa para obter uma lista de threads da tarefa remota. Uma thread é selecionada para sequestro. Essa abordagem diverge dos métodos convencionais de injeção de código, pois criar uma nova thread remota é proibido devido à nova mitigação que bloqueia `thread_create_running()`.

Para controlar a thread, **`thread_suspend()`** é chamada, interrompendo sua execução.

As únicas operações permitidas na thread remota envolvem **parar** e **iniciar** a thread, **recuperar** e **modificar** seus valores de registradores. Chamadas de função remotas são iniciadas configurando os registradores `x0` a `x7` com os **argumentos**, configurando **`pc`** para direcionar à função desejada e ativando a thread. Garantir que a thread não falhe após o retorno requer a detecção do retorno.

Uma estratégia envolve **registrar um manipulador de exceção** para a thread remota usando `thread_set_exception_ports()`, configurando o registrador `lr` para um endereço inválido antes da chamada da função. Isso aciona uma exceção após a execução da função, enviando uma mensagem para a porta de exceção, permitindo a inspeção do estado da thread para recuperar o valor de retorno. Alternativamente, como adotado do exploit triple\_fetch de Ian Beer, `lr` é configurado para loop infinito. Os registradores da thread são então monitorados continuamente até que **`pc` aponte para essa instrução**.

## 2. Mach ports for communication

A fase subsequente envolve estabelecer portas Mach para facilitar a comunicação com a thread remota. Essas portas são instrumentais na transferência de direitos de envio e recebimento arbitrários entre tarefas.

Para comunicação bidirecional, dois direitos de recebimento Mach são criados: um na tarefa local e o outro na tarefa remota. Subsequentemente, um direito de envio para cada porta é transferido para a tarefa correspondente, permitindo a troca de mensagens.

Focando na porta local, o direito de recebimento é mantido pela tarefa local. A porta é criada com `mach_port_allocate()`. O desafio reside em transferir um direito de envio para esta porta na tarefa remota.

Uma estratégia envolve aproveitar `thread_set_special_port()` para colocar um direito de envio na porta local na `THREAD_KERNEL_PORT` da thread remota. Em seguida, a thread remota é instruída a chamar `mach_thread_self()` para recuperar o direito de envio.

Para a porta remota, o processo é essencialmente invertido. A thread remota é direcionada a gerar uma porta Mach via `mach_reply_port()` (já que `mach_port_allocate()` não é adequada devido ao seu mecanismo de retorno). Após a criação da porta, `mach_port_insert_right()` é invocado na thread remota para estabelecer um direito de envio. Esse direito é então armazenado no kernel usando `thread_set_special_port()`. De volta à tarefa local, `thread_get_special_port()` é usado na thread remota para adquirir um direito de envio para a nova porta Mach alocada na tarefa remota.

A conclusão desses passos resulta no estabelecimento de portas Mach, preparando o terreno para comunicação bidirecional.

## 3. Basic Memory Read/Write Primitives

Nesta seção, o foco está em utilizar o primitivo de execução para estabelecer primitivas básicas de leitura e escrita de memória. Esses passos iniciais são cruciais para obter mais controle sobre o processo remoto, embora os primitivos nesta fase não sirvam para muitos propósitos. Em breve, eles serão atualizados para versões mais avançadas.

### Memory Reading and Writing Using Execute Primitive

O objetivo é realizar leitura e escrita de memória usando funções específicas. Para ler memória, funções que se assemelham à seguinte estrutura são usadas:
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
Essas funções correspondem às instruções de assembly dadas:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identificando Funções Adequadas

Uma varredura em bibliotecas comuns revelou candidatos apropriados para essas operações:

1. **Lendo Memória:**
A função `property_getName()` da [biblioteca de tempo de execução do Objective-C](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) é identificada como uma função adequada para ler memória. A função é descrita abaixo:
```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```
Esta função atua efetivamente como o `read_func` ao retornar o primeiro campo de `objc_property_t`.

2. **Escrevendo na Memória:**
Encontrar uma função pré-construída para escrever na memória é mais desafiador. No entanto, a função `_xpc_int64_set_value()` da libxpc é uma candidata adequada com a seguinte desassemblagem:
```c
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Para realizar uma gravação de 64 bits em um endereço específico, a chamada remota é estruturada da seguinte forma:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Com essas primitivas estabelecidas, o palco está preparado para criar memória compartilhada, marcando um progresso significativo no controle do processo remoto.

## 4. Configuração de Memória Compartilhada

O objetivo é estabelecer memória compartilhada entre tarefas locais e remotas, simplificando a transferência de dados e facilitando a chamada de funções com múltiplos argumentos. A abordagem envolve aproveitar `libxpc` e seu tipo de objeto `OS_xpc_shmem`, que é construído sobre entradas de memória Mach.

### Visão Geral do Processo:

1. **Alocação de Memória**:
- Alocar a memória para compartilhamento usando `mach_vm_allocate()`.
- Usar `xpc_shmem_create()` para criar um objeto `OS_xpc_shmem` para a região de memória alocada. Esta função gerenciará a criação da entrada de memória Mach e armazenará o direito de envio Mach no deslocamento `0x18` do objeto `OS_xpc_shmem`.

2. **Criando Memória Compartilhada no Processo Remoto**:
- Alocar memória para o objeto `OS_xpc_shmem` no processo remoto com uma chamada remota para `malloc()`.
- Copiar o conteúdo do objeto local `OS_xpc_shmem` para o processo remoto. No entanto, essa cópia inicial terá nomes de entrada de memória Mach incorretos no deslocamento `0x18`.

3. **Corrigindo a Entrada de Memória Mach**:
- Utilizar o método `thread_set_special_port()` para inserir um direito de envio para a entrada de memória Mach na tarefa remota.
- Corrigir o campo da entrada de memória Mach no deslocamento `0x18` sobrescrevendo-o com o nome da entrada de memória remota.

4. **Finalizando a Configuração de Memória Compartilhada**:
- Validar o objeto remoto `OS_xpc_shmem`.
- Estabelecer o mapeamento de memória compartilhada com uma chamada remota para `xpc_shmem_remote()`.

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
Lembre-se de lidar corretamente com os detalhes das portas Mach e os nomes de entrada de memória para garantir que a configuração de memória compartilhada funcione corretamente.

## 5. Obtendo Controle Total

Após estabelecer com sucesso a memória compartilhada e ganhar capacidades de execução arbitrária, essencialmente ganhamos controle total sobre o processo alvo. As principais funcionalidades que possibilitam esse controle são:

1. **Operações de Memória Arbitrária**:
- Realizar leituras de memória arbitrárias invocando `memcpy()` para copiar dados da região compartilhada.
- Executar gravações de memória arbitrárias usando `memcpy()` para transferir dados para a região compartilhada.

2. **Manipulação de Chamadas de Função com Múltiplos Argumentos**:
- Para funções que requerem mais de 8 argumentos, organize os argumentos adicionais na pilha em conformidade com a convenção de chamada.

3. **Transferência de Porta Mach**:
- Transferir portas Mach entre tarefas através de mensagens Mach via portas previamente estabelecidas.

4. **Transferência de Descritor de Arquivo**:
- Transferir descritores de arquivo entre processos usando fileports, uma técnica destacada por Ian Beer em `triple_fetch`.

Esse controle abrangente está encapsulado na biblioteca [threadexec](https://github.com/bazad/threadexec), fornecendo uma implementação detalhada e uma API amigável para interação com o processo vítima.

## Considerações Importantes:

- Assegure o uso adequado de `memcpy()` para operações de leitura/gravação de memória para manter a estabilidade do sistema e a integridade dos dados.
- Ao transferir portas Mach ou descritores de arquivo, siga os protocolos adequados e gerencie os recursos de forma responsável para evitar leaks ou acesso não intencional.

Ao aderir a essas diretrizes e utilizar a biblioteca `threadexec`, é possível gerenciar e interagir com processos de forma eficiente em um nível granular, alcançando controle total sobre o processo alvo.

## Referências
* [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/)

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
