# Injeção de Thread no macOS via Porta de Tarefa

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

Este post foi copiado de [https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/](https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/) (que contém mais informações)

### Código

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)

### 1. Sequestro de Thread

A primeira coisa que fazemos é chamar **`task_threads()`** na porta de tarefa para obter uma lista de threads na tarefa remota e, em seguida, escolher uma delas para sequestrar. Ao contrário dos frameworks tradicionais de injeção de código, **não podemos criar uma nova thread remota** porque `thread_create_running()` será bloqueado pela nova mitigação.

Em seguida, podemos chamar **`thread_suspend()`** para parar a thread de executar.

Neste ponto, o único controle útil que temos sobre a thread remota é **pará-la**, **iniciá-la**, **obter** seus valores de **registradores** e **definir** seus valores de registradores. Assim, podemos **iniciar uma chamada de função remota** definindo os registradores `x0` até `x7` na thread remota para os **argumentos**, **definindo** **`pc`** para a função que queremos executar e iniciando a thread. Neste ponto, precisamos detectar o retorno e garantir que a thread não trave.

Existem algumas maneiras de fazer isso. Uma maneira seria **registrar um manipulador de exceções** para a thread remota usando `thread_set_exception_ports()` e definir o registrador de endereço de retorno, `lr`, para um endereço inválido antes de chamar a função; dessa forma, após a execução da função, uma exceção seria gerada e uma mensagem seria enviada para nossa porta de exceção, momento em que podemos inspecionar o estado da thread para recuperar o valor de retorno. No entanto, pela simplicidade, copiei a estratégia usada no exploit triple\_fetch de Ian Beer, que era **definir `lr` para o endereço de uma instrução que faria um loop infinito** e, em seguida, sondar repetidamente os registradores da thread até que **`pc` apontasse para essa instrução**.

### 2. Portas Mach para comunicação

O próximo passo é **criar portas Mach pelas quais podemos nos comunicar com a thread remota**. Essas portas Mach serão úteis mais tarde para ajudar na transferência de direitos de envio e recebimento arbitrários entre as tarefas.

Para estabelecer comunicação bidirecional, precisaremos criar dois direitos de recebimento Mach: um na **tarefa local e outro na tarefa remota**. Então, precisaremos **transferir um direito de envio** para cada porta **para a outra tarefa**. Isso dará a cada tarefa uma maneira de enviar uma mensagem que pode ser recebida pela outra.

Vamos primeiro nos concentrar em configurar a porta local, ou seja, a porta para a qual a tarefa local detém o direito de recebimento. Podemos criar a porta Mach como qualquer outra, chamando `mach_port_allocate()`. O truque é conseguir um direito de envio para essa porta na tarefa remota.

Um truque conveniente que podemos usar para copiar um direito de envio da tarefa atual para uma tarefa remota usando apenas um primitivo de execução básico é armazenar um **direito de envio para nossa porta local no `THREAD_KERNEL_PORT` especial da thread remota** usando `thread_set_special_port()`; então, podemos fazer a thread remota chamar `mach_thread_self()` para recuperar o direito de envio.

Em seguida, vamos configurar a porta remota, que é praticamente o inverso do que acabamos de fazer. Podemos fazer a **thread remota alocar uma porta Mach chamando `mach_reply_port()`**; não podemos usar `mach_port_allocate()` porque o último retorna o nome da porta alocada na memória e ainda não temos um primitivo de leitura. Uma vez que temos uma porta, podemos criar um direito de envio chamando `mach_port_insert_right()` na thread remota. Então, podemos armazenar a porta no kernel chamando `thread_set_special_port()`. Finalmente, de volta à tarefa local, podemos recuperar a porta chamando `thread_get_special_port()` na thread remota, **nos dando um direito de envio para a porta Mach recém-alocada na tarefa remota**.

Neste ponto, criamos as portas Mach que usaremos para comunicação bidirecional.

### 3. Leitura/Escrita Básica de Memória <a href="#step-3-basic-memory-readwrite" id="step-3-basic-memory-readwrite"></a>

Agora usaremos o primitivo de execução para criar primitivos básicos de leitura e escrita de memória. Esses primitivos não serão muito usados (em breve atualizaremos para primitivos muito mais poderosos), mas são um passo chave para nos ajudar a expandir nosso controle do processo remoto.

Para ler e escrever memória usando nosso primitivo de execução, estaremos procurando por funções como estas:
```c
uint64_t read_func(uint64_t *address) {
return *address;
}
void write_func(uint64_t *address, uint64_t value) {
*address = value;
}
```
Eles podem corresponder à seguinte montagem:
```
_read_func:
ldr     x0, [x0]
ret
_write_func:
str     x1, [x0]
ret
```
Uma rápida análise de algumas bibliotecas comuns revelou bons candidatos. Para ler memória, podemos usar a função `property_getName()` da [biblioteca de tempo de execução do Objective-C](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html):
```c
const char *property_getName(objc_property_t prop)
{
return prop->name;
}
```
Como se verifica, `prop` é o primeiro campo de `objc_property_t`, portanto, isso corresponde diretamente à hipotética `read_func` acima. Precisamos apenas realizar uma chamada de função remota com o primeiro argumento sendo o endereço que queremos ler, e o valor de retorno será os dados naquele endereço.

Encontrar uma função pronta para escrever na memória é um pouco mais difícil, mas ainda existem ótimas opções sem efeitos colaterais indesejados. Na libxpc, a função `_xpc_int64_set_value()` tem o seguinte desmonte:
```
__xpc_int64_set_value:
str     x1, [x0, #0x18]
ret
```
Portanto, para realizar uma escrita de 64 bits no endereço `address`, podemos executar a chamada remota:
```c
_xpc_int64_set_value(address - 0x18, value)
```
### 4. Memória compartilhada

Nosso próximo passo é criar uma memória compartilhada entre a tarefa remota e a local. Isso nos permitirá transferir dados entre os processos mais facilmente: com uma região de memória compartilhada, a leitura e escrita de memória arbitrária é tão simples quanto uma chamada remota para `memcpy()`. Além disso, ter uma região de memória compartilhada nos permitirá configurar facilmente uma pilha para que possamos chamar funções com mais de 8 argumentos.

Para facilitar, podemos reutilizar os recursos de memória compartilhada do libxpc. O libxpc fornece um tipo de objeto XPC, `OS_xpc_shmem`, que permite estabelecer regiões de memória compartilhada por meio do XPC. Ao reverter o libxpc, determinamos que `OS_xpc_shmem` é baseado em entradas de memória Mach, que são portas Mach que representam uma região de memória virtual. E como já mostramos como enviar portas Mach para a tarefa remota, podemos usar isso para configurar facilmente nossa própria memória compartilhada.

Primeiro, precisamos alocar a memória que compartilharemos usando `mach_vm_allocate()`. Precisamos usar `mach_vm_allocate()` para que possamos usar `xpc_shmem_create()` para criar um objeto `OS_xpc_shmem` para a região. `xpc_shmem_create()` cuidará de criar a entrada de memória Mach para nós e armazenará o direito de envio Mach para a entrada de memória no objeto `OS_xpc_shmem` opaco no deslocamento `0x18`.

Uma vez que temos o porto de entrada de memória, criaremos um objeto `OS_xpc_shmem` no processo remoto representando a mesma região de memória, permitindo-nos chamar `xpc_shmem_map()` para estabelecer o mapeamento de memória compartilhada. Primeiro, realizamos uma chamada remota para `malloc()` para alocar memória para o `OS_xpc_shmem` e usamos nosso primitivo básico de escrita para copiar o conteúdo do objeto `OS_xpc_shmem` local. Infelizmente, o objeto resultante não está completamente correto: seu campo de entrada de memória Mach no deslocamento `0x18` contém o nome da tarefa local para a entrada de memória, não o nome da tarefa remota. Para corrigir isso, usamos o truque `thread_set_special_port()` para inserir um direito de envio para a entrada de memória Mach na tarefa remota e, em seguida, sobrescrever o campo `0x18` com o nome da entrada de memória remota. Neste ponto, o objeto `OS_xpc_shmem` remoto é válido e o mapeamento de memória pode ser estabelecido com uma chamada remota para `xpc_shmem_remote()`.

### 5. Controle total <a href="#step-5-full-control" id="step-5-full-control"></a>

Com a memória compartilhada em um endereço conhecido e um primitivo de execução arbitrária, basicamente terminamos. Leituras e escritas de memória arbitrárias são implementadas chamando `memcpy()` para e da região compartilhada, respectivamente. Chamadas de função com mais de 8 argumentos são realizadas organizando argumentos adicionais além dos primeiros 8 na pilha de acordo com a convenção de chamada. A transferência de portas Mach arbitrárias entre as tarefas pode ser feita enviando mensagens Mach pelas portas estabelecidas anteriormente. Até podemos transferir descritores de arquivo entre os processos usando fileports (agradecimentos especiais a Ian Beer por demonstrar essa técnica em triple_fetch!).

Em resumo, agora temos controle total e fácil sobre o processo vítima. Você pode ver a implementação completa e a API exposta na biblioteca [threadexec](https://github.com/bazad/threadexec).

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF** Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**merchandising oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga** me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
