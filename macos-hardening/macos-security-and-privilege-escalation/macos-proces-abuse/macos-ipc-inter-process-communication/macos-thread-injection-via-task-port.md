# Injeção de Thread no macOS via Porta de Tarefa

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios do GitHub** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Código

* [https://github.com/bazad/threadexec](https://github.com/bazad/threadexec)
* [https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36](https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36)


## 1. Sequestro de Thread

Inicialmente, a função **`task_threads()`** é invocada na porta de tarefa para obter uma lista de threads da tarefa remota. Uma thread é selecionada para o sequestro. Esta abordagem diverge dos métodos convencionais de injeção de código, pois a criação de uma nova thread remota é proibida devido à nova mitigação que bloqueia `thread_create_running()`.

Para controlar a thread, **`thread_suspend()`** é chamado, interrompendo sua execução.

As únicas operações permitidas na thread remota envolvem **parar** e **iniciar** a mesma, **recuperar** e **modificar** seus valores de registradores. Chamadas de função remotas são iniciadas configurando os registradores `x0` a `x7` para os **argumentos**, ajustando **`pc`** para a função desejada e ativando a thread. Garantir que a thread não trave após o retorno requer detecção do retorno.

Uma estratégia envolve **registrar um manipulador de exceções** para a thread remota usando `thread_set_exception_ports()`, definindo o registrador `lr` para um endereço inválido antes da chamada da função. Isso desencadeia uma exceção após a execução da função, enviando uma mensagem para a porta de exceção, permitindo a inspeção do estado da thread para recuperar o valor de retorno. Alternativamente, como adotado do exploit triple\_fetch de Ian Beer, `lr` é configurado para entrar em loop infinito. Os registradores da thread são então monitorados continuamente até que **`pc` aponte para essa instrução**.

## 2. Portas Mach para comunicação

A fase subsequente envolve o estabelecimento de portas Mach para facilitar a comunicação com a thread remota. Essas portas são fundamentais na transferência de direitos de envio e recebimento arbitrários entre tarefas.

Para comunicação bidirecional, dois direitos de recebimento Mach são criados: um na tarefa local e outro na tarefa remota. Em seguida, um direito de envio para cada porta é transferido para a tarefa correspondente, possibilitando a troca de mensagens.

Focando na porta local, o direito de recebimento é mantido pela tarefa local. A porta é criada com `mach_port_allocate()`. O desafio está em transferir um direito de envio para esta porta para a tarefa remota.

Uma estratégia envolve o uso de `thread_set_special_port()` para colocar um direito de envio para a porta local no `THREAD_KERNEL_PORT` da thread remota. Então, a thread remota é instruída a chamar `mach_thread_self()` para recuperar o direito de envio.

Para a porta remota, o processo é essencialmente invertido. A thread remota é direcionada a gerar uma porta Mach através de `mach_reply_port()` (já que `mach_port_allocate()` é inadequado devido ao seu mecanismo de retorno). Após a criação da porta, `mach_port_insert_right()` é invocado na thread remota para estabelecer um direito de envio. Esse direito é então armazenado no kernel usando `thread_set_special_port()`. De volta à tarefa local, `thread_get_special_port()` é usado na thread remota para adquirir um direito de envio para a nova porta Mach alocada na tarefa remota.

A conclusão dessas etapas resulta no estabelecimento de portas Mach, preparando o terreno para comunicação bidirecional.

## 3. Primitivas Básicas de Leitura/Escrita de Memória

Nesta seção, o foco é utilizar a primitiva de execução para estabelecer primitivas básicas de leitura e escrita de memória. Esses passos iniciais são cruciais para obter mais controle sobre o processo remoto, embora as primitivas neste estágio não sirvam para muitos propósitos. Em breve, elas serão atualizadas para versões mais avançadas.

### Leitura e Escrita de Memória Usando Primitiva de Execução

O objetivo é realizar leitura e escrita de memória usando funções específicas. Para ler memória, funções com a seguinte estrutura são utilizadas:
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
Estas funções correspondem às instruções de montagem dadas:
```
_read_func:
ldr x0, [x0]
ret
_write_func:
str x1, [x0]
ret
```
### Identificando Funções Adequadas

Uma varredura de bibliotecas comuns revelou candidatos apropriados para essas operações:

1. **Leitura de Memória:**
A função `property_getName()` da [biblioteca runtime do Objective-C](https://opensource.apple.com/source/objc4/objc4-723/runtime/objc-runtime-new.mm.auto.html) é identificada como uma função adequada para leitura de memória. A função está descrita abaixo:

```c
const char *property_getName(objc_property_t prop) {
return prop->name;
}
```

Essa função efetivamente age como a `read_func` ao retornar o primeiro campo de `objc_property_t`.

2. **Escrita de Memória:**
Encontrar uma função pré-construída para escrita de memória é mais desafiador. No entanto, a função `_xpc_int64_set_value()` da libxpc é uma candidata adequada com a seguinte desmontagem:
```
__xpc_int64_set_value:
str x1, [x0, #0x18]
ret
```
Para realizar uma escrita de 64 bits em um endereço específico, a chamada remota é estruturada como:
```c
_xpc_int64_set_value(address - 0x18, value)
```
Com essas primitivas estabelecidas, o cenário está preparado para a criação de memória compartilhada, marcando um progresso significativo no controle do processo remoto.

## 4. Configuração de Memória Compartilhada

O objetivo é estabelecer memória compartilhada entre tarefas locais e remotas, simplificando a transferência de dados e facilitando a chamada de funções com múltiplos argumentos. A abordagem envolve o uso de `libxpc` e seu tipo de objeto `OS_xpc_shmem`, que é construído sobre entradas de memória Mach.

### Visão Geral do Processo:

1. **Alocação de Memória**:
- Alocar a memória para compartilhamento usando `mach_vm_allocate()`.
- Usar `xpc_shmem_create()` para criar um objeto `OS_xpc_shmem` para a região de memória alocada. Esta função gerenciará a criação da entrada de memória Mach e armazenará o direito de envio Mach no deslocamento `0x18` do objeto `OS_xpc_shmem`.

2. **Criando Memória Compartilhada no Processo Remoto**:
- Alocar memória para o objeto `OS_xpc_shmem` no processo remoto com uma chamada remota para `malloc()`.
- Copiar o conteúdo do objeto `OS_xpc_shmem` local para o processo remoto. No entanto, esta cópia inicial terá nomes de entrada de memória Mach incorretos no deslocamento `0x18`.

3. **Corrigindo a Entrada de Memória Mach**:
- Utilizar o método `thread_set_special_port()` para inserir um direito de envio para a entrada de memória Mach na tarefa remota.
- Corrigir o campo de entrada de memória Mach no deslocamento `0x18` sobrescrevendo-o com o nome da entrada de memória remota.

4. **Finalizando a Configuração de Memória Compartilhada**:
- Validar o objeto `OS_xpc_shmem` remoto.
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
Lembre-se de lidar corretamente com os detalhes dos Mach ports e nomes de entrada de memória para garantir que a configuração de memória compartilhada funcione adequadamente.

## 5. Alcançando Controle Total

Após estabelecer com sucesso a memória compartilhada e obter capacidades de execução arbitrária, essencialmente ganhamos controle total sobre o processo alvo. As funcionalidades-chave que possibilitam esse controle são:

1. **Operações de Memória Arbitrárias**:
- Realize leituras de memória arbitrárias invocando `memcpy()` para copiar dados da região compartilhada.
- Execute escritas de memória arbitrárias usando `memcpy()` para transferir dados para a região compartilhada.

2. **Manipulação de Chamadas de Função com Múltiplos Argumentos**:
- Para funções que requerem mais de 8 argumentos, organize os argumentos adicionais na pilha em conformidade com a convenção de chamadas.

3. **Transferência de Mach Port**:
- Transfira Mach ports entre tarefas através de mensagens Mach via ports previamente estabelecidos.

4. **Transferência de Descritor de Arquivo**:
- Transfira descritores de arquivo entre processos usando fileports, uma técnica destacada por Ian Beer em `triple_fetch`.

Esse controle abrangente está encapsulado na biblioteca [threadexec](https://github.com/bazad/threadexec), fornecendo uma implementação detalhada e uma API amigável para interação com o processo vítima.

## Considerações Importantes:

- Garanta o uso adequado de `memcpy()` para operações de leitura/escrita de memória para manter a estabilidade do sistema e a integridade dos dados.
- Ao transferir Mach ports ou descritores de arquivo, siga os protocolos adequados e gerencie os recursos de forma responsável para evitar vazamentos ou acessos não intencionais.

Seguindo essas diretrizes e utilizando a biblioteca `threadexec`, é possível gerenciar e interagir com processos em um nível granular de forma eficiente, alcançando controle total sobre o processo alvo.

# Referências
* https://bazad.github.io/2018/10/bypassing-platform-binary-task-threads/

<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga**-me no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
