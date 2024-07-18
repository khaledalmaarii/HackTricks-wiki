# macOS MIG - Mach Interface Generator

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}

## Informações Básicas

O MIG foi criado para **simplificar o processo de criação de código Mach IPC**. Basicamente, ele **gera o código necessário** para o servidor e o cliente se comunicarem com uma definição fornecida. Mesmo que o código gerado seja feio, um desenvolvedor só precisará importá-lo e seu código será muito mais simples do que antes.

A definição é especificada na Linguagem de Definição de Interface (IDL) usando a extensão `.defs`.

Essas definições têm 5 seções:

* **Declaração de subsistema**: A palavra-chave subsistema é usada para indicar o **nome** e o **id**. Também é possível marcá-lo como **`KernelServer`** se o servidor deve ser executado no kernel.
* **Inclusões e importações**: O MIG usa o pré-processador C, então é capaz de usar importações. Além disso, é possível usar `uimport` e `simport` para código gerado pelo usuário ou servidor.
* **Declarações de tipo**: É possível definir tipos de dados, embora geralmente importe `mach_types.defs` e `std_types.defs`. Para tipos personalizados, pode ser usada alguma sintaxe:
* \[i`n/out]tran`: Função que precisa ser traduzida de uma mensagem de entrada ou para uma mensagem de saída
* `c[user/server]type`: Mapeamento para outro tipo de C.
* `destructor`: Chama esta função quando o tipo é liberado.
* **Operações**: Estas são as definições dos métodos RPC. Existem 5 tipos diferentes:
* `routine`: Espera resposta
* `simpleroutine`: Não espera resposta
* `procedure`: Espera resposta
* `simpleprocedure`: Não espera resposta
* `function`: Espera resposta

### Exemplo

Crie um arquivo de definição, neste caso com uma função muito simples:

{% code title="myipc.defs" %}
```cpp
subsystem myipc 500; // Arbitrary name and id

userprefix USERPREF;        // Prefix for created functions in the client
serverprefix SERVERPREF;    // Prefix for created functions in the server

#include <mach/mach_types.defs>
#include <mach/std_types.defs>

simpleroutine Subtract(
server_port :  mach_port_t;
n1          :  uint32_t;
n2          :  uint32_t);
```
{% endcode %}

Observe que o primeiro **argumento é a porta a ser vinculada** e o MIG irá **lidar automaticamente com a porta de resposta** (a menos que seja chamado `mig_get_reply_port()` no código do cliente). Além disso, o **ID das operações** será **sequencial** começando pelo ID do subsistema indicado (então, se uma operação for descontinuada, ela será excluída e `skip` é usado para continuar usando seu ID).

Agora use o MIG para gerar o código do servidor e do cliente que serão capazes de se comunicar entre si para chamar a função Subtrair:
```bash
mig -header myipcUser.h -sheader myipcServer.h myipc.defs
```
Vários novos arquivos serão criados no diretório atual.

{% hint style="success" %}
Você pode encontrar um exemplo mais complexo em seu sistema com: `mdfind mach_port.defs`\
E você pode compilá-lo a partir da mesma pasta do arquivo com: `mig -DLIBSYSCALL_INTERFACE mach_ports.defs`
{% endhint %}

Nos arquivos **`myipcServer.c`** e **`myipcServer.h`** você pode encontrar a declaração e definição da struct **`SERVERPREFmyipc_subsystem`**, que basicamente define a função a ser chamada com base no ID da mensagem recebida (indicamos um número inicial de 500):

{% tabs %}
{% tab title="myipcServer.c" %}
```c
/* Description of this subsystem, for use in direct RPC */
const struct SERVERPREFmyipc_subsystem SERVERPREFmyipc_subsystem = {
myipc_server_routine,
500, // start ID
501, // end ID
(mach_msg_size_t)sizeof(union __ReplyUnion__SERVERPREFmyipc_subsystem),
(vm_address_t)0,
{
{ (mig_impl_routine_t) 0,
// Function to call
(mig_stub_routine_t) _XSubtract, 3, 0, (routine_arg_descriptor_t)0, (mach_msg_size_t)sizeof(__Reply__Subtract_t)},
}
};
```
{% endtab %}

{% tab title="myipcServer.h" %} 

### macOS MIG (Mach Interface Generator)

O macOS MIG (Mach Interface Generator) é uma ferramenta usada para gerar interfaces de comunicação entre processos em sistemas macOS. Ele gera código C que lida com a comunicação entre processos usando mensagens MIG. Essas mensagens são enviadas por meio do Mach IPC, permitindo a comunicação entre processos em um sistema macOS. O macOS MIG é amplamente utilizado para comunicação entre processos em nível de sistema operacional. 

Para saber mais sobre o macOS MIG, consulte a documentação oficial da Apple: [Mach Interface Generator (MIG)](https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/MIG/mig_toc.html)

{% endtab %}
```c
/* Description of this subsystem, for use in direct RPC */
extern const struct SERVERPREFmyipc_subsystem {
mig_server_routine_t	server;	/* Server routine */
mach_msg_id_t	start;	/* Min routine number */
mach_msg_id_t	end;	/* Max routine number + 1 */
unsigned int	maxsize;	/* Max msg size */
vm_address_t	reserved;	/* Reserved */
struct routine_descriptor	/* Array of routine descriptors */
routine[1];
} SERVERPREFmyipc_subsystem;
```
{% endtab %}
{% endtabs %}

Com base na estrutura anterior, a função **`myipc_server_routine`** receberá o **ID da mensagem** e retornará a função apropriada a ser chamada:
```c
mig_external mig_routine_t myipc_server_routine
(mach_msg_header_t *InHeadP)
{
int msgh_id;

msgh_id = InHeadP->msgh_id - 500;

if ((msgh_id > 0) || (msgh_id < 0))
return 0;

return SERVERPREFmyipc_subsystem.routine[msgh_id].stub_routine;
}
```
Neste exemplo, apenas definimos 1 função nas definições, mas se tivéssemos definido mais funções, elas estariam dentro do array de **`SERVERPREFmyipc_subsystem`** e a primeira teria sido atribuída ao ID **500**, a segunda ao ID **501**...

Se a função fosse esperada para enviar uma **resposta**, a função `mig_internal kern_return_t __MIG_check__Reply__<nome>` também existiria.

Na verdade, é possível identificar essa relação na struct **`subsystem_to_name_map_myipc`** de **`myipcServer.h`** (**`subsystem_to_name_map_***`** em outros arquivos):
```c
#ifndef subsystem_to_name_map_myipc
#define subsystem_to_name_map_myipc \
{ "Subtract", 500 }
#endif
```
Finalmente, outra função importante para fazer o servidor funcionar será **`myipc_server`**, que é aquela que realmente **chama a função** relacionada ao ID recebido:

```c
mig_external boolean_t myipc_server
(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP)
{
/*
* typedef struct {
* 	mach_msg_header_t Head;
* 	NDR_record_t NDR;
* 	kern_return_t RetCode;
* } mig_reply_error_t;
*/

mig_routine_t routine;

OutHeadP->msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REPLY(InHeadP->msgh_bits), 0);
OutHeadP->msgh_remote_port = InHeadP->msgh_reply_port;
/* Tamanho mínimo: a rotina() irá atualizá-lo se for diferente */
OutHeadP->msgh_size = (mach_msg_size_t)sizeof(mig_reply_error_t);
OutHeadP->msgh_local_port = MACH_PORT_NULL;
OutHeadP->msgh_id = InHeadP->msgh_id + 100;
OutHeadP->msgh_reserved = 0;

if ((InHeadP->msgh_id > 500) || (InHeadP->msgh_id < 500) ||
<strong>	    ((routine = SERVERPREFmyipc_subsystem.routine[InHeadP->msgh_id - 500].stub_routine) == 0)) {
</strong>		((mig_reply_error_t *)OutHeadP)->NDR = NDR_record;
((mig_reply_error_t *)OutHeadP)->RetCode = MIG_BAD_ID;
return FALSE;
}
<strong>	(*routine) (InHeadP, OutHeadP);
</strong>	return TRUE;
}
```

Verifique as linhas anteriormente destacadas acessando a função a ser chamada por ID.

O código a seguir cria um **servidor** e um **cliente** simples onde o cliente pode chamar as funções Subtrair do servidor:

{% tabs %}
{% tab title="myipc_server.c" %}
```c
// gcc myipc_server.c myipcServer.c -o myipc_server

#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcServer.h"

kern_return_t SERVERPREFSubtract(mach_port_t server_port, uint32_t n1, uint32_t n2)
{
printf("Received: %d - %d = %d\n", n1, n2, n1 - n2);
return KERN_SUCCESS;
}

int main() {

mach_port_t port;
kern_return_t kr;

// Register the mach service
kr = bootstrap_check_in(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_check_in() failed with code 0x%x\n", kr);
return 1;
}

// myipc_server is the function that handles incoming messages (check previous exlpanation)
mach_msg_server(myipc_server, sizeof(union __RequestUnion__SERVERPREFmyipc_subsystem), port, MACH_MSG_TIMEOUT_NONE);
}
```
{% endtab %}

{% tab title="myipc_client.c" %} 

## Cliente myipc

Este é o código-fonte do cliente myipc que será usado para se comunicar com o servidor myipc.

```c
#include <stdio.h>
#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipc.h"

int main() {
    mach_port_t server_port;
    kern_return_t ret;

    ret = bootstrap_look_up(bootstrap_port, "com.example.myipc", &server_port);
    if (ret != KERN_SUCCESS) {
        printf("Erro ao procurar o serviço myipc: %s\n", mach_error_string(ret));
        return 1;
    }

    myipc_hello(server_port);

    return 0;
}
```

{% endtab %}
```c
// gcc myipc_client.c myipcUser.c -o myipc_client

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <mach/mach.h>
#include <servers/bootstrap.h>
#include "myipcUser.h"

int main() {

// Lookup the receiver port using the bootstrap server.
mach_port_t port;
kern_return_t kr = bootstrap_look_up(bootstrap_port, "xyz.hacktricks.mig", &port);
if (kr != KERN_SUCCESS) {
printf("bootstrap_look_up() failed with code 0x%x\n", kr);
return 1;
}
printf("Port right name %d\n", port);
USERPREFSubtract(port, 40, 2);
}
```
{% endtab %}
{% endtabs %}

### O registro NDR

O registro NDR é exportado por `libsystem_kernel.dylib` e é uma estrutura que permite ao MIG **transformar dados para que sejam agnósticos do sistema** no qual está sendo usado, já que o MIG foi projetado para ser utilizado entre diferentes sistemas (e não apenas na mesma máquina).

Isso é interessante porque se o `_NDR_record` for encontrado em um binário como uma dependência (`jtool2 -S <binary> | grep NDR` ou `nm`), significa que o binário é um cliente ou servidor MIG.

Além disso, os **servidores MIG** têm a tabela de despacho em `__DATA.__const` (ou em `__CONST.__constdata` no kernel do macOS e `__DATA_CONST.__const` em outros kernels \*OS). Isso pode ser extraído com o **`jtool2`**.

E os **clientes MIG** usarão o `__NDR_record` para enviar com `__mach_msg` para os servidores.

## Análise Binária

### jtool

Como muitos binários agora usam MIG para expor portas mach, é interessante saber como **identificar que o MIG foi usado** e as **funções que o MIG executa** com cada ID de mensagem.

[**jtool2**](../../macos-apps-inspecting-debugging-and-fuzzing/#jtool2) pode analisar informações do MIG de um binário Mach-O indicando o ID da mensagem e identificando a função a ser executada:
```bash
jtool2 -d __DATA.__const myipc_server | grep MIG
```
Além disso, as funções MIG são apenas invólucros da função real que é chamada, o que significa que ao obter seu desmontagem e procurar por BL, você pode ser capaz de encontrar a função real sendo chamada:
```bash
jtool2 -d __DATA.__const myipc_server | grep BL
```
### Assembly

Foi mencionado anteriormente que a função que irá **chamar a função correta dependendo do ID da mensagem recebida** era `myipc_server`. No entanto, geralmente você não terá os símbolos do binário (nomes de funções), então é interessante **ver como ela se parece decompilada**, pois sempre será muito semelhante (o código desta função é independente das funções expostas):

{% tabs %}
{% tab title="myipc_server decompiled 1" %}
<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
var_10 = arg0;
var_18 = arg1;
// Instruções iniciais para encontrar os ponteiros de função apropriados
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
if (*(int32_t *)(var_10 + 0x14) <= 0x1f4 && *(int32_t *)(var_10 + 0x14) >= 0x1f4) {
rax = *(int32_t *)(var_10 + 0x14);
// Chamada para sign_extend_64 que pode ajudar a identificar esta função
// Isso armazena em rax o ponteiro para a chamada que precisa ser feita
// Verifique o uso do endereço 0x100004040 (array de endereços de funções)
// 0x1f4 = 500 (o ID de início)
<strong>            rax = *(sign_extend_64(rax - 0x1f4) * 0x28 + 0x100004040);
</strong>            var_20 = rax;
// Se - senão, se o se retornar falso, enquanto o senão chama a função correta e retorna verdadeiro
<strong>            if (rax == 0x0) {
</strong>                    *(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
else {
// Endereço calculado que chama a função apropriada com 2 argumentos
<strong>                    (var_20)(var_10, var_18);
</strong>                    var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **_NDR_record;
*(int32_t *)(var_18 + 0x20) = 0xfffffffffffffed1;
var_4 = 0x0;
}
rax = var_4;
return rax;
}
</code></pre>
{% endtab %}

{% tab title="myipc_server decompiled 2" %}
Esta é a mesma função decompilada em uma versão gratuita diferente do Hopper:

<pre class="language-c"><code class="lang-c">int _myipc_server(int arg0, int arg1) {
r31 = r31 - 0x40;
saved_fp = r29;
stack[-8] = r30;
var_10 = arg0;
var_18 = arg1;
// Instruções iniciais para encontrar os ponteiros de função apropriados
*(int32_t *)var_18 = *(int32_t *)var_10 & 0x1f | 0x0;
*(int32_t *)(var_18 + 0x8) = *(int32_t *)(var_10 + 0x8);
*(int32_t *)(var_18 + 0x4) = 0x24;
*(int32_t *)(var_18 + 0xc) = 0x0;
*(int32_t *)(var_18 + 0x14) = *(int32_t *)(var_10 + 0x14) + 0x64;
*(int32_t *)(var_18 + 0x10) = 0x0;
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 > 0x0) {
if (CPU_FLAGS & G) {
r8 = 0x1;
}
}
if ((r8 & 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
r8 = r8 - 0x1f4;
if (r8 < 0x0) {
if (CPU_FLAGS & L) {
r8 = 0x1;
}
}
if ((r8 & 0x1) == 0x0) {
r8 = *(int32_t *)(var_10 + 0x14);
// 0x1f4 = 500 (o ID de início)
<strong>                    r8 = r8 - 0x1f4;
</strong>                    asm { smaddl     x8, w8, w9, x10 };
r8 = *(r8 + 0x8);
var_20 = r8;
r8 = r8 - 0x0;
if (r8 != 0x0) {
if (CPU_FLAGS & NE) {
r8 = 0x1;
}
}
// Mesmo se senão que na versão anterior
// Verifique o uso do endereço 0x100004040 (array de endereços de funções)
<strong>                    if ((r8 & 0x1) == 0x0) {
</strong><strong>                            *(var_18 + 0x18) = **0x100004000;
</strong>                            *(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
else {
// Chamada para o endereço calculado onde a função deve estar
<strong>                            (var_20)(var_10, var_18);
</strong>                            var_4 = 0x1;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
}
else {
*(var_18 + 0x18) = **0x100004000;
*(int32_t *)(var_18 + 0x20) = 0xfffffed1;
var_4 = 0x0;
}
r0 = var_4;
return r0;
}

</code></pre>
{% endtab %}
{% endtabs %}

Na verdade, se você for para a função **`0x100004000`**, você encontrará o array de structs **`routine_descriptor`**. O primeiro elemento da struct é o **endereço** onde a **função** é implementada, e a **struct tem 0x28 bytes**, então a cada 0x28 bytes (começando do byte 0) você pode obter 8 bytes e esse será o **endereço da função** que será chamada:

<figure><img src="../../../../.gitbook/assets/image (35).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../../.gitbook/assets/image (36).png" alt=""><figcaption></figcaption></figure>

Esses dados podem ser extraídos [**usando este script do Hopper**](https://github.com/knightsc/hopper/blob/master/scripts/MIG%20Detect.py).
### Depuração

O código gerado pelo MIG também chama `kernel_debug` para gerar logs sobre operações na entrada e saída. É possível verificá-los usando **`trace`** ou **`kdv`**: `kdv all | grep MIG`

## Referências

* [\*OS Internals, Volume I, User Mode, Jonathan Levin](https://www.amazon.com/MacOS-iOS-Internals-User-Mode/dp/099105556X)

{% hint style="success" %}
Aprenda e pratique Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Aprenda e pratique Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Suporte ao HackTricks</summary>

* Verifique os [**planos de assinatura**](https://github.com/sponsors/carlospolop)!
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe truques de hacking enviando PRs para os repositórios** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
{% endhint %}
