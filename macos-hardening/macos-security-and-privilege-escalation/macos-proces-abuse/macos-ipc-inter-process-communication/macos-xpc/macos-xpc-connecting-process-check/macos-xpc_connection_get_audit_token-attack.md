# Ataque xpc\_connection\_get\_audit\_token do macOS

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você deseja ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Junte-se ao** 💬 [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-nos** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repositórios do github.

</details>

**Para mais informações, consulte o post original:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Este é um resumo:

## Informações Básicas sobre Mensagens Mach

Se você não sabe o que são Mensagens Mach, comece verificando esta página:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Por enquanto, lembre-se de que ([definição daqui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
As mensagens Mach são enviadas por uma _porta mach_, que é um canal de comunicação de **um receptor, vários remetentes** integrado ao kernel mach. **Múltiplos processos podem enviar mensagens** para uma porta mach, mas em qualquer momento **apenas um processo pode lê-la**. Assim como descritores de arquivo e soquetes, as portas mach são alocadas e gerenciadas pelo kernel e os processos veem apenas um número inteiro, que podem usar para indicar ao kernel qual de suas portas mach desejam usar.

## Conexão XPC

Se você não sabe como uma conexão XPC é estabelecida, verifique:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Resumo da Vulnerabilidade

O que é interessante saber é que a **abstração do XPC é uma conexão um para um**, mas é baseada em cima de uma tecnologia que **pode ter vários remetentes, então:**

* As portas mach são de um receptor, **vários remetentes**.
* O token de auditoria de uma conexão XPC é o token de auditoria **copiado da mensagem mais recentemente recebida**.
* Obter o **token de auditoria** de uma conexão XPC é crítico para muitas **verificações de segurança**.

Embora a situação anterior pareça promissora, existem cenários em que isso não causará problemas ([daqui](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Os tokens de auditoria são frequentemente usados para uma verificação de autorização para decidir se aceitam uma conexão. Como isso acontece usando uma mensagem para a porta de serviço, **ainda não há conexão estabelecida**. Mais mensagens nesta porta serão tratadas como solicitações de conexão adicionais. Portanto, **verificações antes de aceitar uma conexão não são vulneráveis** (isso também significa que dentro de `-listener:shouldAcceptNewConnection:` o token de auditoria está seguro). Estamos, portanto, **procurando por conexões XPC que verifiquem ações específicas**.
* Os manipuladores de eventos XPC são tratados de forma síncrona. Isso significa que o manipulador de eventos para uma mensagem deve ser concluído antes de chamá-lo para a próxima, mesmo em filas de despacho concorrentes. Portanto, dentro de um **manipulador de eventos XPC, o token de auditoria não pode ser sobrescrito** por outras mensagens normais (não de resposta!).

Duas diferentes formas em que isso pode ser explorado:

1. Variante1:
* **Explorar** **conecta** ao serviço **A** e serviço **B**
* O serviço **B** pode chamar uma **funcionalidade privilegiada** no serviço A que o usuário não pode
* O serviço **A** chama **`xpc_connection_get_audit_token`** enquanto _**não**_ dentro do **manipulador de eventos** para uma conexão em um **`dispatch_async`**.
* Assim, uma **mensagem diferente** poderia **sobrescrever o Token de Auditoria** porque está sendo despachada de forma assíncrona fora do manipulador de eventos.
* O exploit passa para **serviço B o direito de ENVIO para o serviço A**.
* Então svc **B** estará realmente **enviando** as **mensagens** para o serviço **A**.
* O **exploit** tenta **chamar** a **ação privilegiada**. Em um RC svc **A** **verifica** a autorização desta **ação** enquanto **svc B sobrescreveu o Token de Auditoria** (dando ao exploit acesso para chamar a ação privilegiada).
2. Variante 2:
* O serviço **B** pode chamar uma **funcionalidade privilegiada** no serviço A que o usuário não pode
* O exploit se conecta com o **serviço A** que **envia** ao exploit uma **mensagem esperando uma resposta** em uma **porta de resposta** específica.
* O exploit envia ao **serviço** B uma mensagem passando **essa porta de resposta**.
* Quando o serviço **B responde**, ele **envia a mensagem para o serviço A**, **enquanto** o **exploit** envia uma **mensagem diferente para o serviço A** tentando **alcançar uma funcionalidade privilegiada** e esperando que a resposta do serviço B sobrescreva o Token de Auditoria no momento perfeito (Condição de Corrida).

## Variante 1: chamando xpc\_connection\_get\_audit\_token fora de um manipulador de eventos <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Cenário:

* Dois serviços mach **`A`** e **`B`** aos quais podemos nos conectar (com base no perfil de sandbox e nas verificações de autorização antes de aceitar a conexão).
* _**A**_ deve ter uma **verificação de autorização** para uma ação específica que **`B`** pode passar (mas nosso aplicativo não pode).
* Por exemplo, se B tiver algumas **prerrogativas** ou estiver sendo executado como **root**, ele pode permitir que ele peça a A para executar uma ação privilegiada.
* Para esta verificação de autorização, **`A`** obtém o token de auditoria de forma assíncrona, por exemplo, chamando `xpc_connection_get_audit_token` de **`dispatch_async`**.

{% hint style="danger" %}
Neste caso, um atacante poderia desencadear uma **Condição de Corrida** criando um **exploit** que **solicita que A execute uma ação** várias vezes enquanto faz **B enviar mensagens para `A`**. Quando a CC for **bem-sucedida**, o **token de auditoria** de **B** será copiado na memória **enquanto** a solicitação do nosso **exploit** está sendo **tratada** por A, dando-lhe **acesso à ação privilegiada que apenas B poderia solicitar**.
{% endhint %}

Isso aconteceu com **`A`** como `smd` e **`B`** como `diagnosticd`. A função [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) de smb pode ser usada para instalar uma nova ferramenta auxiliar privilegiada (como **root**). Se um **processo em execução como root** entrar em contato com **smd**, nenhuma outra verificação será realizada.

Portanto, o serviço **B** é **`diagnosticd`** porque é executado como **root** e pode ser usado para **monitorar** um processo, então, uma vez que a monitoração tenha começado, ele **enviará várias mensagens por segundo.**

Para realizar o ataque:

1. Inicie uma **conexão** com o serviço chamado `smd` usando o protocolo XPC padrão.
2. Forme uma **conexão secundária** com `diagnosticd`. Contrariamente ao procedimento normal, em vez de criar e enviar duas novas portas mach, o direito de envio da porta do cliente é substituído por uma duplicata do **direito de envio** associado à conexão `smd`.
3. Como resultado, as mensagens XPC podem ser despachadas para `diagnosticd`, mas as respostas de `diagnosticd` são redirecionadas para `smd`. Para `smd`, parece que as mensagens tanto do usuário quanto de `diagnosticd` estão originando da mesma conexão.

![Imagem representando o processo de exploit](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)
4. O próximo passo envolve instruir o `diagnosticd` a iniciar o monitoramento de um processo escolhido (potencialmente o do próprio usuário). Simultaneamente, uma inundação de mensagens rotineiras 1004 é enviada para o `smd`. A intenção aqui é instalar uma ferramenta com privilégios elevados.
5. Essa ação desencadeia uma condição de corrida dentro da função `handle_bless`. O timing é crítico: a chamada da função `xpc_connection_get_pid` deve retornar o PID do processo do usuário (já que a ferramenta privilegiada reside no pacote de aplicativos do usuário). No entanto, a função `xpc_connection_get_audit_token`, especificamente dentro da sub-rotina `connection_is_authorized`, deve fazer referência ao token de auditoria pertencente ao `diagnosticd`.

## Variante 2: encaminhamento de resposta

Em um ambiente XPC (Comunicação entre Processos), embora os manipuladores de eventos não sejam executados simultaneamente, o tratamento de mensagens de resposta possui um comportamento único. Especificamente, existem dois métodos distintos para enviar mensagens que esperam uma resposta:

1. **`xpc_connection_send_message_with_reply`**: Aqui, a mensagem XPC é recebida e processada em uma fila designada.
2. **`xpc_connection_send_message_with_reply_sync`**: Por outro lado, neste método, a mensagem XPC é recebida e processada na fila de despacho atual.

Essa distinção é crucial porque permite a possibilidade de **pacotes de resposta serem analisados simultaneamente com a execução de um manipulador de eventos XPC**. Notavelmente, embora o `_xpc_connection_set_creds` implemente bloqueio para proteger contra a sobrescrita parcial do token de auditoria, ele não estende essa proteção para o objeto de conexão inteiro. Consequentemente, isso cria uma vulnerabilidade onde o token de auditoria pode ser substituído durante o intervalo entre a análise de um pacote e a execução de seu manipulador de eventos.

Para explorar essa vulnerabilidade, a seguinte configuração é necessária:

* Dois serviços mach, referidos como **`A`** e **`B`**, ambos capazes de estabelecer uma conexão.
* O serviço **`A`** deve incluir uma verificação de autorização para uma ação específica que apenas **`B`** pode realizar (a aplicação do usuário não pode).
* O serviço **`A`** deve enviar uma mensagem que espera uma resposta.
* O usuário pode enviar uma mensagem para **`B`** que irá responder.

O processo de exploração envolve os seguintes passos:

1. Aguardar o serviço **`A`** enviar uma mensagem que espera uma resposta.
2. Em vez de responder diretamente para **`A`**, a porta de resposta é sequestrada e usada para enviar uma mensagem para o serviço **`B`**.
3. Posteriormente, uma mensagem envolvendo a ação proibida é despachada, com a expectativa de que seja processada simultaneamente com a resposta de **`B`**.

Abaixo está uma representação visual do cenário de ataque descrito:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemas de Descoberta

* **Dificuldades em Localizar Instâncias**: A busca por instâncias de uso do `xpc_connection_get_audit_token` foi desafiadora, tanto estaticamente quanto dinamicamente.
* **Metodologia**: Frida foi utilizada para enganchar a função `xpc_connection_get_audit_token`, filtrando chamadas que não se originam de manipuladores de eventos. No entanto, esse método estava limitado ao processo enganchado e exigia uso ativo.
* **Ferramentas de Análise**: Ferramentas como IDA/Ghidra foram usadas para examinar serviços mach alcançáveis, mas o processo foi demorado, complicado por chamadas envolvendo o cache compartilhado dyld.
* **Limitações de Scripting**: As tentativas de criar um script para a análise de chamadas para `xpc_connection_get_audit_token` a partir de blocos `dispatch_async` foram dificultadas por complexidades na análise de blocos e interações com o cache compartilhado dyld.

## A correção <a href="#the-fix" id="the-fix"></a>

* **Problemas Reportados**: Um relatório foi enviado à Apple detalhando os problemas gerais e específicos encontrados dentro do `smd`.
* **Resposta da Apple**: A Apple abordou o problema no `smd` substituindo `xpc_connection_get_audit_token` por `xpc_dictionary_get_audit_token`.
* **Natureza da Correção**: A função `xpc_dictionary_get_audit_token` é considerada segura, pois recupera o token de auditoria diretamente da mensagem mach vinculada à mensagem XPC recebida. No entanto, não faz parte da API pública, semelhante ao `xpc_connection_get_audit_token`.
* **Ausência de uma Correção Mais Abrangente**: Permanece incerto por que a Apple não implementou uma correção mais abrangente, como descartar mensagens que não se alinham com o token de auditoria salvo da conexão. A possibilidade de alterações legítimas no token de auditoria em certos cenários (por exemplo, uso de `setuid`) pode ser um fator.
* **Status Atual**: O problema persiste no iOS 17 e macOS 14, representando um desafio para aqueles que buscam identificá-lo e compreendê-lo.
