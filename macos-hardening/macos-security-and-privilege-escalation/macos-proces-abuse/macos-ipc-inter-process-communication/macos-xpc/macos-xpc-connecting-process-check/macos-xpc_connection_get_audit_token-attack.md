# Ataque xpc_connection_get_audit_token no macOS

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de segurança cibernética**? Gostaria de ver sua **empresa anunciada no HackTricks**? Ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**The PEASS Family**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

**Esta técnica foi copiada de** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)

## Informações básicas sobre Mach Messages

Se você não sabe o que são Mach Messages, comece verificando esta página:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Por enquanto, lembre-se de que:\
As Mach Messages são enviadas por meio de uma _porta Mach_, que é um canal de comunicação de **receptor único, remetentes múltiplos** incorporado no kernel Mach. **Múltiplos processos podem enviar mensagens** para uma porta Mach, mas em qualquer momento **apenas um processo pode lê-la**. Assim como descritores de arquivo e soquetes, as portas Mach são alocadas e gerenciadas pelo kernel, e os processos veem apenas um número inteiro, que podem usar para indicar ao kernel qual de suas portas Mach desejam usar.

## Conexão XPC

Se você não sabe como uma conexão XPC é estabelecida, verifique:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Resumo da vulnerabilidade

O que é interessante saber é que a **abstração do XPC é uma conexão um para um**, mas é baseada em uma tecnologia que **pode ter remetentes múltiplos, então:**

* As portas Mach são de receptor único, _**remetentes múltiplos**_.
* O token de auditoria de uma conexão XPC é o token de auditoria _**copiado da mensagem mais recentemente recebida**_.
* Obter o **token de auditoria** de uma conexão XPC é fundamental para muitas **verificações de segurança**.

Embora a situação anterior pareça promissora, existem alguns cenários em que isso não causará problemas:

* Os tokens de auditoria são frequentemente usados para uma verificação de autorização para decidir se aceitam uma conexão. Como isso acontece usando uma mensagem para a porta de serviço, **ainda não há conexão estabelecida**. Mais mensagens nesta porta serão tratadas como solicitações de conexão adicionais. Portanto, **as verificações antes de aceitar uma conexão não são vulneráveis** (isso também significa que dentro de `-listener:shouldAcceptNewConnection:` o token de auditoria está seguro). Portanto, estamos **procurando por conexões XPC que verifiquem ações específicas**.
* Os manipuladores de eventos XPC são tratados de forma síncrona. Isso significa que o manipulador de eventos para uma mensagem deve ser concluído antes de chamá-lo para a próxima, mesmo em filas de despacho simultâneas. Portanto, dentro de um **manipulador de eventos XPC, o token de auditoria não pode ser sobrescrito** por outras mensagens normais (não de resposta!).

Isso nos deu a ideia de dois métodos diferentes em que isso pode ser possível:

1. Variante 1:
* O **exploit** se **conecta** ao serviço **A** e ao serviço **B**.
* O serviço **B** pode chamar uma **funcionalidade privilegiada** no serviço A que o usuário não pode.
* O serviço **A** chama **`xpc_connection_get_audit_token`** enquanto _**não**_ estiver dentro do manipulador de eventos para uma conexão em um **`dispatch_async`**.
* Portanto, uma **mensagem diferente** pode **sobrescrever o Token de Auditoria** porque está sendo despachada de forma assíncrona fora do manipulador de eventos.
* O exploit passa para o **serviço B o direito de ENVIO para o serviço A**.
* Portanto, o svc **B** estará realmente **enviando** as **mensagens** para o serviço **A**.
* O **exploit** tenta **chamar** a **ação privilegiada**. Em um svc RC, **A verifica** a autorização dessa **ação** enquanto **svc B sobrescreveu o Token de Auditoria** (dando ao exploit acesso para chamar a ação privilegiada).
2. Variante 2:
* O serviço **B** pode chamar uma **funcionalidade privilegiada** no serviço A que o usuário não pode.
* O exploit se conecta ao **serviço A**, que **envia** ao exploit uma **mensagem esperando uma resposta** em uma **porta de resposta** específica.
* O exploit envia ao **serviço B** uma mensagem passando **essa porta de resposta**.
* Quando o serviço **B responde**, ele **envia a mensagem para o serviço A**, **enquanto** o **exploit** envia uma **mensagem diferente para o serviço A** tentando **alcançar uma funcionalidade privilegiada** e esperando que a resposta do serviço B sobrescreva o Token de Auditoria no momento perfeito (Condição de Corrida).
## Variante 1: chamando xpc\_connection\_get\_audit\_token fora de um manipulador de eventos <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Cenário:

* Dois serviços mach **A** e **B** aos quais podemos nos conectar (com base no perfil de sandbox e nas verificações de autorização antes de aceitar a conexão).
* **A** deve ter uma **verificação de autorização** para uma **ação específica** que **B** pode passar (mas nosso aplicativo não pode).
* Por exemplo, se B tiver algumas **entitlements** ou estiver sendo executado como **root**, ele poderá permitir que ele peça a A para executar uma ação privilegiada.
* Para essa verificação de autorização, **A obtém o token de auditoria de forma assíncrona**, por exemplo, chamando `xpc_connection_get_audit_token` de **`dispatch_async`**.

{% hint style="danger" %}
Nesse caso, um atacante poderia desencadear uma **Condição de Corrida** criando um **exploit** que **solicita que A execute uma ação** várias vezes enquanto **B envia mensagens para A**. Quando a CC é **bem-sucedida**, o **token de auditoria** de **B** será copiado na memória **enquanto** a solicitação de nosso **exploit** está sendo **tratada** por A, dando a ele **acesso à ação privilegiada que apenas B poderia solicitar**.
{% endhint %}

Isso aconteceu com **A** como `smd` e **B** como `diagnosticd`. A função [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) do smb pode ser usada para instalar uma nova ferramenta auxiliar privilegiada (como **root**). Se um **processo em execução como root** entrar em contato com **smd**, nenhuma outra verificação será realizada.

Portanto, o serviço **B** é **`diagnosticd`** porque ele é executado como **root** e pode ser usado para **monitorar** um processo, então, uma vez que a monitoração é iniciada, ele **enviará várias mensagens por segundo**.

Para realizar o ataque:

1. Estabelecemos nossa **conexão** com **`smd`** seguindo o protocolo XPC normal.
2. Em seguida, estabelecemos uma **conexão** com **`diagnosticd`**, mas em vez de gerar duas novas portas mach e enviá-las, substituímos o direito de envio da porta do cliente por uma cópia do **direito de envio que temos para a conexão com `smd`**.
3. Isso significa que podemos enviar mensagens XPC para `diagnosticd`, mas qualquer **mensagem que `diagnosticd` envie vai para `smd`**.
* Para `smd`, tanto nossas mensagens quanto as mensagens de `diagnosticd` chegam na mesma conexão.

<figure><img src="../../../../../../.gitbook/assets/image.png" alt="" width="563"><figcaption></figcaption></figure>

4. Pedimos a **`diagnosticd`** para **iniciar a monitoração** de nosso (ou qualquer outro) processo e **enviamos mensagens de rotina 1004 para `smd`** (para instalar uma ferramenta privilegiada).
5. Isso cria uma condição de corrida que precisa atingir uma janela muito específica em `handle_bless`. Precisamos que a chamada para `xpc_connection_get_pid` retorne o PID de nosso próprio processo, pois a ferramenta auxiliar privilegiada está no pacote do nosso aplicativo. No entanto, a chamada para `xpc_connection_get_audit_token` dentro da função `connection_is_authorized` deve usar o token de auditoria de `diagnosticd`.

## Variante 2: encaminhamento de resposta

Como mencionado anteriormente, o manipulador de eventos para uma conexão XPC nunca é executado várias vezes simultaneamente. No entanto, as mensagens de **resposta XPC são tratadas de forma diferente**. Existem duas funções para enviar uma mensagem que espera uma resposta:

* `void xpc_connection_send_message_with_reply(xpc_connection_t connection, xpc_object_t message, dispatch_queue_t replyq, xpc_handler_t handler)`, nesse caso, a mensagem XPC é recebida e analisada na fila especificada.
* `xpc_object_t xpc_connection_send_message_with_reply_sync(xpc_connection_t connection, xpc_object_t message)`, nesse caso, a mensagem XPC é recebida e analisada na fila de despacho atual.

Portanto, **pacotes de resposta XPC podem ser analisados enquanto um manipulador de eventos XPC está sendo executado**. Embora `_xpc_connection_set_creds` use bloqueio, isso apenas impede a substituição parcial do token de auditoria, não bloqueia o objeto de conexão inteiro, tornando possível **substituir o token de auditoria entre a análise** de um pacote e a execução de seu manipulador de eventos.

Para esse cenário, precisaríamos de:

* Como antes, dois serviços mach _A_ e _B_ aos quais podemos nos conectar.
* Novamente, _A_ deve ter uma verificação de autorização para uma ação específica que _B_ pode passar (mas nosso aplicativo não pode).
* _A_ nos envia uma mensagem que espera uma resposta.
* Podemos enviar uma mensagem para _B_ que ele responderá.

Aguardamos _A_ nos enviar uma mensagem que espera uma resposta (1), em vez de responder, pegamos a porta de resposta e a usamos para uma mensagem que enviamos para _B_ (2). Em seguida, enviamos uma mensagem que usa a ação proibida e esperamos que ela chegue simultaneamente com a resposta de _B_ (3).

<figure><img src="../../../../../../.gitbook/assets/image (1).png" alt="" width="563"><figcaption></figcaption></figure>

## Problemas de Descoberta

Passamos muito tempo tentando encontrar outras instâncias, mas as condições dificultaram a busca tanto estática quanto dinamicamente. Para procurar chamadas assíncronas para `xpc_connection_get_audit_token`, usamos o Frida para fazer hook nessa função e verificar se o backtrace inclui `_xpc_connection_mach_event` (o que significa que não é chamado de um manipulador de eventos). Mas isso só encontra chamadas no processo que estamos conectados atualmente e nas ações que estão sendo usadas ativamente. Analisar todos os serviços mach alcançáveis no IDA/Ghidra foi muito demorado, especialmente quando as chamadas envolviam o cache compartilhado do dyld. Tentamos criar um script para procurar chamadas para `xpc_connection_get_audit_token` alcançáveis a partir de um bloco enviado usando `dispatch_async`, mas analisar blocos e chamadas passando pelo cache compartilhado do dyld tornou isso difícil também. Depois de gastar um tempo com isso, decidimos que seria melhor enviar o que tínhamos.
## A solução <a href="#a-solução" id="a-solução"></a>

No final, relatamos o problema geral e o problema específico no `smd`. A Apple corrigiu apenas no `smd`, substituindo a chamada para `xpc_connection_get_audit_token` por `xpc_dictionary_get_audit_token`.

A função `xpc_dictionary_get_audit_token` copia o token de auditoria da mensagem mach na qual essa mensagem XPC foi recebida, o que significa que não é vulnerável. No entanto, assim como `xpc_dictionary_get_audit_token`, isso não faz parte da API pública. Para a API `NSXPCConnection` de nível superior, não existe um método claro para obter o token de auditoria da mensagem atual, pois isso abstrai todas as mensagens em chamadas de método.

Não está claro por que a Apple não aplicou uma correção mais geral, por exemplo, descartando mensagens que não correspondem ao token de auditoria salvo da conexão. Pode haver cenários em que o token de auditoria de um processo muda legitimamente, mas a conexão deve permanecer aberta (por exemplo, chamando `setuid` altera o campo UID), mas mudanças como um PID diferente ou versão do PID são improváveis de serem intencionais.

De qualquer forma, esse problema ainda persiste no iOS 17 e macOS 14, então se você quiser procurá-lo, boa sorte!

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e para o** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
