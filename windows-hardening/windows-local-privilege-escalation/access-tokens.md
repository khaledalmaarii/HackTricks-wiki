# Tokens de Acesso

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo do Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo do telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Tokens de Acesso

Cada **usuário logado** no sistema **possui um token de acesso com informações de segurança** para aquela sessão de logon. O sistema cria um token de acesso quando o usuário faz o login. **Cada processo executado** em nome do usuário **possui uma cópia do token de acesso**. O token identifica o usuário, os grupos do usuário e os privilégios do usuário. Um token também contém um SID de logon (Identificador de Segurança) que identifica a sessão de logon atual.

Você pode ver essas informações executando `whoami /all`
```
whoami /all

USER INFORMATION
----------------

User Name             SID
===================== ============================================
desktop-rgfrdxl\cpolo S-1-5-21-3359511372-53430657-2078432294-1001


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID                                                                                                           Attributes
============================================================= ================ ============================================================================================================= ==================================================
Mandatory Label\Medium Mandatory Level                        Label            S-1-16-8192
Everyone                                                      Well-known group S-1-1-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114                                                                                                     Group used for deny only
BUILTIN\Administrators                                        Alias            S-1-5-32-544                                                                                                  Group used for deny only
BUILTIN\Users                                                 Alias            S-1-5-32-545                                                                                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users                                 Alias            S-1-5-32-559                                                                                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE                                      Well-known group S-1-5-4                                                                                                       Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                                                 Well-known group S-1-2-1                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11                                                                                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                                Well-known group S-1-5-15                                                                                                      Mandatory group, Enabled by default, Enabled group
MicrosoftAccount\cpolop@outlook.com                           User             S-1-11-96-3623454863-58364-18864-2661722203-1597581903-3158937479-2778085403-3651782251-2842230462-2314292098 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account                                    Well-known group S-1-5-113                                                                                                     Mandatory group, Enabled by default, Enabled group
LOCAL                                                         Well-known group S-1-2-0                                                                                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Cloud Account Authentication                     Well-known group S-1-5-64-36                                                                                                   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled
```
### Administrador local

Quando um administrador local faz login, **dois tokens de acesso são criados**: Um com direitos de administrador e outro com direitos normais. **Por padrão**, quando esse usuário executa um processo, o com **direitos regulares** (não administrador) **é utilizado**. Quando esse usuário tenta **executar** algo **como administrador** ("Executar como Administrador", por exemplo), o **UAC** será usado para solicitar permissão.\
Se você quiser [**saber mais sobre o UAC, leia esta página**](../authentication-credentials-uac-and-efs.md#uac)**.**

### Impersonação de usuário de credenciais

Se você tiver **credenciais válidas de qualquer outro usuário**, você pode **criar** uma **nova sessão de logon** com essas credenciais:
```
runas /user:domain\username cmd.exe
```
O **token de acesso** também possui uma **referência** das sessões de logon dentro do **LSASS**, isso é útil se o processo precisa acessar alguns objetos da rede.\
Você pode iniciar um processo que **usa credenciais diferentes para acessar serviços de rede** usando:
```
runas /user:domain\username /netonly cmd.exe
```
Isso é útil se você tiver credenciais úteis para acessar objetos na rede, mas essas credenciais não são válidas dentro do host atual, pois serão usadas apenas na rede (no host atual, os privilégios do seu usuário atual serão usados).

### Tipos de tokens

Existem dois tipos de tokens disponíveis:

* **Token Primário**: Serve como uma representação das credenciais de segurança de um processo. A criação e associação de tokens primários com processos são ações que requerem privilégios elevados, enfatizando o princípio da separação de privilégios. Tipicamente, um serviço de autenticação é responsável pela criação do token, enquanto um serviço de logon lida com sua associação com o shell do sistema operacional do usuário. Vale ressaltar que os processos herdam o token primário de seu processo pai na criação.

* **Token de Impersonação**: Capacita uma aplicação de servidor a adotar temporariamente a identidade do cliente para acessar objetos seguros. Esse mecanismo é estratificado em quatro níveis de operação:
- **Anônimo**: Concede acesso ao servidor semelhante ao de um usuário não identificado.
- **Identificação**: Permite que o servidor verifique a identidade do cliente sem utilizá-la para acesso a objetos.
- **Impersonação**: Permite que o servidor opere sob a identidade do cliente.
- **Delegação**: Semelhante à Impersonação, mas inclui a capacidade de estender essa suposição de identidade a sistemas remotos com os quais o servidor interage, garantindo a preservação das credenciais.

#### Impersonate Tokens

Usando o módulo _**incognito**_ do metasploit, se você tiver privilégios suficientes, pode facilmente **listar** e **impersonate** outros **tokens**. Isso pode ser útil para realizar **ações como se você fosse o outro usuário**. Você também pode **escalar privilégios** com essa técnica.

### Privilégios do Token

Saiba quais **privilégios do token podem ser abusados para escalar privilégios:**

{% content-ref url="privilege-escalation-abusing-tokens/" %}
[privilege-escalation-abusing-tokens](privilege-escalation-abusing-tokens/)
{% endcontent-ref %}

Dê uma olhada em [**todos os possíveis privilégios do token e algumas definições nesta página externa**](https://github.com/gtworek/Priv2Admin).

## Referências

Saiba mais sobre tokens nestes tutoriais: [https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa](https://medium.com/@seemant.bisht24/understanding-and-abusing-process-tokens-part-i-ee51671f2cfa) e [https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962](https://medium.com/@seemant.bisht24/understanding-and-abusing-access-tokens-part-ii-b9069f432962)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
