# Abusando de Tokens

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> - <a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) **grupo Discord** ou ao **grupo telegram** ou **siga-me** no **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Tokens

Se você **não sabe o que são Tokens de Acesso do Windows**, leia esta página antes de continuar:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Talvez você consiga elevar privilégios abusando dos tokens que você já possui**

### SeImpersonatePrivilege (3.1.1)

Qualquer processo que possua esse privilégio pode **fazer uma impersonação** (mas não criar) de qualquer **token** para o qual ele consiga obter um handle. Você pode obter um **token privilegiado** de um **serviço do Windows** (DCOM) fazendo-o realizar uma **autenticação NTLM** contra o exploit, e então executar um processo como **SYSTEM**. Exploração com [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM)(necessita winrm desativado), [SweetPotato](https://github.com/CCob/SweetPotato), [PrintSpoofer](https://github.com/itm4n/PrintSpoofer):

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege (3.1.2)

É muito semelhante ao **SeImpersonatePrivilege**, ele usará o **mesmo método** para obter um token privilegiado.\
Então, esse privilégio permite **atribuir um token primário** a um processo novo/suspenso. Com o token de impersonação privilegiado, você pode derivar um token primário (DuplicateTokenEx).\
Com o token, você pode criar um **novo processo** com 'CreateProcessAsUser' ou criar um processo suspenso e **definir o token** (em geral, você não pode modificar o token primário de um processo em execução).

### SeTcbPrivilege (3.1.3)

Se você habilitou este token, pode usar **KERB\_S4U\_LOGON** para obter um **token de impersonação** para qualquer outro usuário sem saber as credenciais, **adicionar um grupo arbitrário** (administradores) ao token, definir o **nível de integridade** do token como "**médio**", e atribuir este token à **thread atual** (SetThreadToken).

### SeBackupPrivilege (3.1.4)

Este privilégio faz com que o sistema conceda todo o acesso de leitura a qualquer arquivo (somente leitura).\
Use-o para **ler os hashes de senha das contas de Administrador local** do registro e então use "**psexec**" ou "**wmicexec**" com o hash (PTH).\
Este ataque não funcionará se o Administrador Local estiver desativado, ou se estiver configurado que um Admin Local não é admin se estiver conectado remotamente.\
Você pode **abusar deste privilégio** com:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* seguindo **IppSec** em [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Ou conforme explicado na seção **escalando privilégios com Operadores de Backup** de:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege (3.1.5)

Controle de **escrita** em qualquer arquivo no sistema, independentemente da ACL dos arquivos.\
Você pode **modificar serviços**, DLL Hijacking, definir **debugger** (Image File Execution Options)... Muitas opções para elevar privilégios.

### SeCreateTokenPrivilege (3.1.6)

Este token **pode ser usado** como método de EoP **apenas** se o usuário **puder impersonar** tokens (mesmo sem SeImpersonatePrivilege).\
Em um cenário possível, um usuário pode impersonar o token se for para o mesmo usuário e o nível de integridade for menor ou igual ao nível de integridade do processo atual.\
Neste caso, o usuário poderia **criar um token de impersonação** e adicionar a ele um SID de grupo privilegiado.

### SeLoadDriverPrivilege (3.1.7)

**Carregar e descarregar drivers de dispositivo.**\
Você precisa criar uma entrada no registro com valores para ImagePath e Type.\
Como você não tem acesso para escrever em HKLM, você tem que **usar HKCU**. Mas HKCU não significa nada para o kernel, a maneira de guiar o kernel aqui e usar o caminho esperado para uma configuração de driver é usar o caminho: "\Registry\User\S-1-5-21-582075628-3447520101-2530640108-1003\System\CurrentControlSet\Services\DriverName" (o ID é o **RID** do usuário atual).\
Então, você tem que **criar todo esse caminho dentro de HKCU e definir o ImagePath** (caminho para o binário que será executado) **e o Type** (SERVICE\_KERNEL\_DRIVER 0x00000001).\

{% content-ref url="abuse-seloaddriverprivilege.md" %}
[abuse-seloaddriverprivilege.md](abuse-seloaddriverprivilege.md)
{% endcontent-ref %}

### SeTakeOwnershipPrivilege (3.1.8)

Este privilégio é muito semelhante ao **SeRestorePrivilege**.\
Ele permite a um processo “**tomar posse de um objeto** sem ser concedido acesso discricionário” concedendo o direito de acesso WRITE\_OWNER.\
Primeiro, você tem que **tomar posse da chave do registro** na qual você vai escrever e **modificar o DACL** para que você possa escrever nela.
```bash
takeown /f 'C:\some\file.txt' #Now the file is owned by you
icacls 'C:\some\file.txt' /grant <your_username>:F #Now you have full access
# Use this with files that might contain credentials such as
%WINDIR%\repair\sam
%WINDIR%\repair\system
%WINDIR%\repair\software
%WINDIR%\repair\security
%WINDIR%\system32\config\security.sav
%WINDIR%\system32\config\software.sav
%WINDIR%\system32\config\system.sav
%WINDIR%\system32\config\SecEvent.Evt
%WINDIR%\system32\config\default.sav
c:\inetpub\wwwwroot\web.config
```
### SeDebugPrivilege (3.1.9)

Permite ao detentor **depurar outro processo**, o que inclui ler e **escrever** na memória desse **processo**.\
Existem várias estratégias de **injeção de memória** que podem ser usadas com esse privilégio para evitar a maioria das soluções AV/HIPS.

#### Dump de memória

Um exemplo de **abuso desse privilégio** é executar o [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) do [SysInternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **dump de memória de um processo**. Por exemplo, o processo **Local Security Authority Subsystem Service (**[**LSASS**](https://en.wikipedia.org/wiki/Local\_Security\_Authority\_Subsystem\_Service)**)**, que armazena credenciais de usuário após o login de um usuário em um sistema.

Você pode então carregar esse dump no mimikatz para obter senhas:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Se você deseja obter um shell `NT SYSTEM`, você pode usar:

- ****[**SeDebugPrivilegePoC**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
- ****[**psgetsys.ps1**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Verificar privilégios
```
whoami /priv
```
Os **tokens que aparecem como Desativados** podem ser ativados, e na verdade você pode abusar dos tokens _Ativados_ e _Desativados_.

### Ativar todos os tokens

Você pode usar o script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para ativar todos os tokens:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
O **script** incorporado neste [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Folha de dicas completa de privilégios de token em [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), o resumo abaixo listará apenas maneiras diretas de explorar o privilégio para obter uma sessão de administrador ou ler arquivos sensíveis.\\

| Privilégio                 | Impacto     | Ferramenta               | Caminho de execução                                                                                                                                                                                                                                                                                                                               | Observações                                                                                                                                                                                                                                                                                                                   |
| -------------------------- | ----------- | -----------------------   | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Ferramenta de terceiros   | _"Permitiria a um usuário se passar por tokens e elevar privilégios para o sistema nt usando ferramentas como potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                      | Obrigado [Aurélien Chalot](https://twitter.com/Defte\_) pela atualização. Tentarei reformular para algo mais parecido com uma receita em breve.                                                                                                                                                                                |
| **`SeBackup`**             | **Ameaça**  | _**Comandos integrados**_ | Ler arquivos sensíveis com `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Pode ser mais interessante se você puder ler %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (e robocopy) não são úteis quando se trata de arquivos abertos.<br><br>- Robocopy requer tanto SeBackup quanto SeRestore para funcionar com o parâmetro /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Ferramenta de terceiros   | Criar token arbitrário incluindo direitos de administrador local com `NtCreateToken`.                                                                                                                                                                                                                                                              |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**            | Duplicar o token `lsass.exe`.                                                                                                                                                                                                                                                                                                                     | Script disponível em [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Ferramenta de terceiros   | <p>1. Carregar um driver de kernel com falha como <code>szkg64.sys</code><br>2. Explorar a vulnerabilidade do driver<br><br>Alternativamente, o privilégio pode ser usado para descarregar drivers relacionados à segurança com o comando integrado <code>ftlMC</code>. por exemplo: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. A vulnerabilidade do <code>szkg64</code> está listada como <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. O código de exploração do <code>szkg64</code> foi criado por <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**            | <p>1. Iniciar o PowerShell/ISE com o privilégio SeRestore presente.<br>2. Habilitar o privilégio com <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renomear utilman.exe para utilman.old<br>4. Renomear cmd.exe para utilman.exe<br>5. Bloquear o console e pressionar Win+U</p> | <p>O ataque pode ser detectado por alguns softwares antivírus.</p><p>O método alternativo depende da substituição de binários de serviço armazenados em "Arquivos de Programas" usando o mesmo privilégio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Comandos integrados**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renomear cmd.exe para utilman.exe<br>4. Bloquear o console e pressionar Win+U</p>                                                                                                                                       | <p>O ataque pode ser detectado por alguns softwares antivírus.</p><p>O método alternativo depende da substituição de binários de serviço armazenados em "Arquivos de Programas" usando o mesmo privilégio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Ferramenta de terceiros   | <p>Manipular tokens para incluir direitos de administrador local. Pode exigir SeImpersonate.</p><p>A ser verificado.</p>                                                                                                                                                                                                                         |                                                                                                                                                                                                                                                                                                                                |

## Referência

* Consulte esta tabela definindo tokens do Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Consulte [**este artigo**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) sobre elevação de privilégios com tokens.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** **🐦**[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
