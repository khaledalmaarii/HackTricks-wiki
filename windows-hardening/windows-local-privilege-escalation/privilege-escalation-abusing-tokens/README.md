# Abusando de Tokens

<details>

<summary><strong>Aprenda hacking AWS do zero ao avançado com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Tokens

Se você **não sabe o que são Tokens de Acesso do Windows**, leia esta página antes de continuar:

{% content-ref url="../access-tokens.md" %}
[access-tokens.md](../access-tokens.md)
{% endcontent-ref %}

**Talvez você consiga elevar privilégios abusando dos tokens que já possui**

### SeImpersonatePrivilege

Este é um privilégio que é mantido por qualquer processo que permite a impersonação (mas não a criação) de qualquer token, desde que seja possível obter um identificador para ele. Um token privilegiado pode ser adquirido de um serviço do Windows (DCOM) induzindo-o a realizar autenticação NTLM contra um exploit, possibilitando posteriormente a execução de um processo com privilégios de SISTEMA. Essa vulnerabilidade pode ser explorada usando várias ferramentas, como [juicy-potato](https://github.com/ohpe/juicy-potato), [RogueWinRM](https://github.com/antonioCoco/RogueWinRM) (que requer que o winrm seja desativado), [SweetPotato](https://github.com/CCob/SweetPotato) e [PrintSpoofer](https://github.com/itm4n/PrintSpoofer).

{% content-ref url="../roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](../roguepotato-and-printspoofer.md)
{% endcontent-ref %}

{% content-ref url="../juicypotato.md" %}
[juicypotato.md](../juicypotato.md)
{% endcontent-ref %}

### SeAssignPrimaryPrivilege

É muito semelhante ao **SeImpersonatePrivilege**, ele usará o **mesmo método** para obter um token privilegiado.\
Então, este privilégio permite **atribuir um token primário** a um processo novo/suspenso. Com o token de impersonação privilegiado, você pode derivar um token primário (DuplicateTokenEx).\
Com o token, você pode criar um **novo processo** com 'CreateProcessAsUser' ou criar um processo suspenso e **definir o token** (em geral, não é possível modificar o token primário de um processo em execução).

### SeTcbPrivilege

Se você habilitou este token, pode usar **KERB\_S4U\_LOGON** para obter um **token de impersonação** para qualquer outro usuário sem conhecer as credenciais, **adicionar um grupo arbitrário** (administradores) ao token, definir o **nível de integridade** do token como "**médio**" e atribuir este token à **thread atual** (SetThreadToken).

### SeBackupPrivilege

O sistema é levado a **conceder acesso de leitura total** a qualquer arquivo (limitado a operações de leitura) por este privilégio. Ele é utilizado para **ler os hashes de senha das contas de Administrador local** do registro, após o que, ferramentas como "**psexec**" ou "**wmicexec**" podem ser usadas com o hash (técnica Pass-the-Hash). No entanto, essa técnica falha sob duas condições: quando a conta de Administrador Local está desativada ou quando uma política está em vigor que remove direitos administrativos de Administradores Locais conectando remotamente.\
Você pode **abusar deste privilégio** com:

* [https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1](https://github.com/Hackplayers/PsCabesha-tools/blob/master/Privesc/Acl-FullControl.ps1)
* [https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug](https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug)
* seguindo **IppSec** em [https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec](https://www.youtube.com/watch?v=IfCysW0Od8w\&t=2610\&ab\_channel=IppSec)
* Ou conforme explicado na seção **escalando privilégios com Operadores de Backup** em:

{% content-ref url="../../active-directory-methodology/privileged-groups-and-token-privileges.md" %}
[privileged-groups-and-token-privileges.md](../../active-directory-methodology/privileged-groups-and-token-privileges.md)
{% endcontent-ref %}

### SeRestorePrivilege

A permissão para **acesso de escrita** a qualquer arquivo do sistema, independentemente da Lista de Controle de Acesso (ACL) do arquivo, é fornecida por este privilégio. Isso abre inúmeras possibilidades para escalonamento, incluindo a capacidade de **modificar serviços**, realizar DLL Hijacking e definir **depuradores** via Opções de Execução de Arquivo de Imagem, entre várias outras técnicas.

### SeCreateTokenPrivilege

SeCreateTokenPrivilege é uma permissão poderosa, especialmente útil quando um usuário possui a capacidade de impersonar tokens, mas também na ausência de SeImpersonatePrivilege. Essa capacidade depende da capacidade de impersonar um token que represente o mesmo usuário e cujo nível de integridade não exceda o do processo atual.

**Pontos Chave:**
- **Impersonação sem SeImpersonatePrivilege:** É possível alavancar o SeCreateTokenPrivilege para EoP ao impersonar tokens sob condições específicas.
- **Condições para Impersonação de Token:** A impersonação bem-sucedida requer que o token de destino pertença ao mesmo usuário e tenha um nível de integridade menor ou igual ao nível de integridade do processo que tenta a impersonação.
- **Criação e Modificação de Tokens de Impersonação:** Os usuários podem criar um token de impersonação e aprimorá-lo adicionando o SID de um grupo privilegiado.

### SeLoadDriverPrivilege

Este privilégio permite **carregar e descarregar drivers de dispositivo** com a criação de uma entrada de registro com valores específicos para `ImagePath` e `Type`. Como o acesso de gravação direta ao `HKLM` (HKEY_LOCAL_MACHINE) é restrito, `HKCU` (HKEY_CURRENT_USER) deve ser utilizado. No entanto, para tornar o `HKCU` reconhecível pelo kernel para configuração de driver, um caminho específico deve ser seguido.

Este caminho é `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName`, onde `<RID>` é o Identificador Relativo do usuário atual. Dentro do `HKCU`, todo esse caminho deve ser criado, e dois valores precisam ser definidos:
- `ImagePath`, que é o caminho para o binário a ser executado
- `Type`, com um valor de `SERVICE_KERNEL_DRIVER` (`0x00000001`).

**Passos a Seguir:**
1. Acesse `HKCU` em vez de `HKLM` devido ao acesso de gravação restrito.
2. Crie o caminho `\Registry\User\<RID>\System\CurrentControlSet\Services\DriverName` dentro do `HKCU`, onde `<RID>` representa o Identificador Relativo do usuário atual.
3. Defina o `ImagePath` como o caminho de execução do binário.
4. Atribua o `Type` como `SERVICE_KERNEL_DRIVER` (`0x00000001`).
```python
# Example Python code to set the registry values
import winreg as reg

# Define the path and values
path = r'Software\YourPath\System\CurrentControlSet\Services\DriverName' # Adjust 'YourPath' as needed
key = reg.OpenKey(reg.HKEY_CURRENT_USER, path, 0, reg.KEY_WRITE)
reg.SetValueEx(key, "ImagePath", 0, reg.REG_SZ, "path_to_binary")
reg.SetValueEx(key, "Type", 0, reg.REG_DWORD, 0x00000001)
reg.CloseKey(key)
```
Mais maneiras de abusar desse privilégio em [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/privileged-accounts-and-token-privileges#seloaddriverprivilege)

### SeTakeOwnershipPrivilege

Isso é semelhante ao **SeRestorePrivilege**. Sua função principal permite que um processo **assuma a propriedade de um objeto**, contornando a necessidade de acesso discricionário explícito por meio da concessão de direitos de acesso WRITE_OWNER. O processo envolve primeiro garantir a propriedade da chave de registro pretendida para fins de escrita e, em seguida, alterar o DACL para permitir operações de escrita.
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
### SeDebugPrivilege

Este privilégio permite **depurar outros processos**, incluindo ler e escrever na memória. Várias estratégias de injeção de memória, capazes de evadir a maioria dos antivírus e soluções de prevenção de intrusões de host, podem ser empregadas com este privilégio.

#### Dump de memória

Você pode usar o [ProcDump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump) da [SysInternals Suite](https://docs.microsoft.com/en-us/sysinternals/downloads/sysinternals-suite) para **capturar a memória de um processo**. Especificamente, isso pode se aplicar ao processo **Local Security Authority Subsystem Service ([LSASS](https://en.wikipedia.org/wiki/Local_Security_Authority_Subsystem_Service))**, que é responsável por armazenar as credenciais do usuário uma vez que o usuário tenha feito login com sucesso em um sistema.

Você pode então carregar esse dump no mimikatz para obter senhas:
```
mimikatz.exe
mimikatz # log
mimikatz # sekurlsa::minidump lsass.dmp
mimikatz # sekurlsa::logonpasswords
```
#### RCE

Se você deseja obter um shell `NT SYSTEM`, você pode usar:

- ****[**SeDebugPrivilege-Exploit (C++)**](https://github.com/bruno-1337/SeDebugPrivilege-Exploit)****
- ****[**SeDebugPrivilegePoC (C#)**](https://github.com/daem0nc0re/PrivFu/tree/main/PrivilegedOperations/SeDebugPrivilegePoC)****
- ****[**psgetsys.ps1 (Powershell Script)**](https://raw.githubusercontent.com/decoder-it/psgetsystem/master/psgetsys.ps1)****
```powershell
# Get the PID of a process running as NT SYSTEM
import-module psgetsys.ps1; [MyProcess]::CreateProcessFromParent(<system_pid>,<command_to_execute>)
```
## Verificar privilégios
```
whoami /priv
```
Os **tokens que aparecem como Desativados** podem ser ativados, e na verdade você pode abusar dos tokens _Ativados_ e _Desativados_.

### Ativar Todos os tokens

Se você tiver tokens desativados, você pode usar o script [**EnableAllTokenPrivs.ps1**](https://raw.githubusercontent.com/fashionproof/EnableAllTokenPrivs/master/EnableAllTokenPrivs.ps1) para ativar todos os tokens:
```powershell
.\EnableAllTokenPrivs.ps1
whoami /priv
```
Ou o **script** incorporado neste [**post**](https://www.leeholmes.com/adjusting-token-privileges-in-powershell/).

## Tabela

Folha de dicas completa de privilégios de token em [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin), o resumo abaixo listará apenas maneiras diretas de explorar o privilégio para obter uma sessão de administrador ou ler arquivos sensíveis.

| Privilégio                  | Impacto      | Ferramenta                    | Caminho de execução                                                                                                                                                                                                                                                                                                                                     | Observações                                                                                                                                                                                                                                                                                                                        |
| -------------------------- | ----------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **`SeAssignPrimaryToken`** | _**Admin**_ | Ferramenta de terceiros          | _"Permitiria a um usuário se passar por tokens e elevar privilégios para o sistema nt usando ferramentas como potato.exe, rottenpotato.exe e juicypotato.exe"_                                                                                                                                                                                                      | Obrigado [Aurélien Chalot](https://twitter.com/Defte\_) pela atualização. Tentarei reformular para algo mais parecido com uma receita em breve.                                                                                                                                                                                        |
| **`SeBackup`**             | **Ameaça**  | _**Comandos integrados**_ | Ler arquivos sensíveis com `robocopy /b`                                                                                                                                                                                                                                                                                                             | <p>- Pode ser mais interessante se você puder ler %WINDIR%\MEMORY.DMP<br><br>- <code>SeBackupPrivilege</code> (e robocopy) não são úteis quando se trata de arquivos abertos.<br><br>- Robocopy requer tanto SeBackup quanto SeRestore para funcionar com o parâmetro /b.</p>                                                                      |
| **`SeCreateToken`**        | _**Admin**_ | Ferramenta de terceiros          | Criar token arbitrário incluindo direitos de administrador local com `NtCreateToken`.                                                                                                                                                                                                                                                                          |                                                                                                                                                                                                                                                                                                                                |
| **`SeDebug`**              | _**Admin**_ | **PowerShell**          | Duplicar o token `lsass.exe`.                                                                                                                                                                                                                                                                                                                   | Script disponível em [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                                                                                         |
| **`SeLoadDriver`**         | _**Admin**_ | Ferramenta de terceiros          | <p>1. Carregar um driver de kernel com falha como <code>szkg64.sys</code><br>2. Explorar a vulnerabilidade do driver<br><br>Alternativamente, o privilégio pode ser usado para descarregar drivers relacionados à segurança com o comando integrado <code>ftlMC</code>. ou seja: <code>fltMC sysmondrv</code></p>                                                                           | <p>1. A vulnerabilidade do <code>szkg64</code> está listada como <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732">CVE-2018-15732</a><br>2. O código de exploração do <code>szkg64</code> foi criado por <a href="https://twitter.com/parvezghh">Parvez Anwar</a></p> |
| **`SeRestore`**            | _**Admin**_ | **PowerShell**          | <p>1. Iniciar o PowerShell/ISE com o privilégio SeRestore presente.<br>2. Habilitar o privilégio com <a href="https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1">Enable-SeRestorePrivilege</a>).<br>3. Renomear utilman.exe para utilman.old<br>4. Renomear cmd.exe para utilman.exe<br>5. Bloquear o console e pressionar Win+U</p> | <p>O ataque pode ser detectado por alguns softwares de AV.</p><p>O método alternativo depende da substituição de binários de serviço armazenados em "Arquivos de Programas" usando o mesmo privilégio</p>                                                                                                                                                            |
| **`SeTakeOwnership`**      | _**Admin**_ | _**Comandos integrados**_ | <p>1. <code>takeown.exe /f "%windir%\system32"</code><br>2. <code>icalcs.exe "%windir%\system32" /grant "%username%":F</code><br>3. Renomear cmd.exe para utilman.exe<br>4. Bloquear o console e pressionar Win+U</p>                                                                                                                                       | <p>O ataque pode ser detectado por alguns softwares de AV.</p><p>O método alternativo depende da substituição de binários de serviço armazenados em "Arquivos de Programas" usando o mesmo privilégio.</p>                                                                                                                                                           |
| **`SeTcb`**                | _**Admin**_ | Ferramenta de terceiros          | <p>Manipular tokens para incluir direitos de administrador local. Pode exigir SeImpersonate.</p><p>Para ser verificado.</p>                                                                                                                                                                                                                                     |                                                                                                                                                                                                                                                                                                                                |

## Referência

* Consulte esta tabela definindo tokens do Windows: [https://github.com/gtworek/Priv2Admin](https://github.com/gtworek/Priv2Admin)
* Consulte [**este artigo**](https://github.com/hatRiot/token-priv/blob/master/abusing\_token\_eop\_1.0.txt) sobre elevação de privilégios com tokens.

<details>

<summary><strong>Aprenda hacking AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Você trabalha em uma **empresa de cibersegurança**? Gostaria de ver sua **empresa anunciada no HackTricks**? ou gostaria de ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o [repositório hacktricks](https://github.com/carlospolop/hacktricks) e [repositório hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
