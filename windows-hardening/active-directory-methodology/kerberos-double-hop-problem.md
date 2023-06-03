# Problème de double saut Kerberos

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

## Introduction

Le problème de "double saut" Kerberos apparaît lorsqu'un attaquant tente d'utiliser l'authentification **Kerberos** sur deux **sauts**, par exemple en utilisant **PowerShell**/**WinRM**.

Lorsqu'une **authentification** se produit via **Kerberos**, les **informations d'identification** ne sont pas mises en cache en mémoire. Par conséquent, si vous exécutez mimikatz, vous ne trouverez pas les informations d'identification de l'utilisateur sur la machine, même s'il exécute des processus.

Cela est dû au fait que lors de la connexion avec Kerberos, les étapes suivantes sont suivies :

1. L'utilisateur 1 fournit des informations d'identification et le **contrôleur de domaine** renvoie un **TGT** Kerberos à l'utilisateur 1.
2. L'utilisateur 1 utilise le **TGT** pour demander un **ticket de service** pour se connecter au serveur 1.
3. L'utilisateur 1 se connecte au serveur 1 et fournit le **ticket de service**.
4. Le **serveur 1** n'a pas les **informations d'identification** de l'utilisateur 1 mises en cache ou le **TGT** de l'utilisateur 1. Par conséquent, lorsque l'utilisateur 1 du serveur 1 essaie de se connecter à un deuxième serveur, il n'est pas en mesure de s'authentifier.

### Délégation non contrainte

Si la **délégation non contrainte** est activée sur le PC, cela ne se produira pas car le **serveur** recevra un **TGT** de chaque utilisateur y accédant. De plus, si la délégation non contrainte est utilisée, vous pouvez probablement **compromettre le contrôleur de domaine** à partir de celle-ci.\
[**Plus d'informations sur la page de délégation non contrainte**](unconstrained-delegation.md).

### CredSSP

Une autre option suggérée aux **administrateurs système** pour éviter ce problème, qui est [**notoirement peu sûre**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), est le **Credential Security Support Provider**. Activer CredSSP a été une solution mentionnée sur divers forums au fil des ans. Selon Microsoft :

_"L'authentification CredSSP délègue les informations d'identification de l'utilisateur de l'ordinateur local à un ordinateur distant. Cette pratique augmente le risque de sécurité de l'opération à distance. Si l'ordinateur distant est compromis, lorsque les informations d'identification lui sont transmises, les informations d'identification peuvent être utilisées pour contrôler la session réseau."_

Si vous trouvez que **CredSSP est activé** sur des systèmes de production, des réseaux sensibles, etc., il est recommandé de les désactiver. Un moyen rapide de **vérifier l'état de CredSSP** est d'exécuter `Get-WSManCredSSP`. Ce qui peut être exécuté à distance si WinRM est activé.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
    Get-WSManCredSSP
}
```
## Solutions de contournement

### Commande Invoke <a href="#invoke-command" id="invoke-command"></a>

Cette méthode consiste à travailler avec le problème de double saut, sans nécessairement le résoudre. Elle ne dépend d'aucune configuration et vous pouvez simplement l'exécuter depuis votre machine d'attaque. C'est essentiellement une **commande `Invoke-Command`** imbriquée.

Cela exécutera **`hostname`** sur le **deuxième serveur :**
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
    Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Vous pouvez également établir une **session PowerShell** avec le **premier serveur** et simplement **exécuter** la commande **`Invoke-Command`** avec `$cred` à partir de là au lieu de la mettre en cascade. Cependant, l'exécuter depuis votre boîte d'attaque centralise les tâches :
```powershell
# From the WinRM connection
$pwd = ConvertTo-SecureString 'uiefgyvef$/E3' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)
# Use "-Credential $cred" option in Powerview commands
```
### Enregistrer la configuration de la session PSSession

Si au lieu d'utiliser **`evil-winrm`**, vous pouvez utiliser la commande **`Enter-PSSession`**, vous pouvez ensuite utiliser **`Register-PSSessionConfiguration`** et vous reconnecter pour contourner le problème de double saut :
```powershell
# Register a new PS Session configuration
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
# Restar WinRM
Restart-Service WinRM
# Get a PSSession
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
# Check that in this case the TGT was sent and is in memory of the PSSession
klist
# In this session you won't have the double hop problem anymore
```
### PortForwarding <a href="#portproxy" id="portproxy"></a>

Étant donné que nous avons un accès administrateur local sur la cible intermédiaire **bizintel: 10.35.8.17**, vous pouvez ajouter une règle de redirection de port pour envoyer vos demandes au serveur final/troisième **secdev: 10.35.8.23**.

Vous pouvez rapidement utiliser **netsh** pour extraire une commande en une ligne et ajouter la règle.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
```
Le **premier serveur** écoute sur le port 5446 et transfère les demandes arrivant sur le port 5446 vers le **deuxième serveur** sur le port 5985 (alias WinRM).

Ensuite, ouvrez un trou dans le pare-feu Windows, ce qui peut également être fait avec une commande netsh rapide.
```bash
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
Maintenant, établissons la session, qui nous transférera vers **le premier serveur**.

<figure><img src="../../.gitbook/assets/image (3) (5) (1).png" alt=""><figcaption></figcaption></figure>

#### winrs.exe <a href="#winrsexe" id="winrsexe"></a>

Il semble également que la redirection de port WinRM fonctionne lorsque l'on utilise **`winrs.exe`**. Cela peut être une meilleure option si vous savez que PowerShell est surveillé. La commande ci-dessous renvoie "secdev" en tant que résultat de `hostname`.
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
Comme `Invoke-Command`, cela peut être facilement scripté pour que l'attaquant puisse simplement émettre des commandes système en tant qu'argument. Un exemple de script batch générique _winrm.bat_ :

<figure><img src="../../.gitbook/assets/image (2) (6) (2).png" alt=""><figcaption></figcaption></figure>

### OpenSSH <a href="#openssh" id="openssh"></a>

Cette méthode nécessite l'installation d'OpenSSH sur la première boîte serveur. L'installation d'OpenSSH pour Windows peut être effectuée **complètement via CLI** et ne prend pas beaucoup de temps - en plus, cela ne signale pas de logiciel malveillant !

Bien sûr, dans certaines circonstances, cela peut ne pas être faisable, trop encombrant ou peut être un risque général pour l'OpSec.

Cette méthode peut être particulièrement utile dans une configuration de boîte de saut - avec accès à un réseau autrement inaccessible. Une fois que la connexion SSH est établie, l'utilisateur/attaquant peut lancer autant de `New-PSSession` qu'il le souhaite contre le réseau segmenté sans exploser dans le problème de double saut.

Lorsqu'il est configuré pour utiliser l'**authentification par mot de passe** dans OpenSSH (pas de clés ou de Kerberos), le **type de connexion est 8** alias _connexion en clair réseau_. Cela ne signifie pas que votre mot de passe est envoyé en clair - il est en fait chiffré par SSH. À l'arrivée, il est déchiffré en texte clair via son [paquet d'authentification](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera?redirectedfrom=MSDN) pour que votre session puisse demander des TGT juteux !

Cela permet au serveur intermédiaire de demander et d'obtenir un TGT en votre nom pour le stocker localement sur le serveur intermédiaire. Votre session peut ensuite utiliser ce TGT pour s'authentifier (PS remote) auprès de serveurs supplémentaires.

#### Scénario d'installation OpenSSH

Téléchargez la dernière version de [OpenSSH Release zip depuis github](https://github.com/PowerShell/Win32-OpenSSH/releases) sur votre machine d'attaque et déplacez-la (ou téléchargez-la directement sur la boîte de saut).

Décompressez le zip où vous le souhaitez. Ensuite, exécutez le script d'installation - `Install-sshd.ps1`

<figure><img src="../../.gitbook/assets/image (2) (1) (3).png" alt=""><figcaption></figcaption></figure>

Enfin, ajoutez simplement une règle de pare-feu pour **ouvrir le port 22**. Vérifiez que les services SSH sont installés et démarrez-les. Ces deux services devront être en cours d'exécution pour que SSH fonctionne.

<figure><img src="../../.gitbook/assets/image (1) (7).png" alt=""><figcaption></figcaption></figure>

Si vous recevez une erreur `Connection reset`, mettez à jour les autorisations pour permettre à **Everyone: Lire et exécuter** sur le répertoire racine OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Références

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
