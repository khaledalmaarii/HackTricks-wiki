# Problème du double saut Kerberos

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (Expert en équipe rouge AWS de HackTricks)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Vous voulez voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**La famille PEASS**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Introduction

Le problème du "double saut" Kerberos survient lorsqu'un attaquant tente d'utiliser **l'authentification Kerberos à travers deux** **sauts**, par exemple en utilisant **PowerShell**/**WinRM**.

Lorsqu'une **authentification** se produit via **Kerberos**, les **informations d'identification** ne sont pas mises en cache en **mémoire**. Par conséquent, si vous exécutez mimikatz, vous ne trouverez pas les informations d'identification de l'utilisateur sur la machine même s'il exécute des processus.

Cela est dû au fait que lors de la connexion avec Kerberos, les étapes suivantes sont suivies :

1. L'utilisateur1 fournit des informations d'identification et le **contrôleur de domaine** renvoie un **TGT** Kerberos à l'utilisateur1.
2. L'utilisateur1 utilise le **TGT** pour demander un **ticket de service** pour se **connecter** au Serveur1.
3. L'utilisateur1 se **connecte** au **Serveur1** et fournit le **ticket de service**.
4. Le **Serveur1** n'a pas les **informations d'identification** de l'utilisateur1 en cache ni le **TGT** de l'utilisateur1. Par conséquent, lorsque l'utilisateur1 du Serveur1 essaie de se connecter à un deuxième serveur, il **n'est pas en mesure de s'authentifier**.

### Délégation non contrainte

Si la **délégation non contrainte** est activée sur le PC, cela ne se produira pas car le **Serveur** obtiendra un **TGT** de chaque utilisateur y accédant. De plus, si la délégation non contrainte est utilisée, vous pouvez probablement **compromettre le contrôleur de domaine** à partir de là.\
[**Plus d'informations sur la page de la délégation non contrainte**](unconstrained-delegation.md).

### CredSSP

Une autre façon d'éviter ce problème, qui est [**notablement peu sécurisée**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7), est le **Fournisseur de prise en charge de la sécurité des informations d'identification**. Selon Microsoft :

> L'authentification CredSSP délègue les informations d'identification de l'utilisateur de l'ordinateur local à un ordinateur distant. Cette pratique augmente le risque de sécurité de l'opération à distance. Si l'ordinateur distant est compromis, lorsque les informations d'identification lui sont transmises, les informations d'identification peuvent être utilisées pour contrôler la session réseau.

Il est fortement recommandé de désactiver **CredSSP** sur les systèmes de production, les réseaux sensibles et des environnements similaires en raison de problèmes de sécurité. Pour déterminer si **CredSSP** est activé, la commande `Get-WSManCredSSP` peut être exécutée. Cette commande permet de **vérifier l'état de CredSSP** et peut même être exécutée à distance, à condition que **WinRM** soit activé.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Solutions

### Commande Invoke

Pour résoudre le problème du double saut, une méthode impliquant une `Invoke-Command` imbriquée est présentée. Cela ne résout pas le problème directement mais offre une solution de contournement sans avoir besoin de configurations spéciales. Cette approche permet d'exécuter une commande (`hostname`) sur un serveur secondaire via une commande PowerShell exécutée à partir d'une machine d'attaque initiale ou via une session PS précédemment établie avec le premier serveur. Voici comment procéder :
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
### Enregistrement de la configuration de la session PSSession

Une solution pour contourner le problème du double saut implique d'utiliser `Register-PSSessionConfiguration` avec `Enter-PSSession`. Cette méthode nécessite une approche différente de celle d'`evil-winrm` et permet une session qui ne souffre pas de la limitation du double saut.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Pour les administrateurs locaux sur une cible intermédiaire, le port forwarding permet d'envoyer des requêtes à un serveur final. En utilisant `netsh`, une règle peut être ajoutée pour le port forwarding, ainsi qu'une règle de pare-feu Windows pour autoriser le port redirigé.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` peut être utilisé pour transmettre des requêtes WinRM, potentiellement comme une option moins détectable si la surveillance de PowerShell est une préoccupation. La commande ci-dessous démontre son utilisation:
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

L'installation d'OpenSSH sur le premier serveur permet de contourner le problème du double saut, particulièrement utile pour les scénarios de boîte de saut. Cette méthode nécessite l'installation en ligne de commande et la configuration d'OpenSSH pour Windows. Lorsqu'il est configuré pour l'authentification par mot de passe, cela permet au serveur intermédiaire d'obtenir un TGT au nom de l'utilisateur.

#### Étapes d'installation d'OpenSSH

1. Téléchargez et déplacez le dernier fichier zip de la version d'OpenSSH sur le serveur cible.
2. Décompressez et exécutez le script `Install-sshd.ps1`.
3. Ajoutez une règle de pare-feu pour ouvrir le port 22 et vérifiez que les services SSH sont en cours d'exécution.

Pour résoudre les erreurs de `réinitialisation de connexion`, les autorisations peuvent nécessiter une mise à jour pour permettre à tout le monde de lire et d'exécuter l'accès au répertoire OpenSSH.
```bash
icacls.exe "C:\Users\redsuit\Documents\ssh\OpenSSH-Win64" /grant Everyone:RX /T
```
## Références

* [https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20](https://techcommunity.microsoft.com/t5/ask-the-directory-services-team/understanding-kerberos-double-hop/ba-p/395463?lightbox-message-images-395463=102145i720503211E78AC20)
* [https://posts.slayerlabs.com/double-hop/](https://posts.slayerlabs.com/double-hop/)
* [https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting](https://learn.microsoft.com/en-gb/archive/blogs/sergey\_babkins\_blog/another-solution-to-multi-hop-powershell-remoting)
* [https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/](https://4sysops.com/archives/solve-the-powershell-multi-hop-problem-without-using-credssp/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

<details>

<summary><strong>Apprenez le piratage AWS de zéro à héros avec</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Travaillez-vous dans une **entreprise de cybersécurité**? Voulez-vous voir votre **entreprise annoncée dans HackTricks**? ou voulez-vous avoir accès à la **dernière version du PEASS ou télécharger HackTricks en PDF**? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**dépôt hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**dépôt hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
