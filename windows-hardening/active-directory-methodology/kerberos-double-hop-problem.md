# Problème de Double Hop Kerberos

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR au** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos GitHub.

</details>
{% endhint %}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}


## Introduction

Le problème de "Double Hop" Kerberos apparaît lorsqu'un attaquant tente d'utiliser **l'authentification Kerberos à travers deux** **hops**, par exemple en utilisant **PowerShell**/**WinRM**.

Lorsqu'une **authentification** se produit via **Kerberos**, les **identifiants** **ne sont pas** mis en cache dans **la mémoire.** Par conséquent, si vous exécutez mimikatz, vous **ne trouverez pas les identifiants** de l'utilisateur sur la machine même s'il exécute des processus.

Ceci est dû au fait que lors de la connexion avec Kerberos, voici les étapes :

1. L'utilisateur1 fournit des identifiants et le **contrôleur de domaine** renvoie un **TGT** Kerberos à l'utilisateur1.
2. L'utilisateur1 utilise le **TGT** pour demander un **ticket de service** pour **se connecter** à Server1.
3. L'utilisateur1 **se connecte** à **Server1** et fournit le **ticket de service**.
4. **Server1** **n'a pas** les **identifiants** de l'utilisateur1 mis en cache ni le **TGT** de l'utilisateur1. Par conséquent, lorsque l'utilisateur1 de Server1 essaie de se connecter à un deuxième serveur, il **n'est pas en mesure de s'authentifier**.

### Délégation non contrainte

Si la **délégation non contrainte** est activée sur le PC, cela ne se produira pas car le **Serveur** obtiendra un **TGT** de chaque utilisateur y accédant. De plus, si la délégation non contrainte est utilisée, vous pouvez probablement **compromettre le contrôleur de domaine** à partir de cela.\
[**Plus d'infos sur la page de délégation non contrainte**](unconstrained-delegation.md).

### CredSSP

Une autre façon d'éviter ce problème qui est [**notablement peu sécurisé**](https://docs.microsoft.com/en-us/powershell/module/microsoft.wsman.management/enable-wsmancredssp?view=powershell-7) est le **Credential Security Support Provider**. De Microsoft :

> L'authentification CredSSP délègue les identifiants de l'utilisateur de l'ordinateur local à un ordinateur distant. Cette pratique augmente le risque de sécurité de l'opération distante. Si l'ordinateur distant est compromis, lorsque les identifiants lui sont transmis, les identifiants peuvent être utilisés pour contrôler la session réseau.

Il est fortement recommandé que **CredSSP** soit désactivé sur les systèmes de production, les réseaux sensibles et des environnements similaires en raison de préoccupations de sécurité. Pour déterminer si **CredSSP** est activé, la commande `Get-WSManCredSSP` peut être exécutée. Cette commande permet de **vérifier l'état de CredSSP** et peut même être exécutée à distance, à condition que **WinRM** soit activé.
```powershell
Invoke-Command -ComputerName bizintel -Credential ta\redsuit -ScriptBlock {
Get-WSManCredSSP
}
```
## Solutions de contournement

### Invoke Command

Pour résoudre le problème du double saut, une méthode impliquant un `Invoke-Command` imbriqué est présentée. Cela ne résout pas le problème directement mais offre une solution de contournement sans nécessiter de configurations spéciales. L'approche permet d'exécuter une commande (`hostname`) sur un serveur secondaire via une commande PowerShell exécutée depuis une machine d'attaque initiale ou à travers une PS-Session précédemment établie avec le premier serveur. Voici comment cela se fait :
```powershell
$cred = Get-Credential ta\redsuit
Invoke-Command -ComputerName bizintel -Credential $cred -ScriptBlock {
Invoke-Command -ComputerName secdev -Credential $cred -ScriptBlock {hostname}
}
```
Alternativement, établir une PS-Session avec le premier serveur et exécuter la `Invoke-Command` en utilisant `$cred` est suggéré pour centraliser les tâches.

### Enregistrer la configuration de PSSession

Une solution pour contourner le problème du double saut implique d'utiliser `Register-PSSessionConfiguration` avec `Enter-PSSession`. Cette méthode nécessite une approche différente de `evil-winrm` et permet une session qui ne souffre pas de la limitation du double saut.
```powershell
Register-PSSessionConfiguration -Name doublehopsess -RunAsCredential domain_name\username
Restart-Service WinRM
Enter-PSSession -ConfigurationName doublehopsess -ComputerName <pc_name> -Credential domain_name\username
klist
```
### PortForwarding

Pour les administrateurs locaux sur une cible intermédiaire, le port forwarding permet d'envoyer des requêtes à un serveur final. En utilisant `netsh`, une règle peut être ajoutée pour le port forwarding, ainsi qu'une règle de pare-feu Windows pour autoriser le port transféré.
```bash
netsh interface portproxy add v4tov4 listenport=5446 listenaddress=10.35.8.17 connectport=5985 connectaddress=10.35.8.23
netsh advfirewall firewall add rule name=fwd dir=in action=allow protocol=TCP localport=5446
```
#### winrs.exe

`winrs.exe` peut être utilisé pour transférer des requêtes WinRM, potentiellement comme une option moins détectable si la surveillance de PowerShell est une préoccupation. La commande ci-dessous démontre son utilisation :
```bash
winrs -r:http://bizintel:5446 -u:ta\redsuit -p:2600leet hostname
```
### OpenSSH

L'installation d'OpenSSH sur le premier serveur permet de contourner le problème de double-hop, particulièrement utile pour les scénarios de jump box. Cette méthode nécessite l'installation et la configuration d'OpenSSH pour Windows via CLI. Lorsqu'il est configuré pour l'authentification par mot de passe, cela permet au serveur intermédiaire d'obtenir un TGT au nom de l'utilisateur.

#### Étapes d'installation d'OpenSSH

1. Téléchargez et déplacez le dernier fichier zip de la version d'OpenSSH sur le serveur cible.
2. Décompressez et exécutez le script `Install-sshd.ps1`.
3. Ajoutez une règle de pare-feu pour ouvrir le port 22 et vérifiez que les services SSH fonctionnent.

Pour résoudre les erreurs `Connection reset`, les autorisations peuvent devoir être mises à jour pour permettre à tout le monde un accès en lecture et en exécution sur le répertoire OpenSSH.
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

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenir HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PRs aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts github.

</details>
{% endhint %}
