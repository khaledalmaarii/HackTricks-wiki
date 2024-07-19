# Writable Sys Path +Dll Hijacking Privesc

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

## Introduction

Si vous avez découvert que vous pouvez **écrire dans un dossier de chemin système** (notez que cela ne fonctionnera pas si vous pouvez écrire dans un dossier de chemin utilisateur), il est possible que vous puissiez **escalader les privilèges** dans le système.

Pour ce faire, vous pouvez abuser d'un **Dll Hijacking** où vous allez **détourner une bibliothèque chargée** par un service ou un processus avec **plus de privilèges** que vous, et parce que ce service charge une Dll qui ne existe probablement même pas dans tout le système, il va essayer de la charger depuis le chemin système où vous pouvez écrire.

Pour plus d'informations sur **ce qu'est le Dll Hijacking**, consultez :

{% content-ref url="./" %}
[.](./)
{% endcontent-ref %}

## Privesc avec Dll Hijacking

### Trouver une Dll manquante

La première chose dont vous avez besoin est d'**identifier un processus** s'exécutant avec **plus de privilèges** que vous qui essaie de **charger une Dll depuis le chemin système** dans lequel vous pouvez écrire.

Le problème dans ces cas est que ces processus sont probablement déjà en cours d'exécution. Pour trouver quelles Dlls manquent aux services, vous devez lancer procmon dès que possible (avant que les processus ne soient chargés). Donc, pour trouver les .dll manquantes, faites :

* **Créez** le dossier `C:\privesc_hijacking` et ajoutez le chemin `C:\privesc_hijacking` à la **variable d'environnement de chemin système**. Vous pouvez le faire **manuellement** ou avec **PS** :
```powershell
# Set the folder path to create and check events for
$folderPath = "C:\privesc_hijacking"

# Create the folder if it does not exist
if (!(Test-Path $folderPath -PathType Container)) {
New-Item -ItemType Directory -Path $folderPath | Out-Null
}

# Set the folder path in the System environment variable PATH
$envPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
if ($envPath -notlike "*$folderPath*") {
$newPath = "$envPath;$folderPath"
[Environment]::SetEnvironmentVariable("PATH", $newPath, "Machine")
}
```
* Lancez **`procmon`** et allez dans **`Options`** --> **`Enable boot logging`** et appuyez sur **`OK`** dans l'invite.
* Ensuite, **redémarrez**. Lorsque l'ordinateur redémarre, **`procmon`** commencera à **enregistrer** les événements dès que possible.
* Une fois que **Windows** est **démarré, exécutez `procmon`** à nouveau, il vous dira qu'il a été en cours d'exécution et vous **demandera si vous souhaitez stocker** les événements dans un fichier. Dites **oui** et **stockez les événements dans un fichier**.
* **Après** que le **fichier** soit **généré**, **fermez** la fenêtre **`procmon`** ouverte et **ouvrez le fichier des événements**.
* Ajoutez ces **filtres** et vous trouverez tous les Dlls que certains **processus ont essayé de charger** depuis le dossier System Path écrivable :

<figure><img src="../../../.gitbook/assets/image (945).png" alt=""><figcaption></figcaption></figure>

### Dlls manquantes

En exécutant cela sur une **machine Windows 11 virtuelle (vmware)** gratuite, j'ai obtenu ces résultats :

<figure><img src="../../../.gitbook/assets/image (607).png" alt=""><figcaption></figcaption></figure>

Dans ce cas, les .exe sont inutiles, donc ignorez-les, les DLL manquantes provenaient de :

| Service                         | Dll                | Ligne de commande                                                    |
| ------------------------------- | ------------------ | ------------------------------------------------------------------ |
| Planificateur de tâches (Schedule)       | WptsExtensions.dll | `C:\Windows\system32\svchost.exe -k netsvcs -p -s Schedule`          |
| Service de politique de diagnostic (DPS) | Unknown.DLL        | `C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p -s DPS` |
| ???                             | SharedRes.dll      | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup`              |

Après avoir trouvé cela, j'ai trouvé cet article de blog intéressant qui explique également comment [**abuser de WptsExtensions.dll pour l'élévation de privilèges**](https://juggernaut-sec.com/dll-hijacking/#Windows\_10\_Phantom\_DLL\_Hijacking\_-\_WptsExtensionsdll). Ce que nous **allons faire maintenant**.

### Exploitation

Donc, pour **élever les privilèges**, nous allons détourner la bibliothèque **WptsExtensions.dll**. Ayant le **chemin** et le **nom**, nous devons juste **générer la dll malveillante**.

Vous pouvez [**essayer d'utiliser l'un de ces exemples**](./#creating-and-compiling-dlls). Vous pourriez exécuter des charges utiles telles que : obtenir un shell inversé, ajouter un utilisateur, exécuter un beacon...

{% hint style="warning" %}
Notez que **tous les services ne sont pas exécutés** avec **`NT AUTHORITY\SYSTEM`**, certains sont également exécutés avec **`NT AUTHORITY\LOCAL SERVICE`**, qui a **moins de privilèges** et vous **ne pourrez pas créer un nouvel utilisateur** en abusant de ses permissions.\
Cependant, cet utilisateur a le privilège **`seImpersonate`**, donc vous pouvez utiliser la [**suite potato pour élever les privilèges**](../roguepotato-and-printspoofer.md). Donc, dans ce cas, un shell inversé est une meilleure option que d'essayer de créer un utilisateur.
{% endhint %}

Au moment de l'écriture, le service **Planificateur de tâches** est exécuté avec **Nt AUTHORITY\SYSTEM**.

Ayant **généré la dll malveillante** (_dans mon cas, j'ai utilisé un shell inversé x64 et j'ai obtenu un shell, mais Defender l'a tué parce qu'il provenait de msfvenom_), enregistrez-la dans le chemin système écrivable sous le nom **WptsExtensions.dll** et **redémarrez** l'ordinateur (ou redémarrez le service ou faites ce qu'il faut pour relancer le service/programme affecté).

Lorsque le service est redémarré, la **dll devrait être chargée et exécutée** (vous pouvez **réutiliser** le truc **procmon** pour vérifier si la **bibliothèque a été chargée comme prévu**).

{% hint style="success" %}
Apprenez et pratiquez le hacking AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le hacking GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Supportez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop) !
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous sur** **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de hacking en soumettant des PR au** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
