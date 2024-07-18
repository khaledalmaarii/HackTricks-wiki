{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}


## smss.exe

**Gestionnaire de session**.\
La session 0 démarre **csrss.exe** et **wininit.exe** (**services du système d'exploitation**) tandis que la session 1 démarre **csrss.exe** et **winlogon.exe** (**session utilisateur**). Cependant, vous ne devriez voir **qu'un seul processus** de ce **binaire** sans enfants dans l'arborescence des processus.

De plus, des sessions autres que 0 et 1 peuvent indiquer que des sessions RDP sont en cours.


## csrss.exe

**Processus de sous-système d'exécution client/serveur**.\
Il gère les **processus** et les **threads**, rend l'**API Windows** disponible pour d'autres processus et **mappe les lettres de lecteur**, crée des **fichiers temporaires** et gère le **processus d'arrêt**.

Il y en a un **en cours d'exécution dans la session 0 et un autre dans la session 1** (donc **2 processus** dans l'arborescence des processus). Un autre est créé **par nouvelle session**.


## winlogon.exe

**Processus de connexion Windows**.\
Il est responsable des **connexions**/**déconnexions** des utilisateurs. Il lance **logonui.exe** pour demander un nom d'utilisateur et un mot de passe, puis appelle **lsass.exe** pour les vérifier.

Ensuite, il lance **userinit.exe** qui est spécifié dans **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** avec la clé **Userinit**.

De plus, le registre précédent devrait avoir **explorer.exe** dans la clé **Shell** ou il pourrait être utilisé comme une **méthode de persistance de logiciel malveillant**.


## wininit.exe

**Processus d'initialisation Windows**. \
Il lance **services.exe**, **lsass.exe** et **lsm.exe** dans la session 0. Il ne devrait y avoir qu'un seul processus.


## userinit.exe

**Application de connexion Userinit**.\
Charge le **ntduser.dat dans HKCU** et initialise l'**environnement utilisateur** et exécute des **scripts de connexion** et des **GPO**.

Il lance **explorer.exe**.


## lsm.exe

**Gestionnaire de session local**.\
Il travaille avec smss.exe pour manipuler les sessions utilisateur : Connexion/déconnexion, démarrage du shell, verrouillage/déverrouillage du bureau, etc.

Après W7, lsm.exe a été transformé en un service (lsm.dll).

Il ne devrait y avoir qu'un seul processus dans W7 et parmi eux un service exécutant le DLL.


## services.exe

**Gestionnaire de contrôle des services**.\
Il **charge** les **services** configurés en **démarrage automatique** et les **pilotes**.

C'est le processus parent de **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** et bien d'autres.

Les services sont définis dans `HKLM\SYSTEM\CurrentControlSet\Services` et ce processus maintient une base de données en mémoire des informations sur les services qui peuvent être interrogées par sc.exe.

Notez comment **certains** **services** vont s'exécuter dans un **processus dédié** et d'autres vont **partager un processus svchost.exe**.

Il ne devrait y avoir qu'un seul processus.


## lsass.exe

**Sous-système d'autorité de sécurité local**.\
Il est responsable de l'**authentification des utilisateurs** et crée les **jetons de sécurité**. Il utilise des packages d'authentification situés dans `HKLM\System\CurrentControlSet\Control\Lsa`.

Il écrit dans le **journal des événements de sécurité** et il ne devrait y avoir qu'un seul processus.

Gardez à l'esprit que ce processus est fortement attaqué pour extraire des mots de passe.


## svchost.exe

**Processus hôte de service générique**.\
Il héberge plusieurs services DLL dans un processus partagé.

Généralement, vous constaterez que **svchost.exe** est lancé avec le drapeau `-k`. Cela lancera une requête au registre **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** où il y aura une clé avec l'argument mentionné en -k qui contiendra les services à lancer dans le même processus.

Par exemple : `-k UnistackSvcGroup` lancera : `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Si le **drapeau `-s`** est également utilisé avec un argument, alors svchost est invité à **lancer uniquement le service spécifié** dans cet argument.

Il y aura plusieurs processus de `svchost.exe`. Si l'un d'eux n'utilise **pas le drapeau `-k`**, c'est très suspect. Si vous constatez que **services.exe n'est pas le parent**, c'est également très suspect.


## taskhost.exe

Ce processus agit comme un hôte pour les processus s'exécutant à partir de DLL. Il charge également les services qui s'exécutent à partir de DLL.

Dans W8, cela s'appelle taskhostex.exe et dans W10 taskhostw.exe.


## explorer.exe

Ce processus est responsable du **bureau de l'utilisateur** et du lancement de fichiers via les extensions de fichiers.

**Seul 1** processus devrait être créé **par utilisateur connecté.**

Cela est exécuté à partir de **userinit.exe** qui devrait être terminé, donc **aucun parent** ne devrait apparaître pour ce processus.


# Détection des processus malveillants

* Est-il exécuté à partir du chemin attendu ? (Aucun binaire Windows ne s'exécute à partir de l'emplacement temporaire)
* Communique-t-il avec des adresses IP suspectes ?
* Vérifiez les signatures numériques (les artefacts Microsoft devraient être signés)
* Est-il orthographié correctement ?
* S'exécute-t-il sous l'identifiant de sécurité attendu ?
* Le processus parent est-il celui attendu (le cas échéant) ?
* Les processus enfants sont-ils ceux attendus ? (pas de cmd.exe, wscript.exe, powershell.exe..?)


{% hint style="success" %}
Apprenez et pratiquez le piratage AWS :<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**Formation HackTricks AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Apprenez et pratiquez le piratage GCP : <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**Formation HackTricks GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Soutenez HackTricks</summary>

* Consultez les [**plans d'abonnement**](https://github.com/sponsors/carlospolop)!
* **Rejoignez le** 💬 [**groupe Discord**](https://discord.gg/hRep4RUj7f) ou le [**groupe Telegram**](https://t.me/peass) ou **suivez-nous** sur **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Partagez des astuces de piratage en soumettant des PR aux** [**HackTricks**](https://github.com/carlospolop/hacktricks) et [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) dépôts GitHub.

</details>
{% endhint %}
