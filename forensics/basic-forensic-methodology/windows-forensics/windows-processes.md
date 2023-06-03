## smss.exe

**Gestionnaire de session**.\
La session 0 lance **csrss.exe** et **wininit.exe** (**services** **OS**) tandis que la session 1 lance **csrss.exe** et **winlogon.exe** (**session** **utilisateur**). Cependant, vous ne devriez voir **qu'un seul processus** de cette **application** sans enfants dans l'arborescence des processus.

De plus, des sessions autres que 0 et 1 peuvent signifier que des sessions RDP sont en cours.


## csrss.exe

**Processus de sous-système d'exécution client/serveur**.\
Il gère les **processus** et les **threads**, rend l'API Windows disponible pour d'autres processus et **mappe les lettres de lecteur**, crée des **fichiers temporaires** et gère le **processus d'arrêt**.

Il y a un **processus en cours d'exécution dans la session 0 et un autre dans la session 1** (donc **2 processus** dans l'arborescence des processus). Un autre est créé **par nouvelle session**.


## winlogon.exe

**Processus de connexion Windows**.\
Il est responsable des **connexions/déconnexions** des utilisateurs. Il lance **logonui.exe** pour demander le nom d'utilisateur et le mot de passe, puis appelle **lsass.exe** pour les vérifier.

Ensuite, il lance **userinit.exe** qui est spécifié dans **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** avec la clé **Userinit**.

De plus, le registre précédent devrait avoir **explorer.exe** dans la clé **Shell** ou il pourrait être utilisé comme une **méthode de persistance de malware**.


## wininit.exe

**Processus d'initialisation Windows**. \
Il lance **services.exe**, **lsass.exe** et **lsm.exe** dans la session 0. Il ne devrait y avoir qu'un seul processus.


## userinit.exe

**Application de connexion Userinit**.\
Charge le **ntduser.dat dans HKCU** et initialise l'**environnement utilisateur** et exécute les **scripts de connexion** et les **GPO**.

Il lance **explorer.exe**.


## lsm.exe

**Gestionnaire de session local**.\
Il travaille avec smss.exe pour manipuler les sessions utilisateur : Connexion/Déconnexion, démarrage de la coquille, verrouillage/déverrouillage du bureau, etc.

Après W7, lsm.exe a été transformé en un service (lsm.dll).

Il ne devrait y avoir qu'un seul processus dans W7 et à partir de là, un service exécutant la DLL.


## services.exe

**Gestionnaire de contrôle de service**.\
Il **charge** les **services** configurés en **démarrage automatique** et les **pilotes**.

C'est le processus parent de **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** et bien d'autres.

Les services sont définis dans `HKLM\SYSTEM\CurrentControlSet\Services` et ce processus maintient une base de données en mémoire des informations de service qui peuvent être interrogées par sc.exe.

Notez comment **certains** **services** vont s'exécuter dans un **processus propre** et d'autres vont **partager un processus svchost.exe**.

Il ne devrait y avoir qu'un seul processus.


## lsass.exe

**Sous-système d'autorité de sécurité local**.\
Il est responsable de l'**authentification de l'utilisateur** et crée les **jetons de sécurité**. Il utilise des packages d'authentification situés dans `HKLM\System\CurrentControlSet\Control\Lsa`.

Il écrit dans le **journal d'événements de sécurité** et il ne devrait y avoir qu'un seul processus.

Gardez à l'esprit que ce processus est fortement attaqué pour extraire les mots de passe.


## svchost.exe

**Processus d'hôte de service générique**.\
Il héberge plusieurs services DLL dans un processus partagé.

Généralement, vous constaterez que **svchost.exe** est lancé avec le drapeau `-k`. Cela lancera une requête au registre **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost** où il y aura une clé avec l'argument mentionné dans -k qui contiendra les services à lancer dans le même processus.

Par exemple : `-k UnistackSvcGroup` lancera : `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Si le **drapeau `-s`** est également utilisé avec un argument, alors svchost est invité à **lancer uniquement le service spécifié** dans cet argument.

Il y aura plusieurs processus de `svchost.exe`. Si l'un d'entre eux **n'utilise pas le drapeau `-k`**, c'est très suspect. Si vous constatez que **services.exe n'est pas le parent**, c'est également très suspect.


## taskhost.exe

Ce processus agit comme un hôte pour les processus exécutés à partir de DLL. Il charge également les services qui s'exécutent à partir de DLL.

Dans W8, cela s'appelle taskhostex.exe et dans W10 taskhostw.exe.


## explorer.exe

C'est le processus responsable du **bureau de l'utilisateur** et du lancement de fichiers via les extensions de fichier.

**Seul 1** processus devrait être lancé **par utilisateur connecté.**

Cela est exécuté à partir de **userinit.exe** qui devrait être terminé, donc **aucun parent** ne devrait apparaître pour ce processus.


# Capture de processus malveillants

* Est-il en cours d'exécution à partir du chemin attendu ? (Aucune application Windows ne s'exécute à partir de l'emplacement temporaire)
* Communique-t-il avec des adresses IP étranges ?
* Vérifiez les signatures numériques (les artefacts Microsoft doivent être signés)
* Est-il orthographié correctement ?
* Fonctionne-t-il sous l'identifiant de sécurité attendu ?
* Le processus parent est-il celui attendu (s'il y en a un) ?
* Les processus enfants sont-ils ceux attendus ? (pas de cmd.exe, wscript.exe, powershell.exe..?)
