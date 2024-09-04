# Checklist - Local Windows Privilege Escalation

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

### **Найкращий інструмент для пошуку векторів підвищення привілеїв у Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [System Info](windows-local-privilege-escalation/#system-info)

* [ ] Отримати [**інформацію про систему**](windows-local-privilege-escalation/#system-info)
* [ ] Шукати **kernel** [**експлойти за допомогою скриптів**](windows-local-privilege-escalation/#version-exploits)
* [ ] Використовувати **Google для пошуку** експлойтів **ядра**
* [ ] Використовувати **searchsploit для пошуку** експлойтів **ядра**
* [ ] Цікава інформація в [**env vars**](windows-local-privilege-escalation/#environment)?
* [ ] Паролі в [**історії PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Цікава інформація в [**налаштуваннях Інтернету**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Диски**](windows-local-privilege-escalation/#drives)?
* [ ] [**WSUS експлойт**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Logging/AV enumeration](windows-local-privilege-escalation/#enumeration)

* [ ] Перевірити [**налаштування аудиту**](windows-local-privilege-escalation/#audit-settings) та [**WEF**](windows-local-privilege-escalation/#wef)
* [ ] Перевірити [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Перевірити, чи активний [**WDigest**](windows-local-privilege-escalation/#wdigest)
* [ ] [**LSA Protection**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Credentials Guard**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Кешовані облікові дані**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Перевірити, чи є якийсь [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
* [ ] [**Політика AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
* [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
* [ ] [**Привілеї користувачів**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Перевірити [**поточні** привілеї **користувача**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Чи є ви [**членом будь-якої привілейованої групи**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Перевірити, чи є у вас [будь-які з цих токенів, активованих](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Сесії користувачів**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Перевірити [**домашні папки користувачів**](windows-local-privilege-escalation/#home-folders) (доступ?)
* [ ] Перевірити [**Політику паролів**](windows-local-privilege-escalation/#password-policy)
* [ ] Що [**всередині буфера обміну**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Network](windows-local-privilege-escalation/#network)

* [ ] Перевірити **поточну** [**мережеву** **інформацію**](windows-local-privilege-escalation/#network)
* [ ] Перевірити **приховані локальні служби**, обмежені для зовнішнього доступу

### [Running Processes](windows-local-privilege-escalation/#running-processes)

* [ ] Бінарні файли процесів [**дозволи на файли та папки**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**Видобуток паролів з пам'яті**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**Небезпечні GUI додатки**](windows-local-privilege-escalation/#insecure-gui-apps)
* [ ] Вкрасти облікові дані з **цікавих процесів** за допомогою `ProcDump.exe` ? (firefox, chrome тощо ...)

### [Services](windows-local-privilege-escalation/#services)

* [ ] [Чи можете ви **модифікувати будь-яку службу**?](windows-local-privilege-escalation/#permissions)
* [ ] [Чи можете ви **модифікувати** **бінарний файл**, який **виконується** будь-якою **службою**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Чи можете ви **модифікувати** **реєстр** будь-якої **служби**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [Чи можете ви скористатися будь-яким **нецитованим шляхом** бінарного файлу **служби**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Applications**](windows-local-privilege-escalation/#applications)

* [ ] **Дозволи на запис** [**встановлені програми**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**Програми автозавантаження**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **Вразливі** [**драйвери**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Чи можете ви **записувати в будь-яку папку всередині PATH**?
* [ ] Чи є відомий бінарний файл служби, який **намагається завантажити будь-який неіснуючий DLL**?
* [ ] Чи можете ви **записувати** в будь-яку **папку з бінарними файлами**?

### [Network](windows-local-privilege-escalation/#network)

* [ ] Перерахувати мережу (спільні ресурси, інтерфейси, маршрути, сусіди тощо ...)
* [ ] Уважно перевірити мережеві служби, що слухають на localhost (127.0.0.1)

### [Windows Credentials](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)облікові дані
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) облікові дані, які ви могли б використовувати?
* [ ] Цікаві [**DPAPI облікові дані**](windows-local-privilege-escalation/#dpapi)?
* [ ] Паролі збережених [**Wifi мереж**](windows-local-privilege-escalation/#wifi)?
* [ ] Цікава інформація в [**збережених RDP з'єднаннях**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Паролі в [**недавніх командах**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] [**Менеджер облікових даних віддаленого робочого столу**](windows-local-privilege-escalation/#remote-desktop-credential-manager) паролі?
* [ ] [**AppCmd.exe** існує](windows-local-privilege-escalation/#appcmd-exe)? Облікові дані?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? Завантаження DLL з боку?

### [Files and Registry (Credentials)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Облікові дані**](windows-local-privilege-escalation/#putty-creds) **та** [**SSH ключі хоста**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**SSH ключі в реєстрі**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Паролі в [**непідконтрольних файлах**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Будь-яка [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups) резервна копія?
* [ ] [**Облікові дані хмари**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml) файл?
* [ ] [**Кешований GPP пароль**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Пароль у [**файлі конфігурації IIS Web**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Цікава інформація в [**веб** **логах**](windows-local-privilege-escalation/#logs)?
* [ ] Чи хочете ви [**попросити облікові дані**](windows-local-privilege-escalation/#ask-for-credentials) у користувача?
* [ ] Цікаві [**файли всередині Кошика**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Інші [**реєстри, що містять облікові дані**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Всередині [**даних браузера**](windows-local-privilege-escalation/#browsers-history) (бази даних, історія, закладки тощо)?
* [ ] [**Загальний пошук паролів**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) у файлах та реєстрі
* [ ] [**Інструменти**](windows-local-privilege-escalation/#tools-that-search-for-passwords) для автоматичного пошуку паролів

### [Leaked Handlers](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Чи маєте ви доступ до будь-якого обробника процесу, запущеного адміністратором?

### [Pipe Client Impersonation](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Перевірте, чи можете ви це зловживати

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
