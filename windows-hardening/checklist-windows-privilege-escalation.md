# Checklist - Local Windows Privilege Escalation

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану на HackTricks** або **завантажити HackTricks у PDF-форматі**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи телеграм**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилайте PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) **та** [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) **репозиторіїв на GitHub**.

</details>

**Try Hard Security Group**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

### **Найкращий інструмент для пошуку векторів локального підвищення привілеїв в Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Інформація про систему](windows-local-privilege-escalation/#system-info)

* [ ] Отримати [**інформацію про систему**](windows-local-privilege-escalation/#system-info)
* [ ] Шукати **експлойти ядра** [**за допомогою скриптів**](windows-local-privilege-escalation/#version-exploits)
* [ ] Використовувати **Google для пошуку** експлойтів ядра
* [ ] Використовувати **searchsploit для пошуку** експлойтів ядра
* [ ] Цікава інформація в [**змінних середовища**](windows-local-privilege-escalation/#environment)?
* [ ] Паролі в [**історії PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Цікава інформація в [**налаштуваннях Інтернету**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Диски**](windows-local-privilege-escalation/#drives)?
* [ ] [**Експлойт WSUS**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Перелік/перелік AV](windows-local-privilege-escalation/#enumeration)

* [ ] Перевірити [**налаштування Audit** ](windows-local-privilege-escalation/#audit-settings)та [**WEF**](windows-local-privilege-escalation/#wef)
* [ ] Перевірити [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Перевірити, чи активний [**WDigest**](windows-local-privilege-escalation/#wdigest)
* [ ] [**LSA Protection**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Захист від облікових даних**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Кешовані облікові дані**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Перевірити, чи є який-небудь [**AV**](https://github.com/carlospolop/hacktricks/blob/ua/windows-hardening/windows-av-bypass/README.md)
* [ ] [**Політика AppLocker**](https://github.com/carlospolop/hacktricks/blob/ua/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
* [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/ua/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
* [ ] [**Привілеї користувача**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Перевірити [**поточні** привілеї користувача **privileges**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Чи ви є [**членом будь-якої привілейованої групи**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Перевірити, чи увімкнені [які-небудь з цих токенів](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Сесії користувачів**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Перевірити[ **домашні сторінки користувачів**](windows-local-privilege-escalation/#home-folders) (доступ?)
* [ ] Перевірити [**Політику паролів**](windows-local-privilege-escalation/#password-policy)
* [ ] Що знаходиться[ **в буфері обміну**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Мережа](windows-local-privilege-escalation/#network)

* Перевірити **поточну** [**інформацію про мережу**](windows-local-privilege-escalation/#network)
* Перевірити **приховані локальні служби**, обмежені для зовнішнього світу

### [Запущені процеси](windows-local-privilege-escalation/#running-processes)

* Дозволи для файлів та папок бінарних процесів [**файлів та папок**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [**Видобуток паролів з пам'яті**](windows-local-privilege-escalation/#memory-password-mining)
* [**Небезпечні GUI-програми**](windows-local-privilege-escalation/#insecure-gui-apps)
* Вкрасти облікові дані за допомогою **цікавих процесів** через `ProcDump.exe` ? (firefox, chrome, тощо ...)

### [Служби](windows-local-privilege-escalation/#services)

* [Чи можете ви **змінити будь-яку службу**?](windows-local-privilege-escalation/#permissions)
* [Чи можете ви **змінити** **бінарний файл**, який **виконується** будь-якою **службою**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [Чи можете ви **змінити** **реєстр** будь-якої **служби**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [Чи можете ви скористатися будь-яким **неправильним шляхом бінарного файлу служби**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Додатки**](windows-local-privilege-escalation/#applications)

* **Права на запис** [**встановлених додатків**](windows-local-privilege-escalation/#write-permissions)
* [**Додатки запуску**](windows-local-privilege-escalation/#run-at-startup)
* **Вразливі** [**Драйвери**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Чи можна **записувати в будь-яку теку всередині PATH**?
* [ ] Чи є відомий сервісний бінарний файл, який **намагається завантажити будь-яку неіснуючу DLL**?
* [ ] Чи можна **записувати** в будь-яку **теку з бінарними файлами**?

### [Мережа](windows-local-privilege-escalation/#network)

* [ ] Перелічіть мережу (ресурси, інтерфейси, маршрути, сусіди, ...)
* [ ] Зверніть увагу на мережеві служби, які прослуховують локальний хост (127.0.0.1)

### [Облікові записи Windows](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials)облікові дані
* [ ] Облікові дані [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault), які можна використовувати?
* [ ] Цікаві [**DPAPI облікові дані**](windows-local-privilege-escalation/#dpapi)?
* [ ] Паролі в збережених [**Wifi мережах**](windows-local-privilege-escalation/#wifi)?
* [ ] Цікава інформація в [**збережених підключеннях RDP**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Паролі в [**недавно виконаних командах**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] Паролі менеджера віддаленого робочого столу [**Remote Desktop Credentials Manager**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
* [ ] Чи існує [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe)? Облікові дані?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? Завантаження бібліотеки з боку?

### [Файли та Реєстр (Облікові дані)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Облікові дані**](windows-local-privilege-escalation/#putty-creds) **та** [**SSH ключі хоста**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**SSH ключі в реєстрі**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Паролі в [**файлах без участі користувача**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Чи є резервна копія [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
* [ ] [**Облікові дані хмар**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] Файл [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [ ] [**Кешований пароль GPP**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Пароль в [**файлі конфігурації IIS Web**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Цікава інформація в [**веб-журналах**](windows-local-privilege-escalation/#logs)?
* [ ] Чи хочете ви [**запитати облікові дані**](windows-local-privilege-escalation/#ask-for-credentials) у користувача?
* [ ] Цікаві [**файли в кошику**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Інші [**реєстри, що містять облікові дані**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] У [**даних браузера**](windows-local-privilege-escalation/#browsers-history) (бази даних, історія, закладки, ...)?
* [ ] [**Загальний пошук паролів**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) в файлах та реєстрі
* [ ] [**Інструменти**](windows-local-privilege-escalation/#tools-that-search-for-passwords) для автоматичного пошуку паролів

### [Витікання обробників](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Чи є у вас доступ до будь-якого обробника процесу, запущеного адміністратором?

### [Імітація клієнта каналу](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Перевірте, чи можете ви використовувати це

**Спробуйте групу безпеки Try Hard**

<figure><img src="../.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Вивчайте хакінг AWS від нуля до героя з</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Інші способи підтримки HackTricks:

* Якщо ви хочете побачити вашу **компанію рекламовану в HackTricks** або **завантажити HackTricks у PDF**, перевірте [**ПЛАНИ ПІДПИСКИ**](https://github.com/sponsors/carlospolop)!
* Отримайте [**офіційний PEASS & HackTricks мерч**](https://peass.creator-spring.com)
* Відкрийте для себе [**Сім'ю PEASS**](https://opensea.io/collection/the-peass-family), нашу колекцію ексклюзивних [**NFT**](https://opensea.io/collection/the-peass-family)
* **Приєднуйтесь до** 💬 [**групи Discord**](https://discord.gg/hRep4RUj7f) або [**групи Telegram**](https://t.me/peass) або **слідкуйте** за нами на **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Поділіться своїми хакерськими трюками, надсилаючи PR до** [**HackTricks**](https://github.com/carlospolop/hacktricks) та [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) репозиторіїв GitHub.

</details>
