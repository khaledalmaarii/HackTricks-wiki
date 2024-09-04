# Lista kontrolna - Lokalna eskalacja uprawnień w systemie Windows

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

### **Najlepsze narzędzie do wyszukiwania wektorów eskalacji uprawnień lokalnych w systemie Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacje o systemie](windows-local-privilege-escalation/#system-info)

* [ ] Uzyskaj [**informacje o systemie**](windows-local-privilege-escalation/#system-info)
* [ ] Szukaj **eksploatacji jądra** [**za pomocą skryptów**](windows-local-privilege-escalation/#version-exploits)
* [ ] Użyj **Google do wyszukiwania** eksploatacji **jądra**
* [ ] Użyj **searchsploit do wyszukiwania** eksploatacji **jądra**
* [ ] Ciekawe informacje w [**zmiennych środowiskowych**](windows-local-privilege-escalation/#environment)?
* [ ] Hasła w [**historii PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Ciekawe informacje w [**ustawieniach Internetu**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Dyski**](windows-local-privilege-escalation/#drives)?
* [ ] [**Eksploatacja WSUS**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Logowanie/wyliczanie AV](windows-local-privilege-escalation/#enumeration)

* [ ] Sprawdź [**ustawienia audytu**](windows-local-privilege-escalation/#audit-settings) i [**WEF**](windows-local-privilege-escalation/#wef)
* [ ] Sprawdź [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Sprawdź, czy [**WDigest**](windows-local-privilege-escalation/#wdigest) jest aktywny
* [ ] [**Ochrona LSA**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Guard Credentials**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Zapisane poświadczenia**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Sprawdź, czy jakikolwiek [**AV**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/windows-av-bypass/README.md)
* [ ] [**Polityka AppLocker**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/README.md#applocker-policy)?
* [ ] [**UAC**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control/README.md)
* [ ] [**Uprawnienia użytkowników**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Sprawdź [**aktualne** uprawnienia **użytkownika**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Czy jesteś [**członkiem jakiejkolwiek grupy z uprawnieniami**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Sprawdź, czy masz [jakiekolwiek z tych tokenów włączonych](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Sesje użytkowników**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Sprawdź [**domy użytkowników**](windows-local-privilege-escalation/#home-folders) (dostęp?)
* [ ] Sprawdź [**Politykę haseł**](windows-local-privilege-escalation/#password-policy)
* [ ] Co jest [**w schowku**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Sieć](windows-local-privilege-escalation/#network)

* [ ] Sprawdź **aktualne** [**informacje o sieci**](windows-local-privilege-escalation/#network)
* [ ] Sprawdź **ukryte lokalne usługi** ograniczone do zewnątrz

### [Uruchomione procesy](windows-local-privilege-escalation/#running-processes)

* [ ] Uprawnienia [**plików i folderów binariów procesów**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**Wydobywanie haseł z pamięci**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**Niebezpieczne aplikacje GUI**](windows-local-privilege-escalation/#insecure-gui-apps)
* [ ] Kradnij poświadczenia z **interesujących procesów** za pomocą `ProcDump.exe` ? (firefox, chrome, itd...)

### [Usługi](windows-local-privilege-escalation/#services)

* [ ] [Czy możesz **zmodyfikować jakąkolwiek usługę**?](windows-local-privilege-escalation/#permissions)
* [ ] [Czy możesz **zmodyfikować** **binarne** pliki, które są **wykonywane** przez jakąkolwiek **usługę**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Czy możesz **zmodyfikować** **rejestr** jakiejkolwiek **usługi**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [Czy możesz skorzystać z jakiejkolwiek **niecytowanej ścieżki binarnej usługi**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Aplikacje**](windows-local-privilege-escalation/#applications)

* [ ] **Uprawnienia do zapisu** [**na zainstalowanych aplikacjach**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**Aplikacje uruchamiane przy starcie**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **Vulnerable** [**Sterowniki**](windows-local-privilege-escalation/#drivers)

### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Czy możesz **zapisać w jakimkolwiek folderze w PATH**?
* [ ] Czy istnieje jakikolwiek znany plik binarny usługi, który **próbuje załadować jakąkolwiek nieistniejącą DLL**?
* [ ] Czy możesz **zapisać** w jakimkolwiek **folderze binarnym**?

### [Sieć](windows-local-privilege-escalation/#network)

* [ ] Wylicz sieć (udostępnienia, interfejsy, trasy, sąsiedzi, ...)
* [ ] Zwróć szczególną uwagę na usługi sieciowe nasłuchujące na localhost (127.0.0.1)

### [Poświadczenia Windows](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials) poświadczenia
* [ ] [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault) poświadczenia, które możesz wykorzystać?
* [ ] Ciekawe [**poświadczenia DPAPI**](windows-local-privilege-escalation/#dpapi)?
* [ ] Hasła zapisanych [**sieci Wifi**](windows-local-privilege-escalation/#wifi)?
* [ ] Ciekawe informacje w [**zapisanych połączeniach RDP**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Hasła w [**niedawno uruchomionych poleceniach**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] [**Menadżer poświadczeń pulpitu zdalnego**](windows-local-privilege-escalation/#remote-desktop-credential-manager) hasła?
* [ ] [**AppCmd.exe** istnieje](windows-local-privilege-escalation/#appcmd-exe)? Poświadczenia?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? Ładowanie DLL z boku?

### [Pliki i rejestr (Poświadczenia)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Creds**](windows-local-privilege-escalation/#putty-creds) **i** [**klucze hosta SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**Klucze SSH w rejestrze**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Hasła w [**plikach bezobsługowych**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Jakiekolwiek [**kopie zapasowe SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
* [ ] [**Poświadczenia w chmurze**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] [**Plik McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [ ] [**Zapisane hasło GPP**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Hasło w [**pliku konfiguracyjnym IIS**](windows-local-privilege-escalation/#iis-web-config)?
* [ ] Ciekawe informacje w [**logach**](windows-local-privilege-escalation/#logs)?
* [ ] Czy chcesz [**poprosić użytkownika o poświadczenia**](windows-local-privilege-escalation/#ask-for-credentials)?
* [ ] Ciekawe [**pliki w Koszu**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* [ ] Inne [**rejestry zawierające poświadczenia**](windows-local-privilege-escalation/#inside-the-registry)?
* [ ] Wewnątrz [**danych przeglądarki**](windows-local-privilege-escalation/#browsers-history) (bazy danych, historia, zakładki, ...)?
* [ ] [**Ogólne wyszukiwanie haseł**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) w plikach i rejestrze
* [ ] [**Narzędzia**](windows-local-privilege-escalation/#tools-that-search-for-passwords) do automatycznego wyszukiwania haseł

### [Wyciekające uchwyty](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Czy masz dostęp do jakiegokolwiek uchwytu procesu uruchomionego przez administratora?

### [Impersonacja klienta Pipe](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Sprawdź, czy możesz to wykorzystać

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podziel się sztuczkami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
