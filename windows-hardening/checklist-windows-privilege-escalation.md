# Lista kontrolna - Eskalacja uprawnień lokalnych w systemie Windows

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

### **Narzędzie do wyszukiwania wektorów eskalacji uprawnień lokalnych w systemie Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacje o systemie](windows-local-privilege-escalation/#system-info)

* [ ] Uzyskaj [**informacje o systemie**](windows-local-privilege-escalation/#system-info)
* [ ] Wyszukaj **exploity jądra** [**za pomocą skryptów**](windows-local-privilege-escalation/#version-exploits)
* [ ] Użyj **Google do wyszukiwania** exploitów **jądra**
* [ ] Użyj **searchsploit do wyszukiwania** exploitów **jądra**
* [ ] Czy interesujące informacje znajdują się w [**zmiennej środowiskowej**](windows-local-privilege-escalation/#environment)?
* [ ] Hasła w [**historii PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Czy interesujące informacje znajdują się w [**ustawieniach internetowych**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Dyski**](windows-local-privilege-escalation/#drives)?
* [ ] [**Exploit WSUS**](windows-local-privilege-escalation/#wsus)?
* [ ] [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Eskalacja uprawnień w logowaniu/AV](windows-local-privilege-escalation/#enumeration)

* [ ] Sprawdź ustawienia [**Audytu** ](windows-local-privilege-escalation/#audit-settings)i [**WEF** ](windows-local-privilege-escalation/#wef)
* [ ] Sprawdź [**LAPS**](windows-local-privilege-escalation/#laps)
* [ ] Sprawdź, czy [**WDigest** ](windows-local-privilege-escalation/#wdigest)jest aktywny
* [ ] [**Ochrona LSA**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Guardia poświadczeń**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Buforowane poświadczenia**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Sprawdź, czy jest zainstalowane jakiekolwiek [**oprogramowanie antywirusowe**](windows-av-bypass)
* [ ] [**Polityka AppLocker**](authentication-credentials-uac-and-efs#applocker-policy)?
* [ ] [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [ ] [**Uprawnienia użytkowników**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Sprawdź [**bieżące** uprawnienia użytkownika **użytkownika**](windows-local-privilege-escalation/#users-and-groups)
* [ ] Czy jesteś [**członkiem jakiejkolwiek grupy uprzywilejowanej**](windows-local-privilege-escalation/#privileged-groups)?
* [ ] Sprawdź, czy masz włączone [którekolwiek z tych tokenów](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [ ] [**Sesje użytkowników**](windows-local-privilege-escalation/#logged-users-sessions)?
* [ ] Sprawdź[ **katalogi domowe użytkowników**](windows-local-privilege-escalation/#home-folders) (dostęp?)
* [ ] Sprawdź [**Politykę hasła**](windows-local-privilege-escalation/#password-policy)
* [ ] Co jest [**w schowku**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Sieć](windows-local-privilege-escalation/#network)

* [ ] Sprawdź **bieżące** [**informacje o sieci**](windows-local-privilege-escalation/#network)
* [ ] Sprawdź **ukryte lokalne usługi** ograniczone dla zewnętrznych

### [Uruchomione procesy](windows-local-privilege-escalation/#running-processes)

* [ ] Uprawnienia plików i folderów [**procesów binarnych**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [ ] [**Wydobywanie haseł z pamięci**](windows-local-privilege-escalation/#memory-password-mining)
* [ ] [**Niezabezpieczone aplikacje GUI**](windows-local-privilege-escalation/#insecure-gui-apps)

### [Usługi](windows-local-privilege-escalation/#services)

* [ ] [Czy możesz **modyfikować dowolną usługę**?](windows-local-privilege-escalation#permissions)
* [ ] [Czy możesz **modyfikować** binarny **plik**, który jest **wykonywany** przez dowolną **usługę**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [ ] [Czy możesz **modyfikować** rejestr dowolnej **usługi**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* [ ] [Czy możesz wykorzystać **niepoprawną ścieżkę** binarną **usługi**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Aplikacje**](windows-local-privilege-escalation/#applications)

* [ ] **Uprawnienia do zapisu w zainstalowanych aplikacjach**](windows-local-privilege-escalation/#write-permissions)
* [ ] [**Aplikacje uruchamiane przy starcie**](windows-local-privilege-escalation/#run-at-startup)
* [ ] **Podatne** [**sterowniki**](windows-local-privilege-escalation/#drivers)

### [Hijacking DLL](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Czy możesz **pisać w dowolnym folderze w ścieżce**?
* [ ] Czy istnieje znany binarny plik usługi, który **próbuje załadować nieistniejącą DLL**?
* [ ] Czy możesz **pisać** w dowolnym **folderze z plikami binarnymi**?
### [Sieć](windows-local-privilege-escalation/#sieć)

* [ ] Wylicz sieć (udziały, interfejsy, trasy, sąsiedzi, ...)
* [ ] Szczególnie zwróć uwagę na usługi sieciowe nasłuchujące na localhost (127.0.0.1)

### [Poświadczenia systemu Windows](windows-local-privilege-escalation/#poświadczenia-systemu-windows)

* [ ] Poświadczenia [**Winlogon**](windows-local-privilege-escalation/#poświadczenia-winlogon)
* [ ] Poświadczenia [**Windows Vault**](windows-local-privilege-escalation/#menedżer-poświadczeń-windows-vault), które można wykorzystać?
* [ ] Interesujące [**poświadczenia DPAPI**](windows-local-privilege-escalation/#dpapi)?
* [ ] Hasła zapisanych [**sieci Wifi**](windows-local-privilege-escalation/#wifi)?
* [ ] Interesujące informacje w [**zapisanych połączeniach RDP**](windows-local-privilege-escalation/#zapisane-połączenia-rdp)?
* [ ] Hasła w [**ostatnio uruchomionych poleceniach**](windows-local-privilege-escalation/#ostatnio-uruchomione-polecenia)?
* [ ] Hasła w [**Menedżerze poświadczeń pulpitu zdalnego**](windows-local-privilege-escalation/#menedżer-poświadczeń-pulpitu-zdalnego)?
* [ ] Czy istnieje [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe)? Poświadczenia?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? Ładowanie bocznym kanałem DLL?

### [Pliki i Rejestr (Poświadczenia)](windows-local-privilege-escalation/#pliki-i-rejestr-poświadczenia)

* [ ] **Putty:** [**Poświadczenia**](windows-local-privilege-escalation/#putty-poświadczenia) **i** [**klucze hosta SSH**](windows-local-privilege-escalation/#putty-klucze-hosta-ssh)
* [ ] Klucze SSH w [**rejestrze**](windows-local-privilege-escalation/#klucze-ssh-w-rejestrze)?
* [ ] Hasła w [**plikach bezobsługowych**](windows-local-privilege-escalation/#pliki-bezobsługowe)?
* [ ] Jakiekolwiek kopie zapasowe [**SAM i SYSTEM**](windows-local-privilege-escalation/#kopie-zapasowe-sam-i-system)?
* [ ] [**Poświadczenia chmury**](windows-local-privilege-escalation/#poświadczenia-chmury)?
* [ ] Plik [**McAfee SiteList.xml**](windows-local-privilege-escalation/#plik-mcafee-sitelist.xml)?
* [ ] [**Cached GPP Password**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* [ ] Hasło w [**pliku konfiguracyjnym IIS Web**](windows-local-privilege-escalation/#plik-konfiguracyjny-iis-web)?
* [ ] Interesujące informacje w [**dziennikach sieciowych**](windows-local-privilege-escalation/#dzienniki)?
* [ ] Czy chcesz [**poprosić o poświadczenia**](windows-local-privilege-escalation/#poproś-o-poświadczenia) od użytkownika?
* [ ] Interesujące [**pliki w Koszu**](windows-local-privilege-escalation/#poświadczenia-w-koszu)?
* [ ] Inne [**rejestry zawierające poświadczenia**](windows-local-privilege-escalation/#w-rejestrze)?
* [ ] Wewnątrz danych [**przeglądarki**](windows-local-privilege-escalation/#historia-przeglądarki) (bazy danych, historia, zakładki, ...)?
* [ ] [**Wyszukiwanie ogólne hasła**](windows-local-privilege-escalation/#wyszukiwanie-ogólne-hasła-w-plikach-i-rejestrze) w plikach i rejestrze
* [ ] [**Narzędzia**](windows-local-privilege-escalation/#narzędzia-do-automatycznego-wyszukiwania-hasła) do automatycznego wyszukiwania haseł

### [Wycieki Handlerów](windows-local-privilege-escalation/#wycieki-handlerów)

* [ ] Masz dostęp do jakiegokolwiek handlera procesu uruchomionego przez administratora?

### [Impersonacja klienta nazwanego potoku](windows-local-privilege-escalation/#impersonacja-klienta-nazwanego-potoku)

* [ ] Sprawdź, czy można to wykorzystać

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
