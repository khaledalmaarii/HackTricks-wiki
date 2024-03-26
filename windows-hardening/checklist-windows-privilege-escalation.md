# Lista kontrolna - Eskalacja uprawnień lokalnych w systemie Windows

<details>

<summary><strong>Zacznij od zera i stań się ekspertem od hakowania AWS dzięki</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na GitHubie.

</details>

**Try Hard Security Group**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

***

### **Najlepsze narzędzie do szukania wektorów eskalacji uprawnień lokalnych w systemie Windows:** [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

### [Informacje o systemie](windows-local-privilege-escalation/#system-info)

* [ ] Uzyskaj [**informacje o systemie**](windows-local-privilege-escalation/#system-info)
* [ ] Szukaj **exploitów jądra** [**za pomocą skryptów**](windows-local-privilege-escalation/#version-exploits)
* [ ] Użyj **Google do wyszukiwania** exploitów jądra
* [ ] Użyj **searchsploit do wyszukiwania** exploitów jądra
* [ ] Czy są interesujące informacje w [**zmiennych środowiskowych**](windows-local-privilege-escalation/#environment)?
* [ ] Hasła w [**historii PowerShell**](windows-local-privilege-escalation/#powershell-history)?
* [ ] Czy są interesujące informacje w [**ustawieniach internetowych**](windows-local-privilege-escalation/#internet-settings)?
* [ ] [**Dyski**](windows-local-privilege-escalation/#drives)?
* [ ] [**Exploit WSUS**](windows-local-privilege-escalation/#wsus)?
* [**AlwaysInstallElevated**](windows-local-privilege-escalation/#alwaysinstallelevated)?

### [Eksploracja logowania/AV](windows-local-privilege-escalation/#enumeration)

* [ ] Sprawdź ustawienia [**Audytu** ](windows-local-privilege-escalation/#audit-settings)i [**WEF** ](windows-local-privilege-escalation/#wef)
* [ ] Sprawdź czy [**WDigest** ](windows-local-privilege-escalation/#wdigest)jest aktywny
* [ ] [**Ochrona LSA**](windows-local-privilege-escalation/#lsa-protection)?
* [ ] [**Guardia Credentials**](windows-local-privilege-escalation/#credentials-guard)[?](windows-local-privilege-escalation/#cached-credentials)
* [ ] [**Zachowane poświadczenia**](windows-local-privilege-escalation/#cached-credentials)?
* [ ] Sprawdź, czy jest zainstalowane jakieś [**AV**](windows-av-bypass)
* [**Polityka AppLocker**](authentication-credentials-uac-and-efs#applocker-policy)?
* [**UAC**](authentication-credentials-uac-and-efs/uac-user-account-control)
* [**Uprawnienia użytkownika**](windows-local-privilege-escalation/#users-and-groups)
* Sprawdź [**bieżące** uprawnienia **użytkownika**](windows-local-privilege-escalation/#users-and-groups)
* Czy jesteś [**członkiem jakiejkolwiek grupy uprzywilejowanej**](windows-local-privilege-escalation/#privileged-groups)?
* Sprawdź, czy masz włączone [którekolwiek z tych tokenów](windows-local-privilege-escalation/#token-manipulation): **SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebugPrivilege** ?
* [**Sesje użytkowników**](windows-local-privilege-escalation/#logged-users-sessions)?
* Sprawdź [**katalogi domowe użytkowników**](windows-local-privilege-escalation/#home-folders) (dostęp?)
* Sprawdź [**Politykę hasła**](windows-local-privilege-escalation/#password-policy)
* Co jest [**w schowku**](windows-local-privilege-escalation/#get-the-content-of-the-clipboard)?

### [Sieć](windows-local-privilege-escalation/#network)

* Sprawdź **bieżące** [**informacje sieciowe**](windows-local-privilege-escalation/#network)
* Sprawdź **ukryte lokalne usługi** ograniczone do zewnątrz

### [Uruchomione procesy](windows-local-privilege-escalation/#running-processes)

* Uprawnienia plików i folderów procesów [**binarnych**](windows-local-privilege-escalation/#file-and-folder-permissions)
* [**Wydobywanie haseł z pamięci**](windows-local-privilege-escalation/#memory-password-mining)
* [**Niebezpieczne aplikacje GUI**](windows-local-privilege-escalation/#insecure-gui-apps)
* Ukradnij poświadczenia z **interesujących procesów** za pomocą `ProcDump.exe` ? (firefox, chrome, itp ...)

### [Usługi](windows-local-privilege-escalation/#services)

* [Czy możesz **modyfikować jakąkolwiek usługę**?](windows-local-privilege-escalation#permissions)
* [Czy możesz **modyfikować** **binarny plik**, który jest **wykonywany** przez jakąkolwiek **usługę**?](windows-local-privilege-escalation/#modify-service-binary-path)
* [Czy możesz **modyfikować** **rejestr** jakiejkolwiek **usługi**?](windows-local-privilege-escalation/#services-registry-modify-permissions)
* Czy możesz skorzystać z jakiejkolwiek **ścieżki binarnej usługi bez cudzysłowu**?](windows-local-privilege-escalation/#unquoted-service-paths)

### [**Aplikacje**](windows-local-privilege-escalation/#applications)

* **Prawa do zapisu na zainstalowanych aplikacjach**](windows-local-privilege-escalation/#write-permissions)
* [**Aplikacje uruchamiane przy starcie**](windows-local-privilege-escalation/#run-at-startup)
* **Podatne** [**Sterowniki**](windows-local-privilege-escalation/#drivers)
### [DLL Hijacking](windows-local-privilege-escalation/#path-dll-hijacking)

* [ ] Czy możesz **pisać w dowolnym folderze w ścieżce PATH**?
* [ ] Czy istnieje znany binarny plik usługi, który **próbuje załadować nieistniejącą DLL**?
* [ ] Czy możesz **pisać** w dowolnym **folderze z binarnymi plikami**?

### [Sieć](windows-local-privilege-escalation/#network)

* [ ] Wylicz sieć (udziały, interfejsy, trasy, sąsiedzi, ...)
* [ ] Szczególnie zwróć uwagę na usługi sieciowe nasłuchujące na localhost (127.0.0.1)

### [Dane uwierzytelniające systemu Windows](windows-local-privilege-escalation/#windows-credentials)

* [ ] [**Winlogon** ](windows-local-privilege-escalation/#winlogon-credentials) dane uwierzytelniające
* [ ] Dane uwierzytelniające [**Windows Vault**](windows-local-privilege-escalation/#credentials-manager-windows-vault), których możesz użyć?
* [ ] Interesujące [**dane uwierzytelniające DPAPI**](windows-local-privilege-escalation/#dpapi)?
* [ ] Hasła zapisanych sieci [**Wifi**](windows-local-privilege-escalation/#wifi)?
* [ ] Interesujące informacje w [**zapisanych połączeniach RDP**](windows-local-privilege-escalation/#saved-rdp-connections)?
* [ ] Hasła w [**ostatnio uruchomionych poleceniach**](windows-local-privilege-escalation/#recently-run-commands)?
* [ ] Hasła menedżera [**zdalnego pulpitu**](windows-local-privilege-escalation/#remote-desktop-credential-manager)?
* [ ] Czy istnieje [**AppCmd.exe**](windows-local-privilege-escalation/#appcmd-exe)? Dane uwierzytelniające?
* [ ] [**SCClient.exe**](windows-local-privilege-escalation/#scclient-sccm)? Ładowanie bocznego pliku DLL?

### [Pliki i Rejestr (Dane uwierzytelniające)](windows-local-privilege-escalation/#files-and-registry-credentials)

* [ ] **Putty:** [**Dane uwierzytelniające**](windows-local-privilege-escalation/#putty-creds) **i** [**klucze hosta SSH**](windows-local-privilege-escalation/#putty-ssh-host-keys)
* [ ] [**Klucze SSH w rejestrze**](windows-local-privilege-escalation/#ssh-keys-in-registry)?
* [ ] Hasła w [**plikach bezobsługowych**](windows-local-privilege-escalation/#unattended-files)?
* [ ] Jakiekolwiek kopie zapasowe [**SAM & SYSTEM**](windows-local-privilege-escalation/#sam-and-system-backups)?
* [ ] [**Dane uwierzytelniające chmury**](windows-local-privilege-escalation/#cloud-credentials)?
* [ ] Plik [**McAfee SiteList.xml**](windows-local-privilege-escalation/#mcafee-sitelist.xml)?
* [**Zachowane hasło GPP**](windows-local-privilege-escalation/#cached-gpp-pasword)?
* Hasło w pliku konfiguracyjnym [**IIS Web**](windows-local-privilege-escalation/#iis-web-config)?
* Interesujące informacje w [**logach sieciowych**](windows-local-privilege-escalation/#logs)?
* Czy chcesz [**poprosić o dane uwierzytelniające**](windows-local-privilege-escalation/#ask-for-credentials) od użytkownika?
* Interesujące [**pliki w Koszu**](windows-local-privilege-escalation/#credentials-in-the-recyclebin)?
* Inne [**rejestry zawierające dane uwierzytelniające**](windows-local-privilege-escalation/#inside-the-registry)?
* Wewnątrz [**danych przeglądarki**](windows-local-privilege-escalation/#browsers-history) (bazy danych, historia, zakładki, ...)?
* [**Ogólne wyszukiwanie hasła**](windows-local-privilege-escalation/#generic-password-search-in-files-and-registry) w plikach i rejestrze
* [**Narzędzia**](windows-local-privilege-escalation/#tools-that-search-for-passwords) do automatycznego wyszukiwania haseł

### [Wyciekłe uchwyty](windows-local-privilege-escalation/#leaked-handlers)

* [ ] Czy masz dostęp do jakiegokolwiek uchwytu procesu uruchomionego przez administratora?

### [Impersonacja klienta potoku](windows-local-privilege-escalation/#named-pipe-client-impersonation)

* [ ] Sprawdź, czy możesz to wykorzystać

**Grupa Try Hard Security**

<figure><img src="/.gitbook/assets/telegram-cloud-document-1-5159108904864449420.jpg" alt=""><figcaption></figcaption></figure>

{% embed url="https://discord.gg/tryhardsecurity" %}

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLANY SUBSKRYPCYJNE**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
