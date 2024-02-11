<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>


## smss.exe

**Menedżer sesji**.\
Sesja 0 uruchamia **csrss.exe** i **wininit.exe** (**usługi systemowe**) podczas gdy sesja 1 uruchamia **csrss.exe** i **winlogon.exe** (**sesja użytkownika**). Jednak powinieneś zobaczyć **tylko jeden proces** tego **pliku binarnego** bez potomków w drzewie procesów.

Dodatkowo, sesje inne niż 0 i 1 mogą oznaczać występowanie sesji RDP.


## csrss.exe

**Proces podsystemu klient-serwer**.\
Zarządza **procesami** i **wątkami**, udostępnia **API systemu Windows** innym procesom, a także **mapuje litery dysków**, tworzy **pliki tymczasowe** i obsługuje **proces zamykania**.

Jest jeden **uruchomiony w sesji 0 i kolejny w sesji 1** (czyli **2 procesy** w drzewie procesów). Kolejny jest tworzony **dla każdej nowej sesji**.


## winlogon.exe

**Proces logowania systemu Windows**.\
Jest odpowiedzialny za **logowanie**/**wylogowywanie** użytkownika. Uruchamia **logonui.exe**, aby poprosić o nazwę użytkownika i hasło, a następnie wywołuje **lsass.exe**, aby je zweryfikować.

Następnie uruchamia **userinit.exe**, który jest określony w **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** z kluczem **Userinit**.

Ponadto, wcześniej wspomniany rejestr powinien zawierać **explorer.exe** w kluczu **Shell**, w przeciwnym razie może być wykorzystywany jako **metoda trwałości złośliwego oprogramowania**.


## wininit.exe

**Proces inicjalizacji systemu Windows**. \
Uruchamia **services.exe**, **lsass.exe** i **lsm.exe** w sesji 0. Powinien istnieć tylko 1 proces.


## userinit.exe

**Aplikacja logowania Userinit**.\
Ładuje **ntduser.dat w HKCU** i inicjalizuje **środowisko użytkownika** oraz uruchamia **skrypty logowania** i **GPO**.

Uruchamia **explorer.exe**.


## lsm.exe

**Menedżer lokalnej sesji**.\
Współpracuje z smss.exe w manipulowaniu sesjami użytkowników: logowanie/wylogowywanie, uruchamianie powłoki, blokowanie/odblokowywanie pulpitu, itp.

Po W7 lsm.exe został przekształcony w usługę (lsm.dll).

Powinien istnieć tylko 1 proces w W7, a z nich uruchamiana jest usługa działająca na DLL.


## services.exe

**Menedżer kontroli usług**.\
**Ładuje** **usługi** skonfigurowane jako **auto-start** oraz **sterowniki**.

Jest to proces nadrzędny dla **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** i wielu innych.

Usługi są zdefiniowane w `HKLM\SYSTEM\CurrentControlSet\Services`, a ten proces utrzymuje w pamięci bazę danych z informacjami o usługach, które można zapytać za pomocą sc.exe.

Zauważ, że **niektóre** **usługi** będą uruchamiane w **własnym procesie**, a inne będą **dzielić proces svchost.exe**.

Powinien istnieć tylko 1 proces.


## lsass.exe

**Podsystem lokalnej władzy bezpieczeństwa**.\
Jest odpowiedzialny za **uwierzytelnianie** użytkownika i tworzenie **tokenów bezpieczeństwa**. Wykorzystuje pakiety uwierzytelniania znajdujące się w `HKLM\System\CurrentControlSet\Control\Lsa`.

Zapisuje do **dziennika zdarzeń bezpieczeństwa** i powinien istnieć tylko 1 proces.

Należy pamiętać, że ten proces jest często atakowany w celu wykradzenia haseł.


## svchost.exe

**Proces hosta usług ogólnych**.\
Hostuje wiele usług DLL w jednym wspólnym procesie.

Zazwyczaj zauważysz, że **svchost.exe** jest uruchamiany z flagą `-k`. Spowoduje to wysłanie zapytania do rejestru **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost**, gdzie znajdzie się klucz z wymienionym w -k argumentem, który będzie zawierał usługi do uruchomienia w tym samym procesie.

Na przykład: `-k UnistackSvcGroup` uruchomi: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Jeśli używana jest również **flaga `-s`** z argumentem, to svchost jest proszony o **uruchomienie tylko określonej usługi** w tym argumencie.

Będzie kilka procesów `svchost.exe`. Jeśli którykolwiek z nich **nie używa flagi `-k`**, to jest to bardzo podejrzane. Jeśli okaże się, że **services.exe nie jest procesem nadrzędnym**, to również jest to bardzo podejrzane.


## taskhost.exe

Ten proces działa jako host dla procesów uruchamianych z DLL. Ładuje również usługi uruchamiane z DLL.

W systemie W8 nazywa się to taskhostex.exe, a w systemie W10 taskhostw.exe.


## explorer.exe

Jest to proces odpowiedzialny za **pulpit użytkownika** i uruchamianie plików za pomocą rozszerzeń plików.

Powinien być uruchomiony **tylko 1** proces **na zalogowanego użytkownika**.

Uruchamiany jest z **userinit.exe**, który powinien zostać zakończony, więc **nie powinien pojawić się żaden proces nadrzędny** dla tego procesu.


# Wykrywanie złośliwych procesów

* Czy uruchamiany jest z oczekiwanej ścieżki? (Brak binarnych plików systemowych uruchamianych z lokalizacji tymczasowej)
* Czy komunikuje się z podejrzanymi adresami IP?
* Sprawdź podpisy cyfrowe (Artefakty Microsoftu powinny być podpisane)
* Czy jest poprawnie napisane?
* Czy działa pod oczekiwanym SID?
* Czy proces nadrzędny jest oczekiwany (jeśli istnieje)?
* Czy procesy potomne są oczekiwanymi procesami? (brak cmd.exe, wscript.exe, powershell.exe..?)
