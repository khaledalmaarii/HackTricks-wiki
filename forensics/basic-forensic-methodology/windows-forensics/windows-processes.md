{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}


## smss.exe

**Menedżer sesji**.\
Sesja 0 uruchamia **csrss.exe** i **wininit.exe** (**usługi systemowe**) podczas gdy Sesja 1 uruchamia **csrss.exe** i **winlogon.exe** (**sesja użytkownika**). Jednak powinieneś zobaczyć **tylko jeden proces** tego **binarnego pliku** bez potomków w drzewie procesów.

Dodatkowo, sesje inne niż 0 i 1 mogą oznaczać występowanie sesji RDP.


## csrss.exe

**Proces podsystemu klienta/serwera**.\
Zarządza **procesami** i **wątkami**, udostępnia **API systemu Windows** dla innych procesów oraz **mapuje litery dysków**, tworzy **pliki tymczasowe** i obsługuje **procesy zamykania**.

Jest jeden **uruchomiony w Sesji 0 i drugi w Sesji 1** (więc **2 procesy** w drzewie procesów). Kolejny jest tworzony **na nową sesję**.


## winlogon.exe

**Proces logowania systemu Windows**.\
Jest odpowiedzialny za **logowanie**/**wylogowywanie** użytkownika. Uruchamia **logonui.exe**, aby poprosić o nazwę użytkownika i hasło, a następnie wywołuje **lsass.exe**, aby je zweryfikować.

Następnie uruchamia **userinit.exe**, który jest określony w **`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`** z kluczem **Userinit**.

Ponadto, poprzedni rejestr powinien zawierać **explorer.exe** w kluczu **Shell** lub może być wykorzystany jako **metoda trwałości złośliwego oprogramowania**.


## wininit.exe

**Proces inicjowania systemu Windows**. \
Uruchamia **services.exe**, **lsass.exe** i **lsm.exe** w Sesji 0. Powinien być tylko 1 proces.


## userinit.exe

**Aplikacja logowania Userinit**.\
Ładuje **ntduser.dat w HKCU** i inicjuje **środowisko użytkownika** oraz uruchamia **skrypty logowania** i **GPO**.

Uruchamia **explorer.exe**.


## lsm.exe

**Lokalny menedżer sesji**.\
Współpracuje ze smss.exe w manipulowaniu sesjami użytkownika: logowanie/wylogowanie, uruchamianie powłoki, blokowanie/odblokowywanie pulpitu, itp.

Po W7 lsm.exe został przekształcony w usługę (lsm.dll).

Powinien być tylko 1 proces w W7 i z nich usługa uruchamiająca DLL.


## services.exe

**Menedżer kontrolerów usług**.\
**Ładuje** **usługi** skonfigurowane jako **auto-start** oraz **sterowniki**.

Jest to proces nadrzędny dla **svchost.exe**, **dllhost.exe**, **taskhost.exe**, **spoolsv.exe** i wielu innych.

Usługi są zdefiniowane w `HKLM\SYSTEM\CurrentControlSet\Services`, a ten proces utrzymuje w pamięci bazę danych informacji o usłudze, do której można uzyskać dostęp za pomocą sc.exe.

Zauważ, jak **niektóre** **usługi** będą uruchamiane w **własnym procesie** a inne będą **dzielić proces svchost.exe**.

Powinien być tylko 1 proces.


## lsass.exe

**Podsystem lokalnej władzy bezpieczeństwa**.\
Jest odpowiedzialny za uwierzytelnianie użytkownika i tworzenie **tokenów bezpieczeństwa**. Wykorzystuje pakiety uwierzytelniania znajdujące się w `HKLM\System\CurrentControlSet\Control\Lsa`.

Zapisuje do **dziennika zdarzeń bezpieczeństwa** i powinien być tylko 1 proces.

Pamiętaj, że ten proces jest często atakowany w celu wykradnięcia haseł.


## svchost.exe

**Proces hosta usługi ogólnej**.\
Hostuje wiele usług DLL w jednym wspólnym procesie.

Zazwyczaj zauważysz, że **svchost.exe** jest uruchamiany z flagą `-k`. Spowoduje to wysłanie zapytania do rejestru **HKEY\_LOCAL\_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Svchost**, gdzie będzie klucz z wymienionym argumentem w -k, który będzie zawierał usługi do uruchomienia w tym samym procesie.

Na przykład: `-k UnistackSvcGroup` uruchomi: `PimIndexMaintenanceSvc MessagingService WpnUserService CDPUserSvc UnistoreSvc UserDataSvc OneSyncSvc`

Jeśli używana jest również **flaga `-s`** z argumentem, to svchost jest proszony o **uruchomienie tylko określonej usługi** w tym argumencie.

Będzie kilka procesów `svchost.exe`. Jeśli którykolwiek z nich **nie używa flagi `-k`**, to jest to bardzo podejrzane. Jeśli zauważysz, że **services.exe nie jest rodzicem**, to również jest to bardzo podejrzane.


## taskhost.exe

Ten proces działa jako host dla procesów uruchamianych z plików DLL. Ładuje również usługi uruchamiane z plików DLL.

W W8 nazywa się to taskhostex.exe, a w W10 taskhostw.exe.


## explorer.exe

To jest proces odpowiedzialny za **pulpit użytkownika** i uruchamianie plików za pomocą rozszerzeń plików.

Powinien być uruchomiony tylko **jeden proces na zalogowanego użytkownika.**

Uruchamiany jest z **userinit.exe**, który powinien zostać zakończony, więc **nie powinien pojawić się żaden rodzic** dla tego procesu.


# Wykrywanie złośliwych procesów

* Czy uruchamiany jest z oczekiwanej ścieżki? (Żadne binaria systemowe Windows nie uruchamiają się z lokalizacji tymczasowej)
* Czy komunikuje się z podejrzanymi adresami IP?
* Sprawdź podpisy cyfrowe (Artefakty Microsoftu powinny być podpisane)
* Czy jest poprawnie napisane?
* Czy działa pod oczekiwanym SID?
* Czy proces nadrzędny jest oczekiwany (jeśli istnieje)?
* Czy procesy potomne są oczekiwanymi procesami? (brak cmd.exe, wscript.exe, powershell.exe..?)


{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Szkolenie AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Szkolenie GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
