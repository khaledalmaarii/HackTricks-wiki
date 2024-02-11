# BloodHound i inne narzędzia do wyliczania AD

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Pracujesz w **firmie cyberbezpieczeństwa**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) pochodzi z pakietu Sysinternal Suite:

> Zaawansowany przeglądarka i edytor Active Directory (AD). Możesz używać AD Explorera do łatwego nawigowania po bazie danych AD, definiowania ulubionych lokalizacji, przeglądania właściwości i atrybutów obiektów bez otwierania okien dialogowych, edytowania uprawnień, przeglądania schematu obiektu oraz wykonywania zaawansowanych wyszukiwań, które można zapisać i ponownie wykonać.

### Zrzuty

AD Explorer może tworzyć zrzuty AD, dzięki czemu można je sprawdzić w trybie offline.\
Może być używany do wykrywania podatności w trybie offline lub porównywania różnych stanów bazy danych AD w różnych momentach czasu.

Do utworzenia zrzutu AD przejdź do `Plik` --> `Utwórz zrzut` i wprowadź nazwę dla zrzutu.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) to narzędzie, które wyodrębnia i łączy różne artefakty z środowiska AD. Informacje mogą być prezentowane w **specjalnie sformatowanym** raporcie Microsoft Excel, który zawiera widoki podsumowujące z metrykami ułatwiające analizę i dostarczające holistycznego obrazu aktualnego stanu docelowego środowiska AD.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

Z [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound to jednostronicowa aplikacja internetowa napisana w języku JavaScript, oparta na [Linkurious](http://linkurio.us/), skompilowana przy użyciu [Electron](http://electron.atom.io/), z bazą danych [Neo4j](https://neo4j.com/), zasilaną przez kolektor danych napisany w języku C#.

BloodHound wykorzystuje teorię grafów do odkrywania ukrytych i często niezamierzonych zależności w środowisku Active Directory lub Azure. Atakujący mogą użyć BloodHound do łatwego zidentyfikowania bardzo skomplikowanych ścieżek ataku, które w przeciwnym razie byłoby trudno szybko zidentyfikować. Obrońcy mogą użyć BloodHound do identyfikacji i eliminacji tych samych ścieżek ataku. Zarówno niebieskie, jak i czerwone zespoły mogą używać BloodHound do łatwego zdobycia głębszego zrozumienia relacji uprawnień w środowisku Active Directory lub Azure.

Więc [Bloodhound](https://github.com/BloodHoundAD/BloodHound) to niesamowite narzędzie, które może automatycznie wyliczać domenę, zapisywać wszystkie informacje, znajdować możliwe ścieżki eskalacji uprawnień i pokazywać wszystkie informacje za pomocą grafów.

Bloodhound składa się z 2 głównych części: **ingestorów** i **aplikacji do wizualizacji**.

**Ingestory** są używane do **wyliczenia domeny i wydobycia wszystkich informacji** w formacie, który aplikacja do wizualizacji będzie rozumiała.

**Aplikacja do wizualizacji używa neo4j** do pokazania, jak wszystkie informacje są ze sobą powiązane i do pokazania różnych sposobów eskalacji uprawnień w domenie.

### Instalacja
Po utworzeniu BloodHound CE cały projekt został zaktualizowany, aby ułatwić korzystanie z Docker. Najprostszym sposobem na rozpoczęcie jest użycie prekonfigurowanej konfiguracji Docker Compose.

1. Zainstaluj Docker Compose. Powinien być dołączony do instalacji [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Uruchom:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Zlokalizuj losowo wygenerowane hasło w wynikach terminala Docker Compose.
4. W przeglądarce przejdź do http://localhost:8080/ui/login. Zaloguj się używając nazwy użytkownika admin oraz losowo wygenerowanego hasła z logów.

Po tym będziesz musiał zmienić losowo wygenerowane hasło i będziesz miał gotowy nowy interfejs, z którego możesz bezpośrednio pobrać narzędzia do przetwarzania danych.

### SharpHound

Mają kilka opcji, ale jeśli chcesz uruchomić SharpHound z komputera podłączonego do domeny, używając swojego obecnego użytkownika i wydobyć wszystkie informacje, możesz to zrobić:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Więcej informacji na temat **CollectionMethod** i sesji pętli można znaleźć [tutaj](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Jeśli chcesz uruchomić SharpHound przy użyciu innych poświadczeń, możesz utworzyć sesję CMD netonly i uruchomić SharpHound stamtąd:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Dowiedz się więcej o Bloodhound na stronie ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) to narzędzie do znajdowania **podatności** w Active Directory związanych z **Group Policy**. \
Musisz **uruchomić group3r** z hosta znajdującego się w domenie, używając **dowolnego użytkownika domeny**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **ocenia stan bezpieczeństwa środowiska AD** i dostarcza ładny **raport** z wykresami.

Aby go uruchomić, można wykonać plik binarny `PingCastle.exe`, co spowoduje uruchomienie **sesji interaktywnej**, która przedstawi menu opcji. Domyślną opcją do użycia jest **`healthcheck`**, który ustanowi podstawowy **przegląd** domeny i znajdzie **błędy konfiguracji** oraz **luki w zabezpieczeniach**.&#x20;

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Czy pracujesz w **firmie zajmującej się cyberbezpieczeństwem**? Chcesz zobaczyć swoją **firmę reklamowaną w HackTricks**? A może chcesz mieć dostęp do **najnowszej wersji PEASS lub pobrać HackTricks w formacie PDF**? Sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* **Dołącz do** [**💬**](https://emojipedia.org/speech-balloon/) [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** mnie na **Twitterze** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do repozytorium [hacktricks](https://github.com/carlospolop/hacktricks) i [hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
