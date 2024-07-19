# BloodHound & Other AD Enum Tools

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

## AD Explorer

[AD Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) jest częścią Sysinternal Suite:

> Zaawansowany przeglądarka i edytor Active Directory (AD). Możesz użyć AD Explorer, aby łatwo nawigować po bazie danych AD, definiować ulubione lokalizacje, przeglądać właściwości obiektów i atrybuty bez otwierania okien dialogowych, edytować uprawnienia, przeglądać schemat obiektu i wykonywać zaawansowane wyszukiwania, które możesz zapisać i ponownie wykonać.

### Snapshots

AD Explorer może tworzyć migawki AD, abyś mógł je sprawdzić offline.\
Może być używany do odkrywania luk offline lub do porównywania różnych stanów bazy danych AD w czasie.

Będziesz potrzebować nazwy użytkownika, hasła i kierunku połączenia (wymagany jest dowolny użytkownik AD).

Aby zrobić migawkę AD, przejdź do `File` --> `Create Snapshot` i wprowadź nazwę dla migawki.

## ADRecon

[**ADRecon**](https://github.com/adrecon/ADRecon) to narzędzie, które wydobywa i łączy różne artefakty z środowiska AD. Informacje mogą być przedstawione w **specjalnie sformatowanym** raporcie Microsoft Excel **, który zawiera podsumowania z metrykami, aby ułatwić analizę i zapewnić całościowy obraz aktualnego stanu docelowego środowiska AD.
```bash
# Run it
.\ADRecon.ps1
```
## BloodHound

From [https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)

> BloodHound to aplikacja webowa w JavaScript na jednej stronie, zbudowana na bazie [Linkurious](http://linkurio.us/), skompilowana z użyciem [Electron](http://electron.atom.io/), z bazą danych [Neo4j](https://neo4j.com/) zasilaną przez zbieracz danych w C#.

BloodHound wykorzystuje teorię grafów do ujawnienia ukrytych i często niezamierzonych relacji w środowisku Active Directory lub Azure. Atakujący mogą używać BloodHound do łatwego identyfikowania skomplikowanych ścieżek ataku, które w przeciwnym razie byłyby niemożliwe do szybkiego zidentyfikowania. Obrońcy mogą używać BloodHound do identyfikacji i eliminacji tych samych ścieżek ataku. Zarówno zespoły niebieskie, jak i czerwone mogą używać BloodHound do łatwego uzyskania głębszego zrozumienia relacji uprawnień w środowisku Active Directory lub Azure.

Tak więc, [Bloodhound](https://github.com/BloodHoundAD/BloodHound) to niesamowite narzędzie, które może automatycznie enumerować domenę, zapisywać wszystkie informacje, znajdować możliwe ścieżki eskalacji uprawnień i przedstawiać wszystkie informacje za pomocą grafów.

BloodHound składa się z 2 głównych części: **ingestorów** i **aplikacji wizualizacyjnej**.

**Ingestory** są używane do **enumeracji domeny i ekstrakcji wszystkich informacji** w formacie, który zrozumie aplikacja wizualizacyjna.

**Aplikacja wizualizacyjna używa neo4j** do pokazania, jak wszystkie informacje są ze sobą powiązane oraz do pokazania różnych sposobów eskalacji uprawnień w domenie.

### Instalacja
Po utworzeniu BloodHound CE, cały projekt został zaktualizowany w celu ułatwienia użycia z Dockerem. Najłatwiejszym sposobem na rozpoczęcie jest użycie jego wstępnie skonfigurowanej konfiguracji Docker Compose.

1. Zainstaluj Docker Compose. Powinno to być zawarte w instalacji [Docker Desktop](https://www.docker.com/products/docker-desktop/).
2. Uruchom:
```
curl -L https://ghst.ly/getbhce | docker compose -f - up
```
3. Zlokalizuj losowo wygenerowane hasło w wyjściu terminala Docker Compose.  
4. W przeglądarce przejdź do http://localhost:8080/ui/login. Zaloguj się jako admin, używając losowo wygenerowanego hasła z logów.

Po tym musisz zmienić losowo wygenerowane hasło, a nowy interfejs będzie gotowy, z którego możesz bezpośrednio pobrać ingestry.

### SharpHound

Mają kilka opcji, ale jeśli chcesz uruchomić SharpHound z komputera dołączonego do domeny, używając swojego aktualnego użytkownika i wyodrębnić wszystkie informacje, możesz to zrobić:
```
./SharpHound.exe --CollectionMethods All
Invoke-BloodHound -CollectionMethod All
```
> Możesz przeczytać więcej o **CollectionMethod** i sesji pętli [tutaj](https://support.bloodhoundenterprise.io/hc/en-us/articles/17481375424795-All-SharpHound-Community-Edition-Flags-Explained)

Jeśli chcesz uruchomić SharpHound używając innych poświadczeń, możesz utworzyć sesję CMD netonly i uruchomić SharpHound stamtąd:
```
runas /netonly /user:domain\user "powershell.exe -exec bypass"
```
[**Dowiedz się więcej o Bloodhound na ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux)


## Group3r

[**Group3r**](https://github.com/Group3r/Group3r) to narzędzie do znajdowania **vulnerabilities** w Active Directory związanych z **Group Policy**. \
Musisz **uruchomić group3r** z hosta wewnątrz domeny, używając **dowolnego użytkownika domeny**.
```bash
group3r.exe -f <filepath-name.log>
# -s sends results to stdin
# -f send results to file
```
## PingCastle

[**PingCastle**](https://www.pingcastle.com/documentation/) **ocenia bezpieczeństwo środowiska AD** i dostarcza ładny **raport** z wykresami.

Aby go uruchomić, można wykonać plik binarny `PingCastle.exe`, a rozpocznie on **interaktywną sesję** prezentującą menu opcji. Domyślną opcją do użycia jest **`healthcheck`**, która ustali podstawowy **przegląd** **domeny** oraz znajdzie **błędne konfiguracje** i **luki**.&#x20;

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
