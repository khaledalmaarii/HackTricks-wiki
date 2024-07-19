# macOS Usługi Sieciowe i Protokoły

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}

## Usługi Zdalnego Dostępu

To są powszechne usługi macOS do zdalnego dostępu.\
Możesz włączyć/wyłączyć te usługi w `Ustawienia systemowe` --> `Udostępnianie`

* **VNC**, znane jako “Udostępnianie ekranu” (tcp:5900)
* **SSH**, nazywane “Zdalnym logowaniem” (tcp:22)
* **Apple Remote Desktop** (ARD), lub “Zarządzanie zdalne” (tcp:3283, tcp:5900)
* **AppleEvent**, znane jako “Zdalne zdarzenie Apple” (tcp:3031)

Sprawdź, czy którakolwiek z nich jest włączona, uruchamiając:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentesting ARD

Apple Remote Desktop (ARD) to ulepszona wersja [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) dostosowana do macOS, oferująca dodatkowe funkcje. Znaczną podatnością w ARD jest metoda uwierzytelniania dla hasła ekranu kontrolnego, która wykorzystuje tylko pierwsze 8 znaków hasła, co czyni ją podatną na [atak siłowy](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) za pomocą narzędzi takich jak Hydra lub [GoRedShell](https://github.com/ahhh/GoRedShell/), ponieważ nie ma domyślnych limitów szybkości.

Podatne instancje można zidentyfikować za pomocą skryptu `vnc-info` w **nmap**. Usługi obsługujące `VNC Authentication (2)` są szczególnie podatne na ataki siłowe z powodu skrócenia hasła do 8 znaków.

Aby włączyć ARD do różnych zadań administracyjnych, takich jak eskalacja uprawnień, dostęp GUI lub monitorowanie użytkowników, użyj następującego polecenia:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD zapewnia wszechstronne poziomy kontroli, w tym obserwację, wspólną kontrolę i pełną kontrolę, z sesjami utrzymującymi się nawet po zmianach hasła użytkownika. Umożliwia wysyłanie poleceń Unix bezpośrednio, wykonując je jako root dla użytkowników administracyjnych. Planowanie zadań i zdalne wyszukiwanie Spotlight to istotne funkcje, ułatwiające zdalne, niskoodporne wyszukiwania wrażliwych plików na wielu maszynach.

## Protokół Bonjour

Bonjour, technologia zaprojektowana przez Apple, pozwala **urządzeniom w tej samej sieci na wykrywanie oferowanych przez siebie usług**. Znana również jako Rendezvous, **Zero Configuration** lub Zeroconf, umożliwia urządzeniu dołączenie do sieci TCP/IP, **automatyczne wybieranie adresu IP** i nadawanie swoich usług innym urządzeniom w sieci.

Zero Configuration Networking, zapewniane przez Bonjour, gwarantuje, że urządzenia mogą:
* **Automatycznie uzyskać adres IP** nawet w przypadku braku serwera DHCP.
* Wykonywać **tłumaczenie nazwy na adres** bez potrzeby posiadania serwera DNS.
* **Odkrywać usługi** dostępne w sieci.

Urządzenia korzystające z Bonjour przypisują sobie **adres IP z zakresu 169.254/16** i weryfikują jego unikalność w sieci. Maci utrzymują wpis w tabeli routingu dla tej podsieci, co można zweryfikować za pomocą `netstat -rn | grep 169`.

Dla DNS Bonjour wykorzystuje **protokół Multicast DNS (mDNS)**. mDNS działa na **porcie 5353/UDP**, stosując **standardowe zapytania DNS**, ale kierując je na **adres multicast 224.0.0.251**. Takie podejście zapewnia, że wszystkie nasłuchujące urządzenia w sieci mogą odbierać i odpowiadać na zapytania, ułatwiając aktualizację swoich rekordów.

Po dołączeniu do sieci każde urządzenie samodzielnie wybiera nazwę, zazwyczaj kończącą się na **.local**, która może pochodzić z nazwy hosta lub być generowana losowo.

Odkrywanie usług w sieci ułatwia **DNS Service Discovery (DNS-SD)**. Wykorzystując format rekordów DNS SRV, DNS-SD używa **rekordów DNS PTR** do umożliwienia listowania wielu usług. Klient poszukujący konkretnej usługi zażąda rekordu PTR dla `<Service>.<Domain>`, otrzymując w zamian listę rekordów PTR sformatowanych jako `<Instance>.<Service>.<Domain>`, jeśli usługa jest dostępna z wielu hostów.

Narzędzie `dns-sd` może być używane do **odkrywania i ogłaszania usług sieciowych**. Oto kilka przykładów jego użycia:

### Wyszukiwanie usług SSH

Aby wyszukać usługi SSH w sieci, używa się następującego polecenia:
```bash
dns-sd -B _ssh._tcp
```
To polecenie inicjuje przeszukiwanie usług _ssh._tcp i wyświetla szczegóły, takie jak znacznik czasu, flagi, interfejs, domena, typ usługi i nazwa instancji.

### Reklamowanie usługi HTTP

Aby zareklamować usługę HTTP, możesz użyć:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Ten polecenie rejestruje usługę HTTP o nazwie "Index" na porcie 80 z ścieżką `/index.html`.

Aby następnie wyszukać usługi HTTP w sieci:
```bash
dns-sd -B _http._tcp
```
Kiedy usługa się uruchamia, ogłasza swoją dostępność wszystkim urządzeniom w podsieci, multicastując swoją obecność. Urządzenia zainteresowane tymi usługami nie muszą wysyłać żądań, wystarczy, że po prostu nasłuchują tych ogłoszeń.

Dla bardziej przyjaznego interfejsu, aplikacja **Discovery - DNS-SD Browser** dostępna w Apple App Store może wizualizować usługi oferowane w twojej lokalnej sieci.

Alternatywnie, można napisać niestandardowe skrypty do przeglądania i odkrywania usług za pomocą biblioteki `python-zeroconf`. Skrypt [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) demonstruje tworzenie przeglądarki usług dla usług `_http._tcp.local.`, drukując dodane lub usunięte usługi:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Wyłączanie Bonjour
Jeśli istnieją obawy dotyczące bezpieczeństwa lub inne powody, aby wyłączyć Bonjour, można to zrobić za pomocą następującego polecenia:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Odniesienia

* [**Podręcznik hakera Maca**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
{% endhint %}
