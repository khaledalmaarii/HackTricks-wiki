# Usługi i protokoły sieciowe w systemie macOS

<details>

<summary><strong>Dowiedz się, jak hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCYJNY**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Usługi zdalnego dostępu

Oto powszechne usługi w systemie macOS, które umożliwiają zdalny dostęp.\
Możesz włączać/wyłączać te usługi w `Ustawienia systemowe` --> `Udostępnianie`

* **VNC**, znane jako "Screen Sharing" (tcp:5900)
* **SSH**, zwane "Remote Login" (tcp:22)
* **Apple Remote Desktop** (ARD), lub "Remote Management" (tcp:3283, tcp:5900)
* **AppleEvent**, znane jako "Remote Apple Event" (tcp:3031)

Sprawdź, czy któryś z nich jest włączony, uruchamiając:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Pentestowanie ARD

Apple Remote Desktop (ARD) to ulepszona wersja [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) dostosowana do systemu macOS, oferująca dodatkowe funkcje. Znaczącą podatnością w ARD jest metoda uwierzytelniania hasła do ekranu kontrolnego, która używa tylko pierwszych 8 znaków hasła, co czyni je podatnym na [ataki brute force](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) przy użyciu narzędzi takich jak Hydra lub [GoRedShell](https://github.com/ahhh/GoRedShell/), ponieważ nie ma domyślnych limitów szybkości.

Podatne instancje można zidentyfikować za pomocą skryptu `vnc-info` w narzędziu **nmap**. Usługi obsługujące `VNC Authentication (2)` są szczególnie podatne na ataki brute force z powodu obcięcia hasła do 8 znaków.

Aby włączyć ARD do różnych zadań administracyjnych, takich jak eskalacja uprawnień, dostęp do interfejsu graficznego lub monitorowanie użytkownika, użyj następującej komendy:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
ARD zapewnia różne poziomy kontroli, w tym obserwację, wspólną kontrolę i pełną kontrolę, a sesje utrzymują się nawet po zmianie hasła użytkownika. Umożliwia wysyłanie bezpośrednio poleceń Unix, wykonując je jako root dla użytkowników administracyjnych. Planowanie zadań i zdalne wyszukiwanie Spotlight to godne uwagi funkcje, ułatwiające zdalne, niewielkie wyszukiwanie poufnych plików na wielu maszynach.


## Protokół Bonjour

Bonjour, technologia opracowana przez Apple, umożliwia **urządzeniom w tej samej sieci wykrywanie oferowanych usług**. Znane również jako Rendezvous, **Zero Configuration** lub Zeroconf, umożliwia urządzeniu dołączenie do sieci TCP/IP, **automatyczne wybranie adresu IP** i rozgłoszenie swoich usług innym urządzeniom sieciowym.

Zero Configuration Networking, dostarczane przez Bonjour, zapewnia, że urządzenia mogą:
* **Automatycznie uzyskać adres IP** nawet w przypadku braku serwera DHCP.
* Wykonywać **tłumaczenie nazw na adresy** bez konieczności korzystania z serwera DNS.
* **Odkrywać dostępne usługi** w sieci.

Urządzenia korzystające z Bonjour przypisują sobie **adres IP z zakresu 169.254/16** i sprawdzają jego unikalność w sieci. Maci utrzymują wpis w tablicy routingu dla tego podsieci, który można zweryfikować za pomocą polecenia `netstat -rn | grep 169`.

Bonjour wykorzystuje protokół **Multicast DNS (mDNS)** do obsługi DNS. mDNS działa na porcie **5353/UDP**, używając **standardowych zapytań DNS**, ale kierując je do **adresu multicastowego 224.0.0.251**. Taki sposób działania zapewnia, że wszystkie nasłuchujące urządzenia w sieci mogą otrzymywać i odpowiadać na zapytania, ułatwiając aktualizację ich rekordów.

Po dołączeniu do sieci każde urządzenie samo wybiera nazwę, zwykle kończącą się na **.local**, która może być pochodną nazwy hosta lub losowo generowana.

Odkrywanie usług w sieci jest ułatwione przez **DNS Service Discovery (DNS-SD)**. Wykorzystując format rekordów DNS SRV, DNS-SD używa **rekordów DNS PTR**, aby umożliwić wyświetlanie wielu usług. Klient poszukujący konkretnej usługi będzie żądał rekordu PTR dla `<Usługa>.<Domena>`, otrzymując w zamian listę rekordów PTR sformatowanych jako `<Instancja>.<Usługa>.<Domena>`, jeśli usługa jest dostępna z wielu hostów.


Do **odkrywania i reklamowania usług sieciowych** można użyć narzędzia `dns-sd`. Oto kilka przykładów jego użycia:

### Wyszukiwanie usług SSH

Aby wyszukać usługi SSH w sieci, używa się następującego polecenia:
```bash
dns-sd -B _ssh._tcp
```
Ten polecenie inicjuje przeglądanie usług _ssh._tcp i wyświetla szczegóły takie jak znacznik czasu, flagi, interfejs, domena, typ usługi i nazwa instancji.

### Reklamowanie usługi HTTP

Aby zareklamować usługę HTTP, można użyć:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Ten polecenie rejestruje usługę HTTP o nazwie "Index" na porcie 80 z ścieżką `/index.html`.

Aby wyszukać usługi HTTP w sieci:
```bash
dns-sd -B _http._tcp
```
Kiedy usługa się uruchamia, ogłasza swoją dostępność wszystkim urządzeniom w podsieci, wysyłając komunikat wielokastowy. Urządzenia zainteresowane tymi usługami nie muszą wysyłać żądań, ale po prostu nasłuchują tych ogłoszeń.

Dla bardziej przyjaznego interfejsu, aplikacja **Discovery - DNS-SD Browser** dostępna w sklepie Apple App Store może wizualizować usługi oferowane w lokalnej sieci.

Alternatywnie, można napisać własne skrypty do przeglądania i odkrywania usług przy użyciu biblioteki `python-zeroconf`. Skrypt [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) demonstruje tworzenie przeglądarki usług dla usług `_http._tcp.local.`, drukując dodane lub usunięte usługi:
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
Jeśli istnieją obawy dotyczące bezpieczeństwa lub innych powodów do wyłączenia Bonjour, można to zrobić za pomocą następującej komendy:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Odwołania

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
