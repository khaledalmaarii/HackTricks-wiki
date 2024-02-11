# AppArmor

<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>

## Podstawowe informacje

AppArmor to **uaktualnienie jądra zaprojektowane w celu ograniczenia zasobów dostępnych dla programów poprzez profile dla poszczególnych programów**, efektywnie wprowadzając kontrolę dostępu wymuszaną (MAC), wiążąc atrybuty kontroli dostępu bezpośrednio z programami, a nie z użytkownikami. Ten system działa poprzez **wczytywanie profili do jądra**, zazwyczaj podczas uruchamiania, a te profile określają, do jakich zasobów program może uzyskać dostęp, takich jak połączenia sieciowe, dostęp do gniazd surowych i uprawnienia do plików.

Istnieją dwa tryby operacyjne dla profili AppArmor:

- **Tryb egzekwowania**: Ten tryb aktywnie egzekwuje zasady zdefiniowane w profilu, blokując działania naruszające te zasady i rejestrując wszelkie próby ich naruszenia za pomocą systemów takich jak syslog lub auditd.
- **Tryb skarg**: W przeciwieństwie do trybu egzekwowania, tryb skarg nie blokuje działań sprzecznych z zasadami profilu. Zamiast tego rejestruje te próby jako naruszenia zasad bez egzekwowania ograniczeń.

### Składniki AppArmor

- **Moduł jądra**: Odpowiada za egzekwowanie zasad.
- **Zasady**: Określają zasady i ograniczenia dotyczące zachowania programu i dostępu do zasobów.
- **Parser**: Wczytuje zasady do jądra w celu egzekwowania lub raportowania.
- **Narzędzia**: Są to programy w trybie użytkownika, które zapewniają interfejs do interakcji z AppArmor i zarządzania nim.

### Ścieżka profili

Profile AppArmor zazwyczaj są zapisywane w _**/etc/apparmor.d/**_\
Za pomocą polecenia `sudo aa-status` można wyświetlić listę binarnych plików, które są ograniczone przez jakiś profil. Jeśli można zmienić znak "/" na kropkę w ścieżce każdego wymienionego pliku binarnego, otrzyma się nazwę profilu apparmor w wymienionym folderze.

Na przykład, profil **apparmor** dla _/usr/bin/man_ będzie znajdował się w _/etc/apparmor.d/usr.bin.man_

### Polecenia
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Tworzenie profilu

* Aby wskazać dotknięty plik wykonywalny, dozwolone są **ścieżki bezwzględne i symbole wieloznaczne** (dla globbingu plików) w celu określenia plików.
* Aby wskazać dostęp, jaki będzie miał program binarny do **plików**, można użyć następujących **kontroli dostępu**:
* **r** (odczyt)
* **w** (zapis)
* **m** (mapowanie pamięci jako wykonywalne)
* **k** (blokowanie plików)
* **l** (tworzenie twardych dowiązań)
* **ix** (wykonanie innego programu z nowym programem dziedziczącym politykę)
* **Px** (wykonanie w ramach innego profilu po wyczyszczeniu środowiska)
* **Cx** (wykonanie w ramach profilu potomnego po wyczyszczeniu środowiska)
* **Ux** (wykonanie bez ograniczeń po wyczyszczeniu środowiska)
* **Zmienne** mogą być definiowane w profilach i mogą być manipulowane spoza profilu. Na przykład: @{PROC} i @{HOME} (dodaj #include \<tunables/global> do pliku profilu)
* **Zasady odrzucania są obsługiwane w celu zastąpienia zasad zezwalania**.

### aa-genprof

Aby łatwo rozpocząć tworzenie profilu, można skorzystać z narzędzia apparmor. Możliwe jest sprawienie, żeby **apparmor zbadał działania wykonywane przez program binarny, a następnie pozwolił Ci zdecydować, które działania chcesz zezwolić lub odrzucić**.\
Wystarczy uruchomić:
```bash
sudo aa-genprof /path/to/binary
```
Następnie, w innym konsolowym oknie wykonaj wszystkie czynności, które zwykle wykonuje binarny plik:
```bash
/path/to/binary -a dosomething
```
Następnie, w pierwszej konsoli naciśnij "**s**", a następnie w zarejestrowanych działaniach wskaż, czy chcesz zignorować, zezwolić, czy cokolwiek innego. Po zakończeniu naciśnij "**f**", a nowy profil zostanie utworzony w _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Za pomocą strzałek możesz wybrać, co chcesz zezwolić/odmówić/cokolwiek innego
{% endhint %}

### aa-easyprof

Możesz również utworzyć szablon profilu apparmor dla binarnego pliku za pomocą:
```bash
sudo aa-easyprof /path/to/binary
# vim:syntax=apparmor
# AppArmor policy for binary
# ###AUTHOR###
# ###COPYRIGHT###
# ###COMMENT###

#include <tunables/global>

# No template variables specified

"/path/to/binary" {
#include <abstractions/base>

# No abstractions specified

# No policy groups specified

# No read paths specified

# No write paths specified
}
```
{% hint style="info" %}
Zauważ, że domyślnie w utworzonym profilu nic nie jest dozwolone, więc wszystko jest odrzucane. Będziesz musiał dodać linie takie jak `/etc/passwd r,` aby umożliwić odczyt binarny `/etc/passwd` na przykład.
{% endhint %}

Następnie możesz **wymusić** nowy profil za pomocą
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modyfikowanie profilu na podstawie logów

Narzędzie poniżej odczyta logi i zapyta użytkownika, czy chce zezwolić na niektóre z wykrytych zabronionych działań:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Za pomocą strzałek możesz wybrać, co chcesz zezwolić/odmówić/cokolwiek
{% endhint %}

### Zarządzanie profilem
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Dzienniki

Przykład **AUDIT** i **DENIED** dzienników z pliku _/var/log/audit/audit.log_ dla wykonywalnego pliku **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Możesz również uzyskać te informacje, korzystając z:
```bash
sudo aa-notify -s 1 -v
Profile: /bin/service_bin
Operation: open
Name: /etc/passwd
Denied: r
Logfile: /var/log/audit/audit.log

Profile: /bin/service_bin
Operation: open
Name: /etc/hosts
Denied: r
Logfile: /var/log/audit/audit.log

AppArmor denials: 2 (since Wed Jan  6 23:51:08 2021)
For more information, please see: https://wiki.ubuntu.com/DebuggingApparmor
```
## Apparmor w Dockerze

Zauważ, że profil **docker-profile** dla Dockera jest domyślnie załadowany:
```bash
sudo aa-status
apparmor module is loaded.
50 profiles are loaded.
13 profiles are in enforce mode.
/sbin/dhclient
/usr/bin/lxc-start
/usr/lib/NetworkManager/nm-dhcp-client.action
/usr/lib/NetworkManager/nm-dhcp-helper
/usr/lib/chromium-browser/chromium-browser//browser_java
/usr/lib/chromium-browser/chromium-browser//browser_openjdk
/usr/lib/chromium-browser/chromium-browser//sanitized_helper
/usr/lib/connman/scripts/dhclient-script
docker-default
```
Domyślnie **profil Apparmor docker-default** jest generowany z [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Podsumowanie profilu docker-default**:

* **Dostęp** do całej **sieci**
* **Nie zdefiniowano** żadnych uprawnień (Jednak niektóre uprawnienia będą pochodzić z podstawowych reguł bazowych, tj. #include \<abstractions/base>)
* **Zapisywanie** do dowolnego pliku **/proc** jest **nie dozwolone**
* Inne **podkatalogi**/**pliki** w /**proc** i /**sys** są **zakazane** dostępu do odczytu/zapisu/blokady/linkowania/wykonania
* **Montowanie** jest **nie dozwolone**
* **Ptrace** może być uruchomiony tylko na procesie, który jest ograniczony przez **ten sam profil apparmor**

Po **uruchomieniu kontenera dockerowego** powinieneś zobaczyć następujący wynik:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Zauważ, że **apparmor domyślnie blokuje uprawnienia capabilities** przyznane kontenerowi. Na przykład, będzie w stanie **zablokować uprawnienie do zapisu wewnątrz /proc, nawet jeśli przyznano uprawnienie SYS\_ADMIN**, ponieważ domyślny profil apparmor dla dockera odrzuca ten dostęp:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Musisz **wyłączyć apparmor**, aby ominąć jego ograniczenia:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Zauważ, że domyślnie **AppArmor** również **zabrania kontenerowi montowania** folderów od wewnątrz, nawet z uprawnieniami SYS\_ADMIN.

Zauważ, że możesz **dodawać/usuwać** **uprawnienia** dla kontenera Docker (to nadal będzie ograniczone przez metody ochrony takie jak **AppArmor** i **Seccomp**):

* `--cap-add=SYS_ADMIN` nadaje uprawnienia `SYS_ADMIN`
* `--cap-add=ALL` nadaje wszystkie uprawnienia
* `--cap-drop=ALL --cap-add=SYS_PTRACE` usuwa wszystkie uprawnienia i nadaje tylko `SYS_PTRACE`

{% hint style="info" %}
Zazwyczaj, gdy **zauważysz**, że masz **uprawnienia zwiększające** dostępność **wewnątrz** kontenera **docker**, ale **część ataku nie działa**, oznacza to, że **apparmor docker** to uniemożliwia.
{% endhint %}

### Przykład

(Przykład z [**tutaj**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Aby zilustrować funkcjonalność AppArmor, utworzyłem nowy profil Docker "mydocker" z dodanym następującym wierszem:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Aby aktywować profil, musimy wykonać następujące czynności:
```
sudo apparmor_parser -r -W mydocker
```
Aby wyświetlić profile, możemy użyć następującej komendy. Poniższa komenda wyświetla mój nowy profil AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Jak pokazano poniżej, otrzymujemy błąd podczas próby zmiany "/etc/", ponieważ profil AppArmor uniemożliwia dostęp do zapisu w "/etc".
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Możesz sprawdzić, który **profil AppArmor uruchamia kontener** za pomocą:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Następnie możesz uruchomić następującą komendę, aby **znaleźć dokładny profil używany**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
W dziwnym przypadku możesz **zmodyfikować profil apparmor dla dockera i go przeładować**. Możesz usunąć ograniczenia i je "omijać".

### Ominięcie AppArmor Docker

**AppArmor działa na podstawie ścieżek**, co oznacza, że nawet jeśli **chroni** pliki wewnątrz katalogu, takiego jak **`/proc`**, jeśli możesz **skonfigurować sposób uruchamiania kontenera**, możesz **zamontować** katalog proc z hosta wewnątrz **`/host/proc`**, a nie będzie już chroniony przez AppArmor.

### Ominięcie AppArmor Shebang

W [**tym błędzie**](https://bugs.launchpad.net/apparmor/+bug/1911431) możesz zobaczyć przykład, jak **nawet jeśli uniemożliwiasz uruchomienie perla z pewnymi zasobami**, jeśli po prostu utworzysz skrypt powłoki **określając** w pierwszej linii **`#!/usr/bin/perl`** i **wykonasz plik bezpośrednio**, będziesz mógł wykonać cokolwiek chcesz. Na przykład:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
<details>

<summary><strong>Naucz się hakować AWS od zera do bohatera z</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Inne sposoby wsparcia HackTricks:

* Jeśli chcesz zobaczyć swoją **firmę reklamowaną w HackTricks** lub **pobrać HackTricks w formacie PDF**, sprawdź [**PLAN SUBSKRYPCJI**](https://github.com/sponsors/carlospolop)!
* Zdobądź [**oficjalne gadżety PEASS & HackTricks**](https://peass.creator-spring.com)
* Odkryj [**Rodzinę PEASS**](https://opensea.io/collection/the-peass-family), naszą kolekcję ekskluzywnych [**NFT**](https://opensea.io/collection/the-peass-family)
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podziel się swoimi sztuczkami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów github.

</details>
