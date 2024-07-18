# AppArmor

{% hint style="success" %}
Ucz się i praktykuj Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Ucz się i praktykuj Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Dziel się trikami hakerskimi, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to **dark-web** napędzona wyszukiwarka, która oferuje **darmowe** funkcje do sprawdzania, czy firma lub jej klienci zostali **skompromitowani** przez **złośliwe oprogramowanie kradnące dane**.

Ich głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z złośliwego oprogramowania kradnącego informacje.

Możesz sprawdzić ich stronę internetową i wypróbować ich silnik za **darmo** na:

{% embed url="https://whiteintel.io" %}

***

## Podstawowe informacje

AppArmor to **usprawnienie jądra zaprojektowane do ograniczania zasobów dostępnych dla programów poprzez profile dla poszczególnych programów**, efektywnie wprowadzające Kontrolę Dostępu Ograniczonego (MAC), wiążąc atrybuty kontroli dostępu bezpośrednio z programami, a nie z użytkownikami. Ten system działa poprzez **ładowanie profili do jądra**, zazwyczaj podczas uruchamiania, a te profile określają, do jakich zasobów program może uzyskać dostęp, takich jak połączenia sieciowe, dostęp do gniazd surowych i uprawnienia do plików.

Istnieją dwa tryby operacyjne profili AppArmor:

* **Tryb Egzekwowania**: Ten tryb aktywnie egzekwuje zasady zdefiniowane w profilu, blokując działania, które naruszają te zasady, i rejestrując wszelkie próby ich naruszenia za pośrednictwem systemów takich jak syslog lub auditd.
* **Tryb Skargi**: W odróżnieniu od trybu egzekwowania, tryb skargi nie blokuje działań sprzecznych z zasadami profilu. Zamiast tego rejestruje te próby jako naruszenia zasad bez egzekwowania ograniczeń.

### Składniki AppArmor

* **Moduł Jądra**: Odpowiedzialny za egzekwowanie zasad.
* **Zasady**: Określają zasady i ograniczenia zachowania programu oraz dostępu do zasobów.
* **Parser**: Ładuje zasady do jądra w celu egzekwowania lub raportowania.
* **Narzędzia**: Są to programy w trybie użytkownika, które zapewniają interfejs do interakcji z AppArmor i zarządzania nim.

### Ścieżka profili

Profile AppArmor zazwyczaj są zapisywane w _**/etc/apparmor.d/**_\
Za pomocą `sudo aa-status` będziesz mógł wyświetlić listę binarnych plików, które są ograniczone przez jakiś profil. Jeśli zmienisz znak "/" na kropkę w ścieżce każdego wymienionego binarnego pliku, otrzymasz nazwę profilu apparmor wewnątrz wspomnianego folderu.

Na przykład profil **apparmor** dla _/usr/bin/man_ będzie znajdował się w _/etc/apparmor.d/usr.bin.man_

### Komendy
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

* Aby wskazać dotknięty plik wykonywalny, dozwolone są **ścieżki bezwzględne i symbole wieloznaczne** (do tworzenia plików globbingowych) do określania plików.
* Aby wskazać dostęp, jaki będzie miała binarka do **plików**, można użyć następujących **kontroli dostępu**:
* **r** (odczyt)
* **w** (zapis)
* **m** (mapowanie pamięci jako wykonywalne)
* **k** (blokowanie pliku)
* **l** (tworzenie twardych łączy)
* **ix** (wykonanie innego programu z nowym programem dziedziczącym politykę)
* **Px** (wykonanie pod innym profilem po wyczyszczeniu środowiska)
* **Cx** (wykonanie pod profilem potomnym po wyczyszczeniu środowiska)
* **Ux** (wykonanie bez ograniczeń po wyczyszczeniu środowiska)
* **Zmienne** mogą być zdefiniowane w profilach i mogą być manipulowane spoza profilu. Na przykład: @{PROC} i @{HOME} (dodaj #include \<tunables/global> do pliku profilu)
* **Zasady odmowy są obsługiwane do zastępowania zasad zezwalania**.

### aa-genprof

Aby łatwo rozpocząć tworzenie profilu, apparmor może ci pomóc. Możliwe jest **spowodowanie, że apparmor przeanalizuje działania wykonywane przez binarkę, a następnie pozwoli ci zdecydować, które działania chcesz zezwolić lub zabronić**.\
Wystarczy uruchomić:
```bash
sudo aa-genprof /path/to/binary
```
Następnie w innej konsoli wykonaj wszystkie czynności, które zwykle wykonuje plik binarny:
```bash
/path/to/binary -a dosomething
```
Następnie w pierwszej konsoli naciśnij "**s**", a następnie w zarejestrowanych działaniach wskaż, czy chcesz zignorować, zezwolić, czy cokolwiek innego. Gdy skończysz, naciśnij "**f**", a nowy profil zostanie utworzony w _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Korzystając z klawiszy strzałek, możesz wybrać, co chcesz zezwolić/odmówić/cokolwiek innego
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
Zauważ, że domyślnie w utworzonym profilu nic nie jest dozwolone, więc wszystko jest odrzucane. Będziesz musiał dodać linie takie jak `/etc/passwd r,` aby pozwolić na odczyt binarny `/etc/passwd` na przykład.
{% endhint %}

Następnie możesz **narzucić** nowy profil za pomocą
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modyfikowanie profilu z logów

Następujące narzędzie odczyta logi i zapyta użytkownika, czy chce zezwolić na niektóre z wykrytych zabronionych akcji:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Za pomocą klawiszy strzałek możesz wybrać, co chcesz zezwolić/zakazać/cokolwiek innego
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

Przykład **AUDIT** i **DENIED** logów z _/var/log/audit/audit.log_ dla wykonywalnego pliku **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Możesz również uzyskać tę informację, korzystając z:
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
Domyślny profil **Apparmor docker-default** jest generowany z [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**Podsumowanie profilu docker-default**:

- **Dostęp** do całej **sieci**
- **Nie zdefiniowano żadnych uprawnień** (Jednak niektóre uprawnienia zostaną uwzględnione poprzez dołączenie podstawowych reguł bazowych, tj. #include \<abstractions/base>)
- **Zapisywanie** do dowolnego pliku **/proc** jest **nie dozwolone**
- Inne **podkatalogi**/**pliki** z /**proc** i /**sys** mają **zabroniony** dostęp do odczytu/zapisu/blokady/linkowania/wykonania
- **Montowanie** jest **nie dozwolone**
- **Ptrace** może być uruchomiony tylko na procesie, który jest ograniczony przez **ten sam profil apparmor**

Po **uruchomieniu kontenera dockerowego** powinieneś zobaczyć poniższy wynik:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Zauważ, że **apparmor zablokuje nawet przyznane domyślnie uprawnienia do możliwości** kontenera. Na przykład będzie można **zablokować uprawnienie do zapisu wewnątrz /proc nawet jeśli uprawnienie SYS\_ADMIN jest przyznane**, ponieważ domyślny profil apparmor dla dockera blokuje ten dostęp:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Musisz **wyłączyć apparmor**, aby ominąć jego ograniczenia:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Zauważ, że domyślnie **AppArmor** również **zabrania kontenerowi montowania** folderów od wewnątrz nawet z uprawnieniami SYS\_ADMIN.

Zauważ, że możesz **dodać/usunąć** **uprawnienia** do kontenera dockerowego (to nadal będzie ograniczone przez metody ochrony takie jak **AppArmor** i **Seccomp**):

* `--cap-add=SYS_ADMIN` dodaje uprawnienie `SYS_ADMIN`
* `--cap-add=ALL` dodaje wszystkie uprawnienia
* `--cap-drop=ALL --cap-add=SYS_PTRACE` usuwa wszystkie uprawnienia i dodaje tylko `SYS_PTRACE`

{% hint style="info" %}
Zazwyczaj, gdy **zauważysz**, że masz **uprawnienie zwiększone** dostępne **wewnątrz** kontenera **dockerowego, ale** część **exploita nie działa**, może to być spowodowane tym, że **AppArmor docker** mu przeszkadza.
{% endhint %}

### Przykład

(Przykład z [**tutaj**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Aby zilustrować funkcjonalność AppArmor, utworzyłem nowy profil Dockerowy "mydocker" z dodaną następującą linią:
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
Jak pokazano poniżej, otrzymujemy błąd podczas próby zmiany „/etc/”, ponieważ profil AppArmor uniemożliwia dostęp do zapisu do „/etc”.
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### Bypass1 AppArmor Docker

Możesz sprawdzić, który **profil apparmor uruchamia kontener** za pomocą:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Następnie możesz uruchomić poniższą komendę, aby **znaleźć dokładny profil używany**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
### AppArmor Docker Bypass2

**AppArmor działa na podstawie ścieżek**, oznacza to, że nawet jeśli może **chronić** pliki wewnątrz katalogu takiego jak **`/proc`**, jeśli możesz **skonfigurować sposób uruchamiania kontenera**, możesz **zamontować** katalog proc hosta wewnątrz **`/host/proc`** i **nie będzie on już chroniony przez AppArmor**.

### AppArmor Shebang Bypass

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
### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) to wyszukiwarka zasilana przez **dark web**, która oferuje **darmowe** funkcje do sprawdzenia, czy firma lub jej klienci zostali **skompromitowani** przez **złośliwe oprogramowanie kradnące dane**.

Ich głównym celem WhiteIntel jest zwalczanie przejęć kont i ataków ransomware wynikających z złośliwego oprogramowania kradnącego informacje.

Możesz odwiedzić ich stronę internetową i wypróbować ich silnik za **darmo** pod adresem:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Dowiedz się i ćwicz Hacking AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Dowiedz się i ćwicz Hacking GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Wesprzyj HackTricks</summary>

* Sprawdź [**plany subskrypcyjne**](https://github.com/sponsors/carlospolop)!
* **Dołącz do** 💬 [**Grupy Discord**](https://discord.gg/hRep4RUj7f) lub [**grupy telegramowej**](https://t.me/peass) lub **śledź** nas na **Twitterze** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Udostępnij sztuczki hakerskie, przesyłając PR-y do** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) na githubie.

</details>
{% endhint %}
