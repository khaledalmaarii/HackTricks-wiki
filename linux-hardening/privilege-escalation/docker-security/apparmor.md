# AppArmor

{% hint style="success" %}
Učite i vežbajte hakovanje AWS:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Obuka AWS Crveni Tim Ekspert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte hakovanje GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Obuka GCP Crveni Tim Ekspert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Pomozite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokretan **dark-web**-om koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **kompromitovani** od strane **malvera za krađu**.

Primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera za krađu informacija.

Možete posetiti njihovu veb lokaciju i isprobati njihovu mašinu za **besplatno** na:

{% embed url="https://whiteintel.io" %}

***

## Osnovne informacije

AppArmor je **kernel unapređenje dizajnirano da ograniči resurse dostupne programima putem profila po programu**, efikasno implementirajući obaveznu kontrolu pristupa (MAC) povezivanjem atributa kontrole pristupa direktno sa programima umesto sa korisnicima. Ovaj sistem funkcioniše tako što **učitava profile u kernel**, obično tokom pokretanja, a ovi profili određuju koje resurse program može da pristupi, kao što su mrežne veze, pristup sirovim soketima i dozvole za datoteke.

Postoje dva operativna moda za AppArmor profile:

* **Režim sprovođenja**: Ovaj režim aktivno sprovodi politike definisane unutar profila, blokirajući radnje koje krše ove politike i beležeći svaki pokušaj njihovog kršenja putem sistema poput syslog-a ili auditd-a.
* **Režim prigovora**: Za razliku od režima sprovođenja, režim prigovora ne blokira radnje koje idu protiv politika profila. Umesto toga, beleži ove pokušaje kao kršenja politike bez sprovođenja ograničenja.

### Komponente AppArmor-a

* **Kernel modul**: Odgovoran za sprovođenje politika.
* **Politike**: Specificiraju pravila i ograničenja za ponašanje programa i pristup resursima.
* **Parser**: Učitava politike u kernel radi sprovođenja ili izveštavanja.
* **Alati**: To su programi u režimu korisnika koji pružaju interfejs za interakciju sa AppArmor-om i upravljanje njime.

### Putanje profila

Apparmor profili obično se čuvaju u _**/etc/apparmor.d/**_\
Sa `sudo aa-status` možete da vidite binarne datoteke koje su ograničene nekim profilom. Ako možete da zamenite znak "/" tačkom u putanji svake navedene binarne datoteke, dobićete ime apparmor profila unutar pomenutog foldera.

Na primer, **apparmor** profil za _/usr/bin/man_ biće smešten u _/etc/apparmor.d/usr.bin.man_

### Komande
```bash
aa-status     #check the current status
aa-enforce    #set profile to enforce mode (from disable or complain)
aa-complain   #set profile to complain mode (from diable or enforcement)
apparmor_parser #to load/reload an altered policy
aa-genprof    #generate a new profile
aa-logprof    #used to change the policy when the binary/program is changed
aa-mergeprof  #used to merge the policies
```
## Kreiranje profila

* Da biste naznačili pogođeni izvršni fajl, dozvoljeni su **apsolutni putevi i džokeri** (za pretragu fajlova) za specificiranje fajlova.
* Da biste naznačili pristup koji će binarni fajl imati nad **fajlovima**, mogu se koristiti sledeće **kontrole pristupa**:
* **r** (čitanje)
* **w** (pisanje)
* **m** (mapiranje memorije kao izvršiv)
* **k** (zaključavanje fajla)
* **l** (kreiranje tvrdih linkova)
* **ix** (za izvršavanje drugog programa sa novim programom koji nasleđuje pravila)
* **Px** (izvršavanje pod drugim profilom, nakon čišćenja okruženja)
* **Cx** (izvršavanje pod djetetovim profilom, nakon čišćenja okruženja)
* **Ux** (izvršavanje bez ograničenja, nakon čišćenja okruženja)
* **Promenljive** se mogu definisati u profilima i mogu se manipulisati izvan profila. Na primer: @{PROC} i @{HOME} (dodajte #include \<tunables/global> u fajl profila)
* **Pravila zabrane podržana su za poništavanje pravila dozvole**.

### aa-genprof

Da biste lako počeli kreirati profil, apparmor vam može pomoći. Moguće je da **apparmor inspekcijom akcija koje izvršava binarni fajl, omogući vam da odlučite koje akcije želite dozvoliti ili zabraniti**.\
Samo trebate pokrenuti:
```bash
sudo aa-genprof /path/to/binary
```
Zatim, u drugoj konzoli izvršite sve radnje koje binarni fajl obično izvršava:
```bash
/path/to/binary -a dosomething
```
Zatim, u prvom konzoli pritisnite "**s**", a zatim u zabeleženim radnjama naznačite da li želite da ignorišete, dozvolite ili šta god drugo. Kada završite, pritisnite "**f**" i novi profil će biti kreiran u _/etc/apparmor.d/path.to.binary_

{% hint style="info" %}
Koristeći strelice možete izabrati šta želite da dozvolite/odbijete/šta god
{% endhint %}

### aa-easyprof

Takođe možete kreirati šablon apparmor profila binarnog fajla sa:
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
Imajte na umu da prema podrazumevanom profilu ništa nije dozvoljeno, tako da je sve zabranjeno. Morate dodati linije poput `/etc/passwd r,` da biste omogućili binarno čitanje `/etc/passwd`, na primer.
{% endhint %}

Zatim možete **naterati** novi profil sa
```bash
sudo apparmor_parser -a /etc/apparmor.d/path.to.binary
```
### Modifikovanje profila iz logova

Sledeći alat će pročitati logove i pitati korisnika da li želi da dozvoli neke od detektovanih zabranjenih radnji:
```bash
sudo aa-logprof
```
{% hint style="info" %}
Korišćenjem strelica možete izabrati šta želite da dozvolite/odbijete/bilo šta drugo
{% endhint %}

### Upravljanje profilom
```bash
#Main profile management commands
apparmor_parser -a /etc/apparmor.d/profile.name #Load a new profile in enforce mode
apparmor_parser -C /etc/apparmor.d/profile.name #Load a new profile in complain mode
apparmor_parser -r /etc/apparmor.d/profile.name #Replace existing profile
apparmor_parser -R /etc/apparmor.d/profile.name #Remove profile
```
## Dnevnici

Primeri **AUDIT** i **DENIED** dnevnika iz _/var/log/audit/audit.log_ izvršnog fajla **`service_bin`**:
```bash
type=AVC msg=audit(1610061880.392:286): apparmor="AUDIT" operation="getattr" profile="/bin/rcat" name="/dev/pts/1" pid=954 comm="service_bin" requested_mask="r" fsuid=1000 ouid=1000
type=AVC msg=audit(1610061880.392:287): apparmor="DENIED" operation="open" profile="/bin/rcat" name="/etc/hosts" pid=954 comm="service_bin" requested_mask="r" denied_mask="r" fsuid=1000 ouid=0
```
Možete dobiti ove informacije i korišćenjem:
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
## Apparmor u Dockeru

Primetite kako je profil **docker-profile** u dockeru podrazumevano učitan:
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
Podrazumevano, **Apparmor docker-default profil** se generiše sa [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

**docker-default profil Summary**:

* **Pristup** svim **mrežama**
* Nijedna **sposobnost** nije definisana (Međutim, neke sposobnosti će doći iz uključivanja osnovnih osnovnih pravila tj. #include \<abstractions/base>)
* **Pisanje** u bilo koji **/proc** fajl nije **dozvoljeno**
* Ostali **poddirektorijumi**/**fajlovi** od /**proc** i /**sys** su **odbijeni** pristup za čitanje/pisanje/zaključavanje/povezivanje/izvršavanje
* **Montiranje** nije **dozvoljeno**
* **Ptrace** može biti pokrenut samo na procesu koji je ograničen istim **apparmor profilom**

Kada **pokrenete docker kontejner** trebalo bi da vidite sledeći izlaz:
```bash
1 processes are in enforce mode.
docker-default (825)
```
Napomena da će **apparmor čak blokirati privilegije sposobnosti** dodeljene kontejneru podrazumevano. Na primer, moći će **blokirati dozvolu za pisanje unutar /proc čak i ako je SYS\_ADMIN sposobnost dodeljena** jer apparmor profil za docker podrazumevano odbija ovaj pristup:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined ubuntu /bin/bash
echo "" > /proc/stat
sh: 1: cannot create /proc/stat: Permission denied
```
Potrebno je **onemogućiti apparmor** da biste zaobišli njegova ograničenja:
```bash
docker run -it --cap-add SYS_ADMIN --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu /bin/bash
```
Napomena da će **AppArmor** podrazumevano takođe **zabraniti kontejneru da montira** fascikle iznutra čak i sa SYS\_ADMIN sposobnošću.

Napomena da možete **dodati/ukloniti** **sposobnosti** kontejneru (ovo će i dalje biti ograničeno zaštitnim metodama poput **AppArmor**-a i **Seccomp**-a):

* `--cap-add=SYS_ADMIN` dodaje `SYS_ADMIN` sposobnost
* `--cap-add=ALL` dodaje sve sposobnosti
* `--cap-drop=ALL --cap-add=SYS_PTRACE` uklanja sve sposobnosti i daje samo `SYS_PTRACE`

{% hint style="info" %}
Obično, kada **otkrijete** da imate **privilegovanu sposobnost** dostupnu **unutar** **docker** kontejnera **ali** deo **eksploatacije ne funkcioniše**, to će biti zato što će docker **apparmor to sprečavati**.
{% endhint %}

### Primer

(Primer sa [**ovde**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-2docker-engine/))

Da ilustrujem funkcionalnost AppArmor-a, kreirao sam novi Docker profil "mydocker" sa dodatom sledećom linijom:
```
deny /etc/* w,   # deny write for all files directly in /etc (not in a subdir)
```
Da biste aktivirali profil, treba da uradite sledeće:
```
sudo apparmor_parser -r -W mydocker
```
Da bismo videli profile, možemo koristiti sledeću komandu. Komanda ispod prikazuje moj novi AppArmor profil.
```
$ sudo apparmor_status  | grep mydocker
mydocker
```
Kao što je prikazano ispod, dobijamo grešku prilikom pokušaja promene "/etc/" jer AppArmor profil sprečava pristup za pisanje "/etc".
```
$ docker run --rm -it --security-opt apparmor:mydocker -v ~/haproxy:/localhost busybox chmod 400 /etc/hostname
chmod: /etc/hostname: Permission denied
```
### AppArmor Docker Bypass1

Možete pronaći koji **apparmor profil pokreće kontejner** koristeći:
```bash
docker inspect 9d622d73a614 | grep lowpriv
"AppArmorProfile": "lowpriv",
"apparmor=lowpriv"
```
Zatim možete pokrenuti sledeću liniju da **pronađete tačan profil koji se koristi**:
```bash
find /etc/apparmor.d/ -name "*lowpriv*" -maxdepth 1 2>/dev/null
```
### AppArmor Docker Bypass2

**AppArmor je zasnovan na putanji**, što znači da čak i ako možda **štiti** datoteke unutar direktorijuma poput **`/proc`**, ako možete **konfigurisati kako će kontejner biti pokrenut**, možete **montirati** direktorijum proc domaćina unutar **`/host/proc`** i on **više neće biti zaštićen od strane AppArmor-a**.

### AppArmor Shebang Bypass

U [**ovom bagu**](https://bugs.launchpad.net/apparmor/+bug/1911431) možete videti primer kako **čak i ako sprečavate perl da se pokrene sa određenim resursima**, ako jednostavno kreirate shell skriptu **specifikujući** u prvom redu **`#!/usr/bin/perl`** i **izvršite datoteku direktno**, moći ćete izvršiti šta god želite. Na primer:
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

[**WhiteIntel**](https://whiteintel.io) je pretraživač pokrenut na **dark webu** koji nudi **besplatne** funkcionalnosti za proveru da li je kompanija ili njeni korisnici **ugroženi** od **malvera koji krade informacije**.

Njihov primarni cilj WhiteIntela je borba protiv preuzimanja naloga i napada ransomvera koji proizilaze iz malvera koji krade informacije.

Možete posetiti njihovu veb lokaciju i isprobati njihov pretraživač **besplatno** na:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
