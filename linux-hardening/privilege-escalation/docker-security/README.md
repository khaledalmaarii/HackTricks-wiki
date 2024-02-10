# Docker bezbednost

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da lako izgradite i **automatizujete radne tokove** uz pomoć najnaprednijih alata zajednice.\
Danas dobijte pristup:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## **Osnovna bezbednost Docker Engine-a**

Docker engine koristi Linux kernel-ove **Namespaces** i **Cgroups** da izoluju kontejnere, pružajući osnovni nivo bezbednosti. Dodatna zaštita se obezbeđuje kroz **Capabilities dropping**, **Seccomp** i **SELinux/AppArmor**, poboljšavajući izolaciju kontejnera. **Auth plugin** može dodatno ograničiti korisničke akcije.

![Docker Security](https://sreeninet.files.wordpress.com/2016/03/dockersec1.png)

### Bezbedan pristup Docker Engine-u

Docker engine se može pristupiti lokalno putem Unix socket-a ili udaljeno putem HTTP-a. Za udaljeni pristup, neophodno je koristiti HTTPS i **TLS** kako bi se obezbedila poverljivost, integritet i autentifikacija.

Docker engine, po default-u, osluškuje Unix socket na `unix:///var/run/docker.sock`. Na Ubuntu sistemima, opcije pokretanja Docker-a se definišu u `/etc/default/docker`. Da biste omogućili udaljeni pristup Docker API-ju i klijentu, izložite Docker daemon preko HTTP socket-a dodavanjem sledećih podešavanja:
```bash
DOCKER_OPTS="-D -H unix:///var/run/docker.sock -H tcp://192.168.56.101:2376"
sudo service docker restart
```
Međutim, izlaganje Docker demona preko HTTP-a nije preporučljivo zbog sigurnosnih razloga. Preporučljivo je osigurati veze korišćenjem HTTPS-a. Postoje dva glavna pristupa osiguravanju veze:
1. Klijent proverava identitet servera.
2. Klijent i server međusobno proveravaju identitet.

Sertifikati se koriste za potvrdu identiteta servera. Za detaljne primere oba metoda, pogledajte [**ovaj vodič**](https://sreeninet.wordpress.com/2016/03/06/docker-security-part-3engine-access/).

### Sigurnost kontejnerskih slika

Kontejnerske slike mogu se čuvati u privatnim ili javnim repozitorijumima. Docker nudi nekoliko opcija za skladištenje kontejnerskih slika:

* **[Docker Hub](https://hub.docker.com)**: Javna registracija usluga od strane Docker-a.
* **[Docker Registry](https://github.com/docker/distribution)**: Open-source projekat koji omogućava korisnicima da hostuju sopstveni registar.
* **[Docker Trusted Registry](https://www.docker.com/docker-trusted-registry)**: Komercijalna registracija koju nudi Docker, sa autentifikacijom korisnika na osnovu uloga i integracijom sa LDAP direktorijumskim servisima.

### Skeniranje slika

Kontejneri mogu imati **sigurnosne ranjivosti** ili zbog osnovne slike ili zbog softvera instaliranog na osnovnoj slici. Docker radi na projektu pod nazivom **Nautilus** koji vrši sigurnosno skeniranje kontejnera i navodi ranjivosti. Nautilus radi tako što upoređuje svaki sloj slike kontejnera sa repozitorijumom ranjivosti kako bi identifikovao sigurnosne propuste.

Za više [**informacija pročitajte ovo**](https://docs.docker.com/engine/scan/).

* **`docker scan`**

Komanda **`docker scan`** omogućava vam skeniranje postojećih Docker slika koristeći ime ili ID slike. Na primer, pokrenite sledeću komandu da biste skenirali sliku hello-world:
```bash
docker scan hello-world

Testing hello-world...

Organization:      docker-desktop-test
Package manager:   linux
Project name:      docker-image|hello-world
Docker image:      hello-world
Licenses:          enabled

✓ Tested 0 dependencies for known issues, no vulnerable paths found.

Note that we do not currently have vulnerability data for your image.
```
* [**`trivy`**](https://github.com/aquasecurity/trivy)
```bash
trivy -q -f json <ontainer_name>:<tag>
```
* [**`snyk`**](https://docs.snyk.io/snyk-cli/getting-started-with-the-cli)
```bash
snyk container test <image> --json-file-output=<output file> --severity-threshold=high
```
* [**`clair-scanner`**](https://github.com/arminc/clair-scanner)
```bash
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
### Potpisivanje Docker slika

Potpisivanje Docker slika osigurava sigurnost i integritet slika koje se koriste u kontejnerima. Evo sažetog objašnjenja:

- **Docker Content Trust** koristi Notary projekat, zasnovan na The Update Framework (TUF), za upravljanje potpisivanjem slika. Za više informacija, pogledajte [Notary](https://github.com/docker/notary) i [TUF](https://theupdateframework.github.io).
- Da biste aktivirali Docker content trust, postavite `export DOCKER_CONTENT_TRUST=1`. Ova funkcionalnost je isključena po default-u u Docker verziji 1.10 i novijim.
- Sa ovom funkcionalnošću omogućenom, mogu se preuzimati samo potpisane slike. Inicijalno slanje slike zahteva postavljanje lozinki za root i tagging ključeve, pri čemu Docker takođe podržava Yubikey za poboljšanu sigurnost. Više detalja možete pronaći [ovde](https://blog.docker.com/2015/11/docker-content-trust-yubikey/).
- Pokušaj preuzimanja nepotpisane slike sa omogućenim content trust-om rezultira greškom "No trust data for latest".
- Za slanje slika nakon prvog puta, Docker traži lozinku za ključ repozitorijuma kako bi potpisao sliku.

Za bekapiranje privatnih ključeva, koristite komandu:
```bash
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
Prilikom prelaska na druge Docker hostove, neophodno je premestiti root i repozitorijum ključeva kako bi se održao rad.

***

<figure><img src="../../../.gitbook/assets/image (3) (1) (1) (1) (1).png" alt=""><figcaption></figcaption></figure>

\
Koristite [**Trickest**](https://trickest.com/?utm\_campaign=hacktrics\&utm\_medium=banner\&utm\_source=hacktricks) da biste lako izgradili i automatizovali radne tokove uz pomoć najnaprednijih alata zajednice.\
Dobijte pristup danas:

{% embed url="https://trickest.com/?utm_campaign=hacktrics&utm_medium=banner&utm_source=hacktricks" %}

## Funkcije bezbednosti kontejnera

<details>

<summary>Rezime funkcija bezbednosti kontejnera</summary>

### Glavne funkcije izolacije glavnog procesa

U kontejnerizovanim okruženjima, izolacija projekata i njihovih procesa je od suštinske važnosti za bezbednost i upravljanje resursima. Evo pojednostavljene objašnjenja ključnih koncepata:

#### **Namespaces**
- **Svrha**: Osiguravanje izolacije resursa poput procesa, mreže i fajl sistema. Posebno u Dockeru, namespaces čuvaju procese kontejnera odvojene od hosta i drugih kontejnera.
- **Korišćenje `unshare` komande**: Komanda `unshare` (ili odgovarajući sistemski poziv) se koristi za kreiranje novih namespaces, pružajući dodatni nivo izolacije. Međutim, iako Kubernetes inherentno ne blokira ovo, Docker to čini.
- **Ograničenje**: Kreiranje novih namespaces ne dozvoljava procesu da se vrati na podrazumevane namespaces hosta. Da bi se prodrlo u host namespaces, obično je potreban pristup `/proc` direktorijumu hosta, koristeći `nsenter` za ulazak.

#### **Control Groups (CGroups)**
- **Funkcija**: Pretežno se koristi za dodelu resursa među procesima.
- **Aspekt bezbednosti**: Sami CGroups ne pružaju bezbednost izolacije, osim funkcije `release_agent`, koja, ako nije pravilno konfigurisana, može biti iskorišćena za neovlašćeni pristup.

#### **Capability Drop**
- **Važnost**: To je ključna funkcija bezbednosti za izolaciju procesa.
- **Funkcionalnost**: Ograničava radnje koje root proces može izvršiti odbacivanjem određenih sposobnosti. Čak i ako proces radi sa privilegijama root-a, nedostatak potrebnih sposobnosti sprečava izvršavanje privilegovanih radnji, jer će sistemski pozivi biti neuspešni zbog nedovoljnih dozvola.

Ovo su **preostale sposobnosti** nakon što proces odbaci ostale:

{% code overflow="wrap" %}
```
Current: cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap=ep
```
{% endcode %}

**Seccomp**

Podrazumevano je omogućeno u Dockeru. Pomaže da se **još više ograniče syscalls** koje proces može pozvati.\
Podrazumevani Docker Seccomp profil može se pronaći na [https://github.com/moby/moby/blob/master/profiles/seccomp/default.json](https://github.com/moby/moby/blob/master/profiles/seccomp/default.json)

**AppArmor**

Docker ima predložak koji možete aktivirati: [https://github.com/moby/moby/tree/master/profiles/apparmor](https://github.com/moby/moby/tree/master/profiles/apparmor)

Ovo će omogućiti smanjenje mogućnosti, syscalls, pristup datotekama i fasciklama...

</details>

### Namespaces

**Namespaces** su funkcija Linux kernela koja **deli resurse kernela** tako da jedan skup **procesa vidi** jedan skup **resursa**, dok **drugi** skup **procesa** vidi **drugi** skup resursa. Ova funkcija radi tako što ima isti namespace za skup resursa i procesa, ali ti namespace-ovi se odnose na različite resurse. Resursi mogu postojati u više prostora.

Docker koristi sledeće Linux kernel Namespaces da bi postigao izolaciju kontejnera:

* pid namespace
* mount namespace
* network namespace
* ipc namespace
* UTS namespace

Za **više informacija o namespace-ovima** pogledajte sledeću stranicu:

{% content-ref url="namespaces/" %}
[namespaces](namespaces/)
{% endcontent-ref %}

### cgroups

Linux kernel funkcija **cgroups** omogućava ograničavanje resursa kao što su cpu, memorija, io, mrežna propusnost među skupom procesa. Docker omogućava kreiranje kontejnera koristeći cgroup funkciju koja omogućava kontrolu resursa za određeni kontejner.\
Sledeći je kontejner kreiran sa ograničenjem memorije u korisničkom prostoru na 500m, ograničenjem memorije kernela na 50m, deljenjem cpu-a na 512, blkioweight na 400. Deljenje cpu-a je odnos koji kontroliše upotrebu cpu-a kontejnera. Podrazumevana vrednost je 1024 i opseg između 0 i 1024. Ako tri kontejnera imaju isto deljenje cpu-a od 1024, svaki kontejner može koristiti do 33% cpu-a u slučaju sukoba resursa cpu-a. blkio-weight je odnos koji kontroliše IO kontejnera. Podrazumevana vrednost je 500 i opseg između 10 i 1000.
```
docker run -it -m 500M --kernel-memory 50M --cpu-shares 512 --blkio-weight 400 --name ubuntu1 ubuntu bash
```
Da biste dobili cgroup kontejnera, možete uraditi sledeće:
```bash
docker run -dt --rm denial sleep 1234 #Run a large sleep inside a Debian container
ps -ef | grep 1234 #Get info about the sleep process
ls -l /proc/<PID>/ns #Get the Group and the namespaces (some may be uniq to the hosts and some may be shred with it)
```
Za više informacija pogledajte:

{% content-ref url="cgroups.md" %}
[cgroups.md](cgroups.md)
{% endcontent-ref %}

### Mogućnosti

Mogućnosti omogućavaju **finu kontrolu mogućnosti koje se mogu dozvoliti** za korisnika root. Docker koristi mogućnost funkcionalnosti Linux kernela da **ograniči operacije koje se mogu izvršiti unutar kontejnera** bez obzira na vrstu korisnika.

Kada se pokrene Docker kontejner, **proces odbacuje osetljive mogućnosti koje proces može koristiti za izlazak iz izolacije**. Ovo pokušava da osigura da proces neće moći da izvrši osetljive radnje i izbegne:

{% content-ref url="../linux-capabilities.md" %}
[linux-capabilities.md](../linux-capabilities.md)
{% endcontent-ref %}

### Seccomp u Dockeru

Ovo je sigurnosna funkcionalnost koja omogućava Dockeru da **ograniči syscalls** koji se mogu koristiti unutar kontejnera:

{% content-ref url="seccomp.md" %}
[seccomp.md](seccomp.md)
{% endcontent-ref %}

### AppArmor u Dockeru

**AppArmor** je poboljšanje kernela koje ograničava **kontejnere** na **ograničen** skup **resursa** sa **profilima po programu**:

{% content-ref url="apparmor.md" %}
[apparmor.md](apparmor.md)
{% endcontent-ref %}

### SELinux u Dockeru

- **Sistem označavanja**: SELinux dodeljuje jedinstvenu oznaku svakom procesu i objektu datotečnog sistema.
- **Sprovođenje politike**: Sprovodi sigurnosne politike koje definišu koje radnje oznaka procesa mogu izvršiti nad drugim oznakama u sistemu.
- **Oznake procesa kontejnera**: Kada kontejnerski engine pokrene procese kontejnera, obično im se dodeljuje ograničena SELinux oznaka, obično `container_t`.
- **Oznake datoteka unutar kontejnera**: Datoteke unutar kontejnera obično su označene kao `container_file_t`.
- **Pravila politike**: SELinux politika pre svega osigurava da procesi sa oznakom `container_t` mogu samo da interaguju (čitaju, pišu, izvršavaju) sa datotekama označenim kao `container_file_t`.

Ovaj mehanizam osigurava da čak i ako je proces unutar kontejnera kompromitovan, ograničen je samo na interakciju sa objektima koji imaju odgovarajuće oznake, značajno ograničavajući potencijalnu štetu od takvih kompromitacija.

{% content-ref url="../selinux.md" %}
[selinux.md](../selinux.md)
{% endcontent-ref %}

### AuthZ & AuthN

U Dockeru, autorizacioni plugin igra ključnu ulogu u sigurnosti tako što odlučuje da li će dozvoliti ili blokirati zahteve ka Docker demonu. Ova odluka se donosi pregledom dva ključna konteksta:

- **Kontekst autentifikacije**: Ovo uključuje sveobuhvatne informacije o korisniku, kao što su ko su i kako su se autentifikovali.
- **Kontekst komande**: Ovo obuhvata sve relevantne podatke vezane za zahtev koji se pravi.

Ovi konteksti pomažu da se osigura da se obrađuju samo legitimni zahtevi od autentifikovanih korisnika, poboljšavajući sigurnost Docker operacija.

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## DoS iz kontejnera

Ako pravilno ne ograničavate resurse koje kontejner može koristiti, kompromitovani kontejner može izazvati DoS na hostu na kojem se izvršava.

* CPU DoS
```bash
# stress-ng
sudo apt-get install -y stress-ng && stress-ng --vm 1 --vm-bytes 1G --verify -t 5m

# While loop
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
```
* Bandwidth DoS

Bandwidth DoS (Denial of Service) is a type of attack that aims to exhaust the available bandwidth of a network or a specific target. This attack floods the target with a large volume of traffic, overwhelming its network resources and causing it to become unresponsive or slow down significantly.

The attacker typically uses multiple compromised devices or botnets to generate a massive amount of traffic towards the target. This can be achieved through techniques such as UDP flooding, ICMP flooding, or SYN flooding.

The impact of a Bandwidth DoS attack can be severe, as it can disrupt the normal functioning of a network or a specific service. It can lead to service downtime, loss of revenue, and damage to the reputation of the targeted organization.

To mitigate the risk of Bandwidth DoS attacks, network administrators can implement various measures such as traffic filtering, rate limiting, and traffic shaping. Additionally, monitoring network traffic patterns and implementing intrusion detection systems can help detect and mitigate such attacks in real-time.

It is important for organizations to regularly assess their network infrastructure's resilience against Bandwidth DoS attacks and implement appropriate security measures to protect against them.
```bash
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target IP> 4444; done
```
## Interesantne Docker zastavice

### --privileged zastavica

Na sledećoj stranici možete saznati **šta podrazumeva `--privileged` zastavica**:

{% content-ref url="docker-privileged.md" %}
[docker-privileged.md](docker-privileged.md)
{% endcontent-ref %}

### --security-opt

#### no-new-privileges

Ako pokrećete kontejner u kojem napadač uspe da pristupi kao korisnik sa niskim privilegijama. Ako imate **pogrešno konfigurisan suid binarni fajl**, napadač može zloupotrebiti to i **povećati privilegije unutar** kontejnera. Što mu može omogućiti da pobegne iz njega.

Pokretanje kontejnera sa omogućenom opcijom **`no-new-privileges`** će **sprečiti ovakvo povećanje privilegija**.
```
docker run -it --security-opt=no-new-privileges:true nonewpriv
```
#### Ostalo

Ovde su neke dodatne mere koje možete preduzeti kako biste poboljšali sigurnost Docker kontejnera:

- **Koristite najnoviju verziju Docker softvera**: Redovno ažurirajte Docker softver kako biste dobili najnovije sigurnosne ispravke i poboljšanja performansi.

- **Koristite samo pouzdane Docker slike**: Preuzimajte Docker slike samo sa pouzdanih izvora, kao što su zvanični Docker Hub ili provereni registri slika.

- **Proverite Dockerfile**: Pregledajte Dockerfile kako biste bili sigurni da ne postoji ništa sumnjivo ili potencijalno opasno.

- **Konfigurišite sigurnosne opcije**: Konfigurišite Docker da koristi sigurnosne opcije kao što su AppArmor ili SELinux kako biste ograničili privilegije kontejnera.

- **Koristite Docker Swarm ili Kubernetes**: Razmotrite korišćenje Docker Swarm ili Kubernetes za upravljanje kontejnerima, jer ove platforme pružaju dodatne sigurnosne funkcionalnosti.

- **Pratite Docker logove**: Redovno pratite Docker logove kako biste otkrili bilo kakve sumnjive aktivnosti ili pokušaje napada.

- **Koristite alate za skeniranje ranjivosti**: Koristite alate za skeniranje ranjivosti kako biste identifikovali i rešili potencijalne sigurnosne probleme u Docker kontejnerima.

- **Primenite princip najmanjih privilegija**: Dodelite samo neophodne privilegije Docker kontejnerima i korisnicima kako biste smanjili rizik od zloupotrebe.

- **Redovno ažurirajte i nadgledajte host sistem**: Redovno ažurirajte i nadgledajte host sistem na kojem se izvršavaju Docker kontejneri kako biste održali sigurnost celokupnog okruženja.

- **Edukujte korisnike**: Edukujte korisnike o sigurnom korišćenju Docker kontejnera i praksama koje treba da slede kako bi se izbegli sigurnosni propusti.

Napomena: Ove mere su samo neki od načina za poboljšanje sigurnosti Docker kontejnera i ne garantuju potpunu sigurnost. Uvek je važno pratiti najnovije sigurnosne smernice i preduzeti dodatne korake prema potrebi.
```bash
#You can manually add/drop capabilities with
--cap-add
--cap-drop

# You can manually disable seccomp in docker with
--security-opt seccomp=unconfined

# You can manually disable seccomp in docker with
--security-opt apparmor=unconfined

# You can manually disable selinux in docker with
--security-opt label:disable
```
Za više **`--security-opt`** opcija pogledajte: [https://docs.docker.com/engine/reference/run/#security-configuration](https://docs.docker.com/engine/reference/run/#security-configuration)

## Ostale bezbednosne razmatranja

### Upravljanje tajnama: Najbolje prakse

Izuzetno je važno izbegavati ugradnju tajni direktno u Docker slike ili korišćenje okružnih promenljivih, jer ovi metodi izlažu osetljive informacije svima koji imaju pristup kontejneru putem komandi poput `docker inspect` ili `exec`.

**Docker volumeni** su sigurnija alternativa, preporučena za pristupanje osetljivim informacijama. Mogu se koristiti kao privremeni fajl sistem u memoriji, smanjujući rizike povezane sa `docker inspect` i logovanjem. Međutim, korisnici sa root privilegijama i oni sa `exec` pristupom kontejneru i dalje mogu pristupiti tajnama.

**Docker tajne** pružaju još sigurniji način za rukovanje osetljivim informacijama. Za instance koje zahtevaju tajne tokom faze izgradnje slike, **BuildKit** predstavlja efikasno rešenje sa podrškom za tajne tokom izgradnje, poboljšavajući brzinu izgradnje i pružajući dodatne funkcionalnosti.

Da biste iskoristili BuildKit, može se aktivirati na tri načina:

1. Putem okružne promenljive: `export DOCKER_BUILDKIT=1`
2. Dodavanjem prefiksa komandama: `DOCKER_BUILDKIT=1 docker build .`
3. Omogućavanjem podrazumevano u Docker konfiguraciji: `{ "features": { "buildkit": true } }`, a zatim restartovanje Docker-a.

BuildKit omogućava korišćenje tajni tokom izgradnje sa opcijom `--secret`, obezbeđujući da ove tajne nisu uključene u keš izgradnje slike ili konačnu sliku, koristeći komandu poput:
```bash
docker build --secret my_key=my_value ,src=path/to/my_secret_file .
```
Za tajne potrebne u pokrenutom kontejneru, **Docker Compose i Kubernetes** nude pouzdana rešenja. Docker Compose koristi ključ `secrets` u definiciji servisa za specificiranje tajnih fajlova, kao što je prikazano u primeru `docker-compose.yml` fajla:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
Ova konfiguracija omogućava korišćenje tajni prilikom pokretanja usluga sa Docker Compose-om.

U Kubernetes okruženjima, tajne su podržane na nivou platforme i mogu se dalje upravljati alatima poput [Helm-Secrets](https://github.com/futuresimple/helm-secrets). Upravljanje tajnama u Kubernetes okruženjima je bezbednije zahvaljujući Role Based Access Controls (RBAC), slično kao i u Docker Enterprise.

### gVisor

**gVisor** je jezgro aplikacije, napisano u Go jeziku, koje implementira značajan deo Linux sistema. Uključuje [Open Container Initiative (OCI)](https://www.opencontainers.org) runtime pod nazivom `runsc` koji pruža **izolaciju između aplikacije i jezgra hosta**. `runsc` runtime se integriše sa Dockerom i Kubernetesom, što omogućava jednostavno pokretanje kontejnera u peskovniku.

{% embed url="https://github.com/google/gvisor" %}

### Kata Containers

**Kata Containers** je otvorena zajednica koja radi na izgradnji sigurnog runtime-a za kontejnere sa laganim virtuelnim mašinama koje se ponašaju i izvršavaju kao kontejneri, ali pružaju **jaču izolaciju radnog opterećenja korišćenjem tehnologije hardverske virtualizacije** kao drugog sloja odbrane.

{% embed url="https://katacontainers.io/" %}

### Saveti ukratko

* **Ne koristite `--privileged` flag ili montirajte** [**Docker socket unutar kontejnera**](https://raesene.github.io/blog/2016/03/06/The-Dangers-Of-Docker.sock/)**.** Docker socket omogućava pokretanje kontejnera, pa je to jednostavan način da se preuzme potpuna kontrola nad hostom, na primer, pokretanjem drugog kontejnera sa `--privileged` flagom.
* **Ne pokrećite kontejnere kao root korisnik. Koristite** [**različitog korisnika**](https://docs.docker.com/develop/develop-images/dockerfile\_best-practices/#user) **i** [**user namespaces**](https://docs.docker.com/engine/security/userns-remap/)**.** Root u kontejneru je isti kao na hostu, osim ako nije preimenovan pomoću user namespaces. On je samo delimično ograničen, pre svega, Linux namespaces, mogućnostima i cgroups.
* [**Isključite sve mogućnosti**](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities) **(`--cap-drop=all`) i omogućite samo one koje su potrebne** (`--cap-add=...`). Mnogi radni opterećenja ne zahtevaju nikakve mogućnosti, a dodavanje mogućnosti povećava opseg potencijalnih napada.
* [**Koristite opciju bez novih privilegija**](https://raesene.github.io/blog/2019/06/01/docker-capabilities-and-no-new-privs/) da biste sprečili procese da steknu više privilegija, na primer putem suid binarnih fajlova.
* [**Ograničite resurse dostupne kontejneru**](https://docs.docker.com/engine/reference/run/#runtime-constraints-on-resources)**.** Ograničenja resursa mogu zaštititi mašinu od napada uskraćivanjem usluge.
* **Prilagodite** [**seccomp**](https://docs.docker.com/engine/security/seccomp/)**,** [**AppArmor**](https://docs.docker.com/engine/security/apparmor/) **(ili SELinux)** profile da biste ograničili akcije i sistemski pozive dostupne kontejneru na minimum potrebnog.
* **Koristite** [**zvanične Docker slike**](https://docs.docker.com/docker-hub/official\_images/) **i zahtevajte potpise** ili izgradite sopstvene na osnovu njih. Ne nasleđujte ili ne koristite slike sa [backdoor-om](https://arstechnica.com/information-technology/2018/06/backdoored-images-downloaded-5-million-times-finally-removed-from-docker-hub/). Takođe, čuvajte root ključeve i lozinke na sigurnom mestu. Docker ima planove za upravljanje ključevima sa UCP.
* **Redovno** **ponovo izgradite** svoje slike kako biste primenili sigurnosne zakrpe na hostu i slikama.
* Mudro **upravljajte tajnama** kako bi bilo teško napadaču da im pristupi.
* Ako **izlažete Docker daemon, koristite HTTPS** sa autentifikacijom klijenta i servera.
* U Dockerfile-u, **koristite COPY umesto ADD**. ADD automatski raspakuje zipovane fajlove i može kopirati fajlove sa URL-ova. COPY nema ove mogućnosti. Kad god je moguće, izbegavajte korišćenje ADD kako ne biste bili podložni napadima putem udaljenih URL-ova i zip fajlova.
* Imajte **odvojene kontejnere za svaku mikro-uslugu**.
* **Ne koristite ssh** unutar kontejnera, "docker exec" se može koristiti za ssh ka kontejneru.
* Imajte **manje** slike kontejnera.

## Probijanje Docker-a / Eskalacija privilegija

Ako se nalazite **unutar Docker kontejnera** ili imate pristup korisniku u **docker grupi**, možete pokušati da **izađete iz kontejnera i eskalirate privilegije**:

{% content-ref url="docker-breakout-privilege-escalation/" %}
[docker-breakout-privilege-escalation](docker-breakout-privilege-escalation/)
{% endcontent-ref %}

## Bypass autentifikacije Docker plugin-a

Ako imate pristup Docker socket-u ili pristup korisniku u **docker grupi, ali su vaše akcije ograničene autentifikacionim plugin-om za Docker**, proverite da li možete ga **zaobići**:

{% content-ref url="authz-and-authn-docker-access-authorization-plugin.md" %}
[authz-and-authn-docker-access-authorization-plugin.md](authz-and-authn-docker-access-authorization-plugin.md)
{% endcontent-ref %}

## Ojačavanje Docker-a

* Alatka [**docker-bench-security**](https://github.com/docker/docker-bench-security) je skripta koja proverava desetine uobičajenih najboljih praksi prilikom implementacije Docker kontejnera u produkciji. Testovi su svi automatizovani i zasnovani na [CIS Docker Benchmark v1.3.1](https://www.cisecurity.org/benchmark/docker/).\
Potrebno je pokrenuti alatku sa hosta na kojem se izvršava Docker ili iz kontejnera sa dovoljnim privilegijama. Saznajte **kako je pokrenuti u README-u:** [**https://github.com/docker/docker-bench-security**](https://github.com/docker/docker-bench-security).

## Reference

* [https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)
* [https://twitter.com/\_fel1x/status/1151487051986087936](https://twitter.com/\_fel1x/status/115148705198608
Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu u HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, pogledajte [**PLANOVE PRETPLATE**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks suveniri**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
