# Docker forenzika

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Modifikacija kontejnera

Postoje sumnje da je neki docker kontejner kompromitovan:
```bash
docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
cc03e43a052a        lamp-wordpress      "./run.sh"          2 minutes ago       Up 2 minutes        80/tcp              wordpress
```
Možete lako **pronaći modifikacije urađene na ovom kontejneru u vezi sa slikom** sa:
```bash
docker diff wordpress
C /var
C /var/lib
C /var/lib/mysql
A /var/lib/mysql/ib_logfile0
A /var/lib/mysql/ib_logfile1
A /var/lib/mysql/ibdata1
A /var/lib/mysql/mysql
A /var/lib/mysql/mysql/time_zone_leap_second.MYI
A /var/lib/mysql/mysql/general_log.CSV
...
```
U prethodnoj komandi **C** znači **Promenjeno** a **A,** **Dodato**.\
Ako primetite da je neka zanimljiva datoteka poput `/etc/shadow` izmenjena, možete je preuzeti iz kontejnera radi provere zlonamernih aktivnosti sa:
```bash
docker cp wordpress:/etc/shadow.
```
Možete **uporediti sa originalnim** pokretanjem novog kontejnera i izvlačenjem fajla iz njega:
```bash
docker run -d lamp-wordpress
docker cp b5d53e8b468e:/etc/shadow original_shadow #Get the file from the newly created container
diff original_shadow shadow
```
Ako otkrijete da je **dodat sumnjiv fajl** možete pristupiti kontejneru i proveriti ga:
```bash
docker exec -it wordpress bash
```
## Modifikacije slika

Kada vam je dat izvezen Docker image (verovatno u `.tar` formatu) možete koristiti [**container-diff**](https://github.com/GoogleContainerTools/container-diff/releases) da **izvučete sažetak modifikacija**:
```bash
docker save <image> > image.tar #Export the image to a .tar file
container-diff analyze -t sizelayer image.tar
container-diff analyze -t history image.tar
container-diff analyze -t metadata image.tar
```
Zatim možete **dekompresovati** sliku i **pristupiti blobovima** kako biste pretražili sumnjive datoteke koje ste možda pronašli u istoriji promena:
```bash
tar -xf image.tar
```
### Osnovna analiza

Možete dobiti **osnovne informacije** o pokrenutoj slici:
```bash
docker inspect <image>
```
Takođe možete dobiti sažetak **istorije promena** sa:
```bash
docker history --no-trunc <image>
```
Takođe možete generisati **dockerfile iz slike** sa:
```bash
alias dfimage="docker run -v /var/run/docker.sock:/var/run/docker.sock --rm alpine/dfimage"
dfimage -sV=1.36 madhuakula/k8s-goat-hidden-in-layers>
```
### Uronite

Da biste pronašli dodate/izmenjene datoteke u Docker slikama, možete koristiti i [**dive**](https://github.com/wagoodman/dive) (preuzmite ga sa [**izdanja**](https://github.com/wagoodman/dive/releases/tag/v0.10.0)) alat:
```bash
#First you need to load the image in your docker repo
sudo docker load < image.tar                                                                                                                                                                                                         1 ⨯
Loaded image: flask:latest

#And then open it with dive:
sudo dive flask:latest
```
Ovo vam omogućava da **navigirate kroz različite blobove docker slika** i proverite koje datoteke su izmenjene/dodate. **Crvena** označava dodate, a **žuta** izmenjene datoteke. Koristite **tab** za prelazak na drugi prikaz i **razmak** za skupljanje/otvaranje foldera.

Pomoću ovoga nećete moći pristupiti sadržaju različitih faza slike. Da biste to uradili, moraćete **dekompresovati svaki sloj i pristupiti mu**.\
Možete dekompresovati sve slojeve slike iz direktorijuma gde je slika dekompresovana izvršavanjem:
```bash
tar -xf image.tar
for d in `find * -maxdepth 0 -type d`; do cd $d; tar -xf ./layer.tar; cd ..; done
```
## Kredencijali iz memorije

Imajte na umu da kada pokrenete docker kontejner unutar domaćina **možete videti procese koji se izvršavaju na kontejneru sa domaćina** jednostavno pokretanjem `ps -ef`

Stoga (kao root) možete **izbaciti memoriju procesa** sa domaćina i pretraživati **kredencijale** baš [**kao u sledećem primeru**](../../linux-hardening/privilege-escalation/#process-memory).
