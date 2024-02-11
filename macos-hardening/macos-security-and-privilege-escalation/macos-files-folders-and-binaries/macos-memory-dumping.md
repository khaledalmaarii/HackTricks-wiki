# macOS-geheue-dump

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy jou **maatskappy in HackTricks wil adverteer** of **HackTricks in PDF wil aflaai**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacktruuks deur PRs in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-repos.

</details>

## Geheue-artefakte

### Ruil-lêers

Ruil-lêers, soos `/private/var/vm/swapfile0`, dien as **kasgeheue wanneer die fisiese geheue vol is**. Wanneer daar geen spasie meer in die fisiese geheue is nie, word die data na 'n ruil-lêer oorgedra en dan weer na die fisiese geheue gebring as dit nodig is. Daar kan verskeie ruil-lêers teenwoordig wees, met name soos swapfile0, swapfile1, en so aan.

### Hibernasie-beeld

Die lêer wat by `/private/var/vm/sleepimage` geleë is, is krities tydens **hibernasie-modus**. **Data vanaf die geheue word in hierdie lêer gestoor wanneer OS X hibernasie ondergaan**. Wanneer die rekenaar wakker word, haal die stelsel geheuedata uit hierdie lêer, sodat die gebruiker kan voortgaan waar hy opgehou het.

Dit is die moeite werd om daarop te let dat hierdie lêer op moderne MacOS-stelsels tipies vir veiligheidsredes versleutel is, wat herwinning moeilik maak.

* Om te kontroleer of versleuteling geaktiveer is vir die sleepimage, kan die opdrag `sysctl vm.swapusage` uitgevoer word. Dit sal wys of die lêer versleutel is.

### Geheuedruk-logboeke

'n Ander belangrike geheue-verwante lêer in MacOS-stelsels is die **geheuedruk-logboeke**. Hierdie logboeke is geleë in `/var/log` en bevat gedetailleerde inligting oor die stelsel se geheuegebruik en drukgebeure. Dit kan besonder nuttig wees vir die diagnose van geheue-verwante probleme of om te verstaan hoe die stelsel oor tyd geheue bestuur.

## Geheue dump met osxpmem

Om die geheue in 'n MacOS-rekenaar te dump, kan jy [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) gebruik.

**Let op**: Die volgende instruksies sal slegs werk vir Macs met Intel-argitektuur. Hierdie instrument is nou gearchiveer en die laaste vrystelling was in 2017. Die binêre lêer wat deur die instruksies hieronder afgelaai word, is gemik op Intel-skyfies omdat Apple Silicon nie in 2017 bestaan het nie. Dit mag moontlik wees om die binêre lêer vir arm64-argitektuur te kompileer, maar jy sal dit self moet probeer.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
As jy hierdie fout vind: `osxpmem.app/MacPmem.kext kon nie gelaai word nie - (libkern/kext) verifikasie mislukking (lêer eienaarskap/permisies); kyk na die stelsel/kernel-logboeke vir foute of probeer kextutil(8)` Jy kan dit regmaak deur:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Ander foute** kan opgelos word deur die **laai van die kext** toe te staan in "Security & Privacy --> Algemeen", staan dit net **toe**.

Jy kan ook hierdie **oneliner** gebruik om die toepassing af te laai, die kext te laai en die geheue te dump:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Ander maniere om HackTricks te ondersteun:

* As jy wil sien dat jou **maatskappy geadverteer word in HackTricks** of **HackTricks aflaai in PDF-formaat**, kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-opslagplekke.

</details>
