# macOS Geheue Dumping

{% hint style="success" %}
Leer & oefen AWS Hack: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacktruuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **donkerweb**-aangedrewe soekenjin wat **gratis** funksies bied om te kontroleer of 'n maatskappy of sy kliënte deur **steelmalware** gekompromitteer is.

Die primêre doel van WhiteIntel is om rekeningoorname en lospryse-aanvalle te beveg wat voortspruit uit inligtingsteelmalware.

Jy kan hul webwerf besoek en hul enjin **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

***

## Geheue Artefakte

### Ruil Lêers

Ruil lêers, soos `/private/var/vm/swapfile0`, dien as **kasgeheue wanneer die fisiese geheue vol is**. Wanneer daar nie meer spasie in die fisiese geheue is nie, word die data na 'n ruil lêer oorgedra en dan weer na die fisiese geheue gebring as dit nodig is. Verskeie ruil lêers kan teenwoordig wees, met name soos swapfile0, swapfile1, ensovoorts.

### Hiberneer Beeld

Die lêer wat geleë is by `/private/var/vm/sleepimage` is noodsaaklik tydens **hibernasiemodus**. **Data vanaf die geheue word in hierdie lêer gestoor wanneer OS X hiberneer**. Met die ontwaking van die rekenaar haal die stelsel geheuedata uit hierdie lêer, sodat die gebruiker kan voortgaan waar hulle opgehou het.

Dit is die moeite werd om op te let dat op moderne MacOS-stelsels hierdie lêer tipies vir sekuriteitsredes versleutel is, wat herwinning moeilik maak.

* Om te kontroleer of versleuteling geaktiveer is vir die sleepimage, kan die opdrag `sysctl vm.swapusage` uitgevoer word. Dit sal wys of die lêer versleutel is.

### Geheue Druk Logs

'n Ander belangrike geheueverwante lêer in MacOS-stelsels is die **geheuedruklog**. Hierdie logboeke is geleë in `/var/log` en bevat gedetailleerde inligting oor die stelsel se geheuegebruik en drukgebeure. Dit kan veral nuttig wees vir die diagnose van geheueverwante probleme of om te verstaan hoe die stelsel oor tyd geheue bestuur.

## Dumping van geheue met osxpmem

Om die geheue in 'n MacOS-rekenaar te dump, kan jy [**osxpmem**](https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip) gebruik.

**Nota**: Die volgende instruksies sal slegs werk vir Macs met Intel-argitektuur. Hierdie instrument is nou gearchiveer en die laaste vrystelling was in 2017. Die binêre lêer wat met die instruksies hieronder afgelaai is, teiken Intel-skyfies omdat Apple Silicon nie in 2017 bestaan het nie. Dit mag moontlik wees om die binêre lêer vir arm64-argitektuur te kompileer, maar jy sal dit self moet probeer.
```bash
#Dump raw format
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem

#Dump aff4 format
sudo osxpmem.app/osxpmem -o /tmp/dump_mem.aff4
```
Indien jy hierdie fout vind: `osxpmem.app/MacPmem.kext kon nie laai nie - (libkern/kext) verifikasie mislukking (lêereienaarskap/permisies); kyk na die stelsel/kernel-logboeke vir foute of probeer kextutil(8)` Jy kan dit regmaak deur:
```bash
sudo cp -r osxpmem.app/MacPmem.kext "/tmp/"
sudo kextutil "/tmp/MacPmem.kext"
#Allow the kext in "Security & Privacy --> General"
sudo osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
**Ander foute** kan reggestel word deur **die laai van die kext toe te staan** in "Sekuriteit & Privaatheid --> Algemeen", net **staan** dit toe.

Jy kan ook hierdie **eenlynige kode** gebruik om die aansoek af te laai, die kext te laai en die geheue te dump:

{% code overflow="wrap" %}
```bash
sudo su
cd /tmp; wget https://github.com/google/rekall/releases/download/v1.5.1/osxpmem-2.1.post4.zip; unzip osxpmem-2.1.post4.zip; chown -R root:wheel osxpmem.app/MacPmem.kext; kextload osxpmem.app/MacPmem.kext; osxpmem.app/osxpmem --format raw -o /tmp/dump_mem
```
{% endcode %}

### [WhiteIntel](https://whiteintel.io)

<figure><img src="../../../.gitbook/assets/image (1227).png" alt=""><figcaption></figcaption></figure>

[**WhiteIntel**](https://whiteintel.io) is 'n **dark-web** aangedrewe soekenjin wat **gratis** funksies bied om te kontroleer of 'n maatskappy of sy kliënte deur **diewe malware** gekompromitteer is.

Hul primêre doel van WhiteIntel is om rekening-oorneemings en lospryse-aanvalle te beveg wat voortspruit uit inligting-diewe malware.

Jy kan hul webwerf besoek en hul enjin **gratis** probeer by:

{% embed url="https://whiteintel.io" %}

{% hint style="success" %}
Leer & oefen AWS Hack:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Opleiding AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hack: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Opleiding GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kontroleer die [**inskrywingsplanne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hack-truuks deur PR's in te dien by die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github-opslag.

</details>
{% endhint %}
