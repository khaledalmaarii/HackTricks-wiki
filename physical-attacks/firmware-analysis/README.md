# Firmware Analysis

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

## **Introduction**

Firmware is essensiële sagteware wat toestelle in staat stel om korrek te werk deur kommunikasie tussen die hardewarekomponente en die sagteware waarmee gebruikers interaksie het, te bestuur en te fasiliteer. Dit word in permanente geheue gestoor, wat verseker dat die toestel toegang kan verkry tot noodsaaklike instruksies vanaf die oomblik dat dit aangeskakel word, wat lei tot die opstart van die bedryfstelsel. Om firmware te ondersoek en moontlik te wysig, is 'n kritieke stap in die identifisering van sekuriteitskwesbaarhede.

## **Gathering Information**

**Inligting versameling** is 'n kritieke aanvanklike stap in die begrip van 'n toestel se samestelling en die tegnologieë wat dit gebruik. Hierdie proses behels die versameling van data oor:

- Die CPU-argitektuur en bedryfstelsel wat dit gebruik
- Bootloader spesifikasies
- Hardeware uitleg en datasheets
- Codebase metrieke en bronliggings
- Eksterne biblioteke en lisensietipes
- Opdatering geskiedenisse en regulerende sertifikate
- Argitektoniese en vloediagramme
- Sekuriteitsassessering en geïdentifiseerde kwesbaarhede

Vir hierdie doel is **oopbron intelligensie (OSINT)** gereedskap van onskatbare waarde, sowel as die analise van enige beskikbare oopbron sagtewarekomponente deur handmatige en geoutomatiseerde hersieningsprosesse. Gereedskap soos [Coverity Scan](https://scan.coverity.com) en [Semmle’s LGTM](https://lgtm.com/#explore) bied gratis statiese analise wat benut kan word om potensiële probleme te vind.

## **Acquiring the Firmware**

Om firmware te verkry kan op verskeie maniere benader word, elk met sy eie vlak van kompleksiteit:

- **Direk** van die bron (ontwikkelaars, vervaardigers)
- **Bou** dit volgens verskafde instruksies
- **Aflaai** van amptelike ondersteuningswebwerwe
- Gebruik **Google dork** navrae om gehoste firmware-lêers te vind
- Toegang tot **cloud storage** direk, met gereedskap soos [S3Scanner](https://github.com/sa7mon/S3Scanner)
- Interseptering van **opdaterings** via man-in-the-middle tegnieke
- **Ekstrak** van die toestel deur verbindings soos **UART**, **JTAG**, of **PICit**
- **Sniffing** vir opdateringsversoeke binne toestelkommunikasie
- Identifisering en gebruik van **hardcoded update endpoints**
- **Dumping** van die bootloader of netwerk
- **Verwydering en lees** van die stoorchip, wanneer alles anders misluk, met toepaslike hardeware gereedskap

## Analyzing the firmware

Nou dat jy **die firmware het**, moet jy inligting daaroor onttrek om te weet hoe om dit te behandel. Verskillende gereedskap wat jy daarvoor kan gebruik:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #print offsets in hex
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head # might find signatures in header
fdisk -lu <bin> #lists a drives partition and filesystems if multiple
```
If you don't find much with those tools check the **entropy** of the image with `binwalk -E <bin>`, if low entropy, then it's not likely to be encrypted. If high entropy, Its likely encrypted (or compressed in some way).

Boonop, jy kan hierdie gereedskap gebruik om **lêers ingebed binne die firmware** te onttrek:

{% content-ref url="../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md" %}
[file-data-carving-recovery-tools.md](../../forensics/basic-forensic-methodology/partitions-file-systems-carving/file-data-carving-recovery-tools.md)
{% endcontent-ref %}

Of [**binvis.io**](https://binvis.io/#/) ([code](https://code.google.com/archive/p/binvis/)) om die lêer te inspekteer.

### Getting the Filesystem

Met die vorige kommentaar gereedskap soos `binwalk -ev <bin>` behoort jy in staat te wees om die **lêerstelsel** te **onttrek**.\
Binwalk onttrek dit gewoonlik binne 'n **map genaamd soos die lêerstelseltipe**, wat gewoonlik een van die volgende is: squashfs, ubifs, romfs, rootfs, jffs2, yaffs2, cramfs, initramfs.

#### Manual Filesystem Extraction

Soms, binwalk sal **nie die magiese byte van die lêerstelsel in sy handtekeninge hê nie**. In hierdie gevalle, gebruik binwalk om die **offset van die lêerstelsel te vind en die gecomprimeerde lêerstelsel** uit die binêre te **karve** en die lêerstelsel volgens sy tipe te **onttrek** met die stappe hieronder.
```
$ binwalk DIR850L_REVB.bin

DECIMAL HEXADECIMAL DESCRIPTION
----------------------------------------------------------------------------- ---

0 0x0 DLOB firmware header, boot partition: """"dev=/dev/mtdblock/1""""
10380 0x288C LZMA compressed data, properties: 0x5D, dictionary size: 8388608 bytes, uncompressed size: 5213748 bytes
1704052 0x1A0074 PackImg section delimiter tag, little endian size: 32256 bytes; big endian size: 8257536 bytes
1704084 0x1A0094 Squashfs filesystem, little endian, version 4.0, compression:lzma, size: 8256900 bytes, 2688 inodes, blocksize: 131072 bytes, created: 2016-07-12 02:28:41
```
Voer die volgende **dd-opdrag** uit om die Squashfs-lêerstelsel te sny.
```
$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs

8257536+0 records in

8257536+0 records out

8257536 bytes (8.3 MB, 7.9 MiB) copied, 12.5777 s, 657 kB/s
```
Alternatiewelik kan die volgende opdrag ook uitgevoer word.

`$ dd if=DIR850L_REVB.bin bs=1 skip=$((0x1A0094)) of=dir.squashfs`

* Vir squashfs (gebruik in die voorbeeld hierbo)

`$ unsquashfs dir.squashfs`

Lêers sal in die "`squashfs-root`" gids wees daarna.

* CPIO argief lêers

`$ cpio -ivd --no-absolute-filenames -F <bin>`

* Vir jffs2 lêerstelsels

`$ jefferson rootfsfile.jffs2`

* Vir ubifs lêerstelsels met NAND flash

`$ ubireader_extract_images -u UBI -s <start_offset> <bin>`

`$ ubidump.py <bin>`


## Analise van Firmware

Sodra die firmware verkry is, is dit noodsaaklik om dit te ontleed om die struktuur en potensiële kwesbaarhede te verstaan. Hierdie proses behels die gebruik van verskeie gereedskap om waardevolle data uit die firmware beeld te analiseer en te onttrek.

### Begin Analise Gereedskap

'n Stel opdragte word verskaf vir die aanvanklike inspeksie van die binêre lêer (verwys na `<bin>`). Hierdie opdragte help om lêertipes te identifiseer, stringe te onttrek, binêre data te analiseer, en die partisie en lêerstelsel besonderhede te verstaan:
```bash
file <bin>
strings -n8 <bin>
strings -tx <bin> #prints offsets in hexadecimal
hexdump -C -n 512 <bin> > hexdump.out
hexdump -C <bin> | head #useful for finding signatures in the header
fdisk -lu <bin> #lists partitions and filesystems, if there are multiple
```
Om die versleutelingstatus van die beeld te evalueer, word die **entropy** nagegaan met `binwalk -E <bin>`. Lae entropy dui op 'n gebrek aan versleuteling aan, terwyl hoë entropy moontlike versleuteling of kompressie aandui.

Vir die onttrekking van **embedded files**, word gereedskap en hulpbronne soos die **file-data-carving-recovery-tools** dokumentasie en **binvis.io** vir lêerinspeksie aanbeveel.

### Onttrekking van die Filesystem

Met `binwalk -ev <bin>` kan 'n mens gewoonlik die filesystem onttrek, dikwels in 'n gids wat na die filesystem tipe genoem is (bv. squashfs, ubifs). As **binwalk** egter nie die filesystem tipe kan herken nie weens ontbrekende magic bytes, is handmatige onttrekking nodig. Dit behels die gebruik van `binwalk` om die filesystem se offset te lokaliseer, gevolg deur die `dd` opdrag om die filesystem uit te sny:
```bash
$ binwalk DIR850L_REVB.bin

$ dd if=DIR850L_REVB.bin bs=1 skip=1704084 of=dir.squashfs
```
```markdown
Daarna, afhangende van die lêerstelseltipe (bv., squashfs, cpio, jffs2, ubifs), word verskillende opdragte gebruik om die inhoud handmatig te onttrek.

### Lêerstelselanalise

Met die lêerstelsel onttrek, begin die soektog na sekuriteitsfoute. Aandag word gegee aan onveilige netwerk daemons, hardcoded akrediteerbesonderhede, API eindpunte, opdatering bediener funksies, ongecompileerde kode, opstart skripte, en gecompileerde binêre vir offline analise.

**Belangrike plekke** en **items** om te inspekteer sluit in:

- **etc/shadow** en **etc/passwd** vir gebruikers akrediteerbesonderhede
- SSL sertifikate en sleutels in **etc/ssl**
- Konfigurasie en skrip lêers vir potensiële kwesbaarhede
- Ingebedde binêre vir verdere analise
- Algemene IoT toestel webbedieners en binêre

Verskeie gereedskap help om sensitiewe inligting en kwesbaarhede binne die lêerstelsel te ontdek:

- [**LinPEAS**](https://github.com/carlospolop/PEASS-ng) en [**Firmwalker**](https://github.com/craigz28/firmwalker) vir sensitiewe inligting soektog
- [**The Firmware Analysis and Comparison Tool (FACT)**](https://github.com/fkie-cad/FACT\_core) vir omvattende firmware analise
- [**FwAnalyzer**](https://github.com/cruise-automation/fwanalyzer), [**ByteSweep**](https://gitlab.com/bytesweep/bytesweep), [**ByteSweep-go**](https://gitlab.com/bytesweep/bytesweep-go), en [**EMBA**](https://github.com/e-m-b-a/emba) vir statiese en dinamiese analise

### Sekuriteitskontroles op Gecompileerde Binêre

Sowel die bronkode as gecompileerde binêre wat in die lêerstelsel gevind word, moet ondersoek word vir kwesbaarhede. Gereedskap soos **checksec.sh** vir Unix binêre en **PESecurity** vir Windows binêre help om onbeskermde binêre te identifiseer wat uitgebuit kan word.

## Emulering van Firmware vir Dynamiese Analise

Die proses van emulering van firmware stel **dynamiese analise** in staat, hetsy van 'n toestel se werking of 'n individuele program. Hierdie benadering kan uitdagings ondervind met hardeware of argitektuur afhanklikhede, maar die oordrag van die wortellêerstelsel of spesifieke binêre na 'n toestel met ooreenstemmende argitektuur en endianness, soos 'n Raspberry Pi, of na 'n voorafgeboude virtuele masjien, kan verdere toetsing fasiliteer.

### Emulering van Individuele Binêre

Vir die ondersoek van enkele programme, is dit van kardinale belang om die program se endianness en CPU argitektuur te identifiseer.

#### Voorbeeld met MIPS Argitektuur

Om 'n MIPS argitektuur binêre te emuleer, kan 'n mens die opdrag gebruik:
```
```bash
file ./squashfs-root/bin/busybox
```
En om die nodige emulasie-instrumente te installeer:
```bash
sudo apt-get install qemu qemu-user qemu-user-static qemu-system-arm qemu-system-mips qemu-system-x86 qemu-utils
```
For MIPS (big-endian), `qemu-mips` word gebruik, en vir little-endian binaries, `qemu-mipsel` sou die keuse wees.

#### ARM Argitektuur Emulasie

Vir ARM binaries is die proses soortgelyk, met die `qemu-arm` emulator wat gebruik word vir emulasie.

### Volle Stelsel Emulasie

Gereedskap soos [Firmadyne](https://github.com/firmadyne/firmadyne), [Firmware Analysis Toolkit](https://github.com/attify/firmware-analysis-toolkit), en ander, fasiliteer volle firmware emulasie, outomatiseer die proses en help met dinamiese analise.

## Dinamiese Analise in Praktyk

Op hierdie stadium word 'n werklike of geëmuleerde toestelomgewing vir analise gebruik. Dit is noodsaaklik om shell-toegang tot die OS en lêerstelsel te handhaaf. Emulasie mag nie perfek hardeware-interaksies naboots nie, wat af en toe emulasie-herlaai vereis. Analise moet die lêerstelsel herbesoek, blootgestelde webbladsye en netwerkdienste benut, en opstartlader kwesbaarhede verken. Firmware integriteitstoetse is krities om potensiële agterdeur kwesbaarhede te identifiseer.

## Tydren Analise Tegnieke

Tydren analise behels interaksie met 'n proses of binary in sy bedryfsomgewing, met behulp van gereedskap soos gdb-multiarch, Frida, en Ghidra om breekpunte in te stel en kwesbaarhede te identifiseer deur middel van fuzzing en ander tegnieke.

## Binary Exploitatie en Bewys-van-Konsep

Om 'n PoC vir geïdentifiseerde kwesbaarhede te ontwikkel, vereis 'n diep begrip van die teikenargitektuur en programmering in laervlak tale. Binary tydren beskermings in ingebedde stelsels is skaars, maar wanneer dit teenwoordig is, mag tegnieke soos Return Oriented Programming (ROP) nodig wees.

## Voorbereide Bedryfstelsels vir Firmware Analise

Bedryfstelsels soos [AttifyOS](https://github.com/adi0x90/attifyos) en [EmbedOS](https://github.com/scriptingxss/EmbedOS) bied vooraf-gekonfigureerde omgewings vir firmware sekuriteitstoetsing, toegerus met nodige gereedskap.

## Voorbereide OS's om Firmware te analiseer

* [**AttifyOS**](https://github.com/adi0x90/attifyos): AttifyOS is 'n distro wat bedoel is om jou te help om sekuriteitsassessering en penetrasietoetsing van Internet of Things (IoT) toestelle uit te voer. Dit bespaar jou baie tyd deur 'n vooraf-gekonfigureerde omgewing met al die nodige gereedskap te bied.
* [**EmbedOS**](https://github.com/scriptingxss/EmbedOS): Ingebedde sekuriteitstoetsing bedryfstelsel gebaseer op Ubuntu 18.04 wat vooraf gelaai is met firmware sekuriteitstoetsing gereedskap.

## Kwetsbare firmware om te oefen

Om kwesbaarhede in firmware te ontdek, gebruik die volgende kwesbare firmware projekte as 'n beginpunt.

* OWASP IoTGoat
* [https://github.com/OWASP/IoTGoat](https://github.com/OWASP/IoTGoat)
* The Damn Vulnerable Router Firmware Project
* [https://github.com/praetorian-code/DVRF](https://github.com/praetorian-code/DVRF)
* Damn Vulnerable ARM Router (DVAR)
* [https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html](https://blog.exploitlab.net/2018/01/dvar-damn-vulnerable-arm-router.html)
* ARM-X
* [https://github.com/therealsaumil/armx#downloads](https://github.com/therealsaumil/armx#downloads)
* Azeria Labs VM 2.0
* [https://azeria-labs.com/lab-vm-2-0/](https://azeria-labs.com/lab-vm-2-0/)
* Damn Vulnerable IoT Device (DVID)
* [https://github.com/Vulcainreo/DVID](https://github.com/Vulcainreo/DVID)

## Verwysings

* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)
* [Practical IoT Hacking: The Definitive Guide to Attacking the Internet of Things](https://www.amazon.co.uk/Practical-IoT-Hacking-F-Chantzis/dp/1718500904)

## Opleiding en Sertifikaat

* [https://www.attify-store.com/products/offensive-iot-exploitation](https://www.attify-store.com/products/offensive-iot-exploitation)

{% hint style="success" %}
Leer & oefen AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Leer & oefen GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Ondersteun HackTricks</summary>

* Kyk na die [**subskripsie planne**](https://github.com/sponsors/carlospolop)!
* **Sluit aan by die** 💬 [**Discord groep**](https://discord.gg/hRep4RUj7f) of die [**telegram groep**](https://t.me/peass) of **volg** ons op **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Deel hacking truuks deur PRs in te dien na die** [**HackTricks**](https://github.com/carlospolop/hacktricks) en [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
