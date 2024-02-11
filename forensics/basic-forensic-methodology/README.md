# Basiese Forensiese Metodologie

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

## Skep en Monteer 'n Beeld

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md" %}
[image-acquisition-and-mount.md](../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md)
{% endcontent-ref %}

## Malware-analise

Dit is **nie noodwendig die eerste stap om uit te voer nadat jy die beeld het nie**. Maar jy kan hierdie malware-analise tegnieke onafhanklik gebruik as jy 'n lêer, 'n lêerstelselbeeld, geheuebeeld, pcap... het, so dit is goed om **hierdie aksies in gedagte te hou**:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Inspekteer 'n Beeld

As jy 'n **forensiese beeld** van 'n toestel gekry het, kan jy begin **analiseer die partisies, lêerstelsel** wat gebruik word en **herwin** potensieel **interessante lêers** (selfs uitgewisde lêers). Leer hoe om dit te doen:

{% content-ref url="partitions-file-systems-carving/" %}
[partitions-file-systems-carving](partitions-file-systems-carving/)
{% endcontent-ref %}

Afhanklik van die gebruikte bedryfstelsels en selfs platforms moet verskillende interessante artefakte gesoek word:

{% content-ref url="windows-forensics/" %}
[windows-forensics](windows-forensics/)
{% endcontent-ref %}

{% content-ref url="linux-forensics.md" %}
[linux-forensics.md](linux-forensics.md)
{% endcontent-ref %}

{% content-ref url="docker-forensics.md" %}
[docker-forensics.md](docker-forensics.md)
{% endcontent-ref %}

## Diep inspeksie van spesifieke lêertipes en sagteware

As jy 'n baie **verdagte lêer** het, dan kan verskeie **truuks** nuttig wees, afhangende van die lêertipe en sagteware wat dit geskep het.\
Lees die volgende bladsy om 'n paar interessante truuks te leer:

{% content-ref url="specific-software-file-type-tricks/" %}
[specific-software-file-type-tricks](specific-software-file-type-tricks/)
{% endcontent-ref %}

Ek wil 'n spesiale vermelding maak van die bladsy:

{% content-ref url="specific-software-file-type-tricks/browser-artifacts.md" %}
[browser-artifacts.md](specific-software-file-type-tricks/browser-artifacts.md)
{% endcontent-ref %}

## Geheue-uitstorting-inspeksie

{% content-ref url="memory-dump-analysis/" %}
[memory-dump-analysis](memory-dump-analysis/)
{% endcontent-ref %}

## Pcap-inspeksie

{% content-ref url="pcap-inspection/" %}
[pcap-inspection](pcap-inspection/)
{% endcontent-ref %}

## **Anti-Forensiese Tegnieke**

Hou moontlike gebruik van anti-forensiese tegnieke in gedagte:

{% content-ref url="anti-forensic-techniques.md" %}
[anti-forensic-techniques.md](anti-forensic-techniques.md)
{% endcontent-ref %}

## Bedreigingsjag

{% content-ref url="file-integrity-monitoring.md" %}
[file-integrity-monitoring.md](file-integrity-monitoring.md)
{% endcontent-ref %}

<details>

<summary><strong>Leer AWS-hacking van nul tot held met</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Werk jy in 'n **cybersecurity-maatskappy**? Wil jy jou **maatskappy adverteer in HackTricks**? Of wil jy toegang hê tot die **nuutste weergawe van die PEASS of HackTricks aflaai in PDF-formaat**? Kyk na die [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Ontdek [**The PEASS Family**](https://opensea.io/collection/the-peass-family), ons versameling eksklusiewe [**NFTs**](https://opensea.io/collection/the-peass-family)
* Kry die [**amptelike PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Sluit aan by die** [**💬**](https://emojipedia.org/speech-balloon/) [**Discord-groep**](https://discord.gg/hRep4RUj7f) of die [**telegram-groep**](https://t.me/peass) of **volg** my op **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Deel jou hacking-truuks deur PR's in te dien by die [hacktricks repo](https://github.com/carlospolop/hacktricks) en [hacktricks-cloud repo](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
