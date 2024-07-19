# Osnovna Forenzička Metodologija

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

## Kreiranje i Montiranje Slike

{% content-ref url="../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md" %}
[image-acquisition-and-mount.md](../../generic-methodologies-and-resources/basic-forensic-methodology/image-acquisition-and-mount.md)
{% endcontent-ref %}

## Analiza Malvera

Ovo **nije nužno prvi korak koji treba preduzeti kada imate sliku**. Ali možete koristiti ove tehnike analize malvera nezavisno ako imate datoteku, sliku datotečnog sistema, sliku memorije, pcap... tako da je dobro **imati na umu ove akcije**:

{% content-ref url="malware-analysis.md" %}
[malware-analysis.md](malware-analysis.md)
{% endcontent-ref %}

## Istraživanje Slike

Ako vam je data **forenzička slika** uređaja, možete početi **analizirati particije, datotečni sistem** koji se koristi i **opraviti** potencijalno **zanimljive datoteke** (čak i obrisane). Saznajte kako u:

{% content-ref url="partitions-file-systems-carving/" %}
[partitions-file-systems-carving](partitions-file-systems-carving/)
{% endcontent-ref %}

U zavisnosti od korišćenih OS-ova i čak platformi, različiti zanimljivi artefakti treba da se pretražuju:

{% content-ref url="windows-forensics/" %}
[windows-forensics](windows-forensics/)
{% endcontent-ref %}

{% content-ref url="linux-forensics.md" %}
[linux-forensics.md](linux-forensics.md)
{% endcontent-ref %}

{% content-ref url="docker-forensics.md" %}
[docker-forensics.md](docker-forensics.md)
{% endcontent-ref %}

## Dubinska Inspekcija Specifičnih Tipova Datoteka i Softvera

Ako imate veoma **sumnjivu** **datoteku**, onda **u zavisnosti od tipa datoteke i softvera** koji je kreirao, nekoliko **trikova** može biti korisno.\
Pročitajte sledeću stranicu da biste saznali neke zanimljive trikove:

{% content-ref url="specific-software-file-type-tricks/" %}
[specific-software-file-type-tricks](specific-software-file-type-tricks/)
{% endcontent-ref %}

Želim da posebno pomenem stranicu:

{% content-ref url="specific-software-file-type-tricks/browser-artifacts.md" %}
[browser-artifacts.md](specific-software-file-type-tricks/browser-artifacts.md)
{% endcontent-ref %}

## Inspekcija Dump-a Memorije

{% content-ref url="memory-dump-analysis/" %}
[memory-dump-analysis](memory-dump-analysis/)
{% endcontent-ref %}

## Inspekcija Pcap-a

{% content-ref url="pcap-inspection/" %}
[pcap-inspection](pcap-inspection/)
{% endcontent-ref %}

## **Anti-forenzičke Tehnike**

Imajte na umu moguću upotrebu anti-forenzičkih tehnika:

{% content-ref url="anti-forensic-techniques.md" %}
[anti-forensic-techniques.md](anti-forensic-techniques.md)
{% endcontent-ref %}

## Lov na Pretnje

{% content-ref url="file-integrity-monitoring.md" %}
[file-integrity-monitoring.md](file-integrity-monitoring.md)
{% endcontent-ref %}

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
