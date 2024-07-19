# macOS xpc\_connection\_get\_audit\_token Attack

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

**For further information check the original post:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). This is a summary:

## Mach Messages Basic Info

If you don't know what Mach Messages are start checking this page:

{% content-ref url="../../" %}
[..](../../)
{% endcontent-ref %}

For the moment remember that ([definition from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach poruke se šalju preko _mach porta_, koji je **kanal komunikacije sa jednim prijemnikom i više pošiljalaca** ugrađen u mach kernel. **Više procesa može slati poruke** na mach port, ali u bilo kojem trenutku **samo jedan proces može čitati iz njega**. Baš kao i deskriptori datoteka i soketi, mach portovi se dodeljuju i upravljaju od strane kernela, a procesi vide samo ceo broj, koji mogu koristiti da označe kernelu koji od svojih mach portova žele da koriste.

## XPC Connection

If you don't know how a XPC connection is established check:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Vuln Summary

What is interesting for you to know is that **XPC’s abstraction is a one-to-one connection**, but it is based on top of a technology which **can have multiple senders, so:**

* Mach portovi su jedini prijemnik, **više pošiljalaca**.
* Audit token XPC veze je audit token **kopiran iz najnovije primljene poruke**.
* Dobijanje **audit token** XPC veze je ključno za mnoge **provere bezbednosti**.

Although the previous situation sounds promising there are some scenarios where this is not going to cause problems ([from here](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Audit tokeni se često koriste za proveru autorizacije da odluče da li da prihvate vezu. Kako se to dešava koristeći poruku na servisnom portu, **veza još nije uspostavljena**. Više poruka na ovom portu će se samo obraditi kao dodatni zahtevi za vezu. Dakle, sve **provere pre prihvatanja veze nisu ranjive** (to takođe znači da unutar `-listener:shouldAcceptNewConnection:` audit token je siguran). Stoga **tražimo XPC veze koje verifikuju specifične akcije**.
* XPC rukovaoci događajima se obrađuju sinhrono. To znači da rukovalac događajem za jednu poruku mora biti završen pre nego što se pozove za sledeću, čak i na konkurentnim redovima za raspodelu. Dakle, unutar **XPC rukovaoca događajem audit token ne može biti prepisan** drugim normalnim (ne-odgovor!) porukama.

Two different methods this might be exploitable:

1. Variant1:
* **Eksploit** **se povezuje** na servis **A** i servis **B**
* Servis **B** može pozvati **privilegovan funkcionalnost** u servisu A koju korisnik ne može
* Servis **A** poziva **`xpc_connection_get_audit_token`** dok _**nije**_ unutar **rukovaoca događajem** za vezu u **`dispatch_async`**.
* Tako bi **druga** poruka mogla **prepisati Audit Token** jer se šalje asinhrono van rukovaoca događajem.
* Eksploit prosleđuje **servisu B pravo SLANJA servisu A**.
* Tako će svc **B** zapravo **slati** **poruke** servisu **A**.
* **Eksploit** pokušava da **pozove** **privilegovanu akciju.** U RC svc **A** **proverava** autorizaciju ove **akcije** dok **svc B prepisuje Audit token** (dajući eksploitu pristup da pozove privilegovanu akciju).
2. Variant 2:
* Servis **B** može pozvati **privilegovan funkcionalnost** u servisu A koju korisnik ne može
* Eksploit se povezuje sa **servisom A** koji **šalje** eksploitu **poruku očekujući odgovor** u specifičnom **portu za odgovor**.
* Eksploit šalje **servisu** B poruku prosleđujući **taj port za odgovor**.
* Kada servis **B odgovara**, on **šalje poruku servisu A**, **dok** **eksploit** šalje drugačiju **poruku servisu A** pokušavajući da **dođe do privilegovane funkcionalnosti** i očekujući da će odgovor servisa B prepisati Audit token u savršenom trenutku (Race Condition).

## Variant 1: calling xpc\_connection\_get\_audit\_token outside of an event handler <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

* Dva mach servisa **`A`** i **`B`** na koja se možemo povezati (na osnovu profila sandboxes i provere autorizacije pre prihvatanja veze).
* _**A**_ mora imati **proveru autorizacije** za specifičnu akciju koju **`B`** može proći (ali naša aplikacija ne može).
* Na primer, ako B ima neka **prava** ili radi kao **root**, to bi mu moglo omogućiti da zatraži od A da izvrši privilegovanu akciju.
* Za ovu proveru autorizacije, **`A`** dobija audit token asinhrono, na primer pozivajući `xpc_connection_get_audit_token` iz **`dispatch_async`**.

{% hint style="danger" %}
U ovom slučaju, napadač bi mogao izazvati **Race Condition** praveći **eksploit** koji **traži od A da izvrši akciju** više puta dok **B šalje poruke `A`**. Kada je RC **uspešan**, **audit token** **B** će biti kopiran u memoriji **dok** se zahtev našeg **eksploita** obrađuje od strane A, dajući mu **pristup privilegovanoj akciji koju je samo B mogao zatražiti**.
{% endhint %}

Ovo se dogodilo sa **`A`** kao `smd` i **`B`** kao `diagnosticd`. Funkcija [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) iz smb može se koristiti za instalaciju novog privilegovanog pomoćnog alata (kao **root**). Ako **proces koji radi kao root kontaktira** **smd**, neće se izvršiti druge provere.

Stoga, servis **B** je **`diagnosticd`** jer radi kao **root** i može se koristiti za **praćenje** procesa, tako da kada praćenje počne, on će **slati više poruka u sekundi.**

Da bi se izvršio napad:

1. Inicirajte **vezu** sa servisom nazvanim `smd` koristeći standardni XPC protokol.
2. Formirajte sekundarnu **vezu** sa `diagnosticd`. Suprotno normalnoj proceduri, umesto da kreira i šalje dva nova mach porta, pravo slanja klijentskog porta se zamenjuje duplikatom **prava slanja** povezanog sa `smd` vezom.
3. Kao rezultat, XPC poruke mogu se slati `diagnosticd`, ali odgovori iz `diagnosticd` se preusmeravaju na `smd`. Za `smd`, izgleda kao da poruke od korisnika i `diagnosticd` potiču iz iste veze.

![Image depicting the exploit process](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Sledeći korak uključuje davanje instrukcija `diagnosticd` da započne praćenje odabranog procesa (potencijalno korisnikovog). Paralelno, poplava rutinskih 1004 poruka se šalje `smd`. Cilj ovde je instalirati alat sa povišenim privilegijama.
5. Ova akcija pokreće trku uslov unutar funkcije `handle_bless`. Tajming je kritičan: poziv funkcije `xpc_connection_get_pid` mora vratiti PID korisnikovog procesa (jer se privilegovani alat nalazi u korisničkom paketu aplikacije). Međutim, funkcija `xpc_connection_get_audit_token`, posebno unutar podrutine `connection_is_authorized`, mora se pozivati na audit token koji pripada `diagnosticd`.

## Variant 2: reply forwarding

U XPC (komunikacija između procesa) okruženju, iako rukovaoci događajima ne izvršavaju se konkurentno, obrada odgovarajućih poruka ima jedinstveno ponašanje. Konkretno, postoje dva različita metoda za slanje poruka koje očekuju odgovor:

1. **`xpc_connection_send_message_with_reply`**: Ovde se XPC poruka prima i obrađuje na određenoj redi.
2. **`xpc_connection_send_message_with_reply_sync`**: Suprotno tome, u ovoj metodi, XPC poruka se prima i obrađuje na trenutnoj redi za raspodelu.

Ova razlika je ključna jer omogućava mogućnost da **paketi odgovora budu obrađeni konkurentno sa izvršenjem XPC rukovaoca događajem**. Važno je napomenuti da, iako `_xpc_connection_set_creds` implementira zaključavanje kako bi se zaštitilo od delimičnog prepisivanja audit tokena, ova zaštita se ne proširuje na ceo objekat veze. Kao rezultat, to stvara ranjivost gde audit token može biti zamenjen tokom intervala između obrade paketa i izvršenja njegovog rukovaoca događajem.

Da bi se iskoristila ova ranjivost, potrebna je sledeća postavka:

* Dva mach servisa, nazvana **`A`** i **`B`**, oba od kojih mogu uspostaviti vezu.
* Servis **`A`** treba da uključuje proveru autorizacije za specifičnu akciju koju samo **`B`** može izvršiti (korisnička aplikacija ne može).
* Servis **`A`** treba da pošalje poruku koja očekuje odgovor.
* Korisnik može poslati poruku **`B`** na koju će odgovoriti.

Proces eksploatacije uključuje sledeće korake:

1. Sačekajte da servis **`A`** pošalje poruku koja očekuje odgovor.
2. Umesto da direktno odgovara **`A`**, port za odgovor se otima i koristi za slanje poruke servisu **`B`**.
3. Zatim se šalje poruka koja uključuje zabranjenu akciju, uz očekivanje da će biti obrađena konkurentno sa odgovorom iz **`B`**.

Below is a visual representation of the described attack scenario:

!\[https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png]\(../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (33).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Discovery Problems

* **Difficulties in Locating Instances**: Pretraga za instancama korišćenja `xpc_connection_get_audit_token` bila je izazovna, kako statički tako i dinamički.
* **Methodology**: Frida je korišćena za povezivanje funkcije `xpc_connection_get_audit_token`, filtrirajući pozive koji ne potiču iz rukovaoca događajem. Međutim, ova metoda je bila ograničena na povezani proces i zahtevala aktivnu upotrebu.
* **Analysis Tooling**: Alati poput IDA/Ghidra korišćeni su za ispitivanje dostupnih mach servisa, ali je proces bio dugotrajan, otežan pozivima koji uključuju dyld deljenu keš memoriju.
* **Scripting Limitations**: Pokušaji da se skriptuje analiza poziva `xpc_connection_get_audit_token` iz `dispatch_async` blokova bili su ometeni složenostima u analizi blokova i interakcijama sa dyld deljenom keš memorijom.

## The fix <a href="#the-fix" id="the-fix"></a>

* **Reported Issues**: Izveštaj je podnet Apple-u koji detaljno opisuje opšte i specifične probleme pronađene unutar `smd`.
* **Apple's Response**: Apple je rešio problem u `smd` zamenom `xpc_connection_get_audit_token` sa `xpc_dictionary_get_audit_token`.
* **Nature of the Fix**: Funkcija `xpc_dictionary_get_audit_token` se smatra sigurnom jer direktno preuzima audit token iz mach poruke vezane za primljenu XPC poruku. Međutim, nije deo javnog API-ja, slično kao `xpc_connection_get_audit_token`.
* **Absence of a Broader Fix**: Ostaje nejasno zašto Apple nije implementirao sveobuhvatnije rešenje, kao što je odbacivanje poruka koje se ne poklapaju sa sačuvanim audit tokenom veze. Mogućnost legitimnih promena audit tokena u određenim scenarijima (npr. korišćenje `setuid`) može biti faktor.
* **Current Status**: Problem i dalje postoji u iOS 17 i macOS 14, predstavljajući izazov za one koji žele da ga identifikuju i razumeju.

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
