# Napad na xpc\_connection\_get\_audit\_token na macOS-u

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

**Za dodatne informacije pogledajte originalni post:** [**https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/**](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/). Ovo je sažetak:

## Osnovne informacije o Mach porukama

Ako ne znate šta su Mach poruke, počnite sa proverom ove stranice:

{% content-ref url="../../" %}
[..](../../)
{% endcontent-ref %}

Za sada zapamtite da ([definicija sa ovog linka](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach poruke se šalju preko _mach porta_, koji je **kanal komunikacije sa jednim primaocem, više pošiljalaca** ugrađen u mach kernel. **Više procesa može slati poruke** ka mach portu, ali u svakom trenutku **samo jedan proces može čitati iz njega**. Baš kao i deskriptori fajlova i soketi, mach portovi se dodeljuju i upravljaju od strane kernela, a procesi vide samo celobrojne vrednosti koje mogu koristiti da označe kernelu koji od njihovih mach portova žele da koriste.

## XPC Veza

Ako ne znate kako se uspostavlja XPC veza, proverite:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Sumiranje ranjivosti

Ono što je za vas zanimljivo da znate je da je **XPC-ova apstrakcija jedan-na-jedan veza**, ali se zasniva na tehnologiji koja **može imati više pošiljalaca, tako da:**

* Mach portovi su jedan primaoc, **više pošiljalaca**.
* Audit token XPC veze je audit token **kopiran iz najskorije primljene poruke**.
* Dobijanje **audit tokena** XPC veze je ključno za mnoge **bezbednosne provere**.

Iako prethodna situacija zvuči obećavajuće, postoje neki scenariji gde to neće izazvati probleme ([sa ovog linka](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Audit tokeni se često koriste za proveru autorizacije kako bi se odlučilo da li prihvatiti vezu. Pošto se ovo dešava korišćenjem poruke ka servisnom portu, **veza još uvek nije uspostavljena**. Više poruka na ovom portu će biti tretirano kao dodatni zahtevi za vezu. Dakle, bilo kakve **provere pre prihvatanja veze nisu ranjive** (ovo takođe znači da je unutar `-listener:shouldAcceptNewConnection:` audit token siguran). Zato **tražimo XPC veze koje proveravaju specifične akcije**.
* XPC event handleri se obrađuju sinhrono. Ovo znači da event handler za jednu poruku mora biti završen pre nego što se pozove za sledeću, čak i na konkurentnim redovima za raspodelu. Dakle, unutar **XPC event handlera audit token ne može biti prepisan** od strane drugih normalnih (ne-odgovornih!) poruka.

Dva različita načina na koje ovo može biti iskorišćeno:

1. Varijanta 1:
* **Eksploit** se **povezuje** sa servisom **A** i servisom **B**
* Servis **B** može pozvati **privilegovanu funkcionalnost** u servisu A koju korisnik ne može
* Servis **A** poziva **`xpc_connection_get_audit_token`** dok _**nije**_ unutar **event handlera** za vezu u **`dispatch_async`**.
* Tako da **različita** poruka može **prepisati Audit Token** jer se šalje asinhrono izvan event handlera.
* Eksploit prosleđuje **servisu B SEND pravo ka servisu A**.
* Tako da će svc **B** zapravo **slati** **poruke** servisu **A**.
* **Eksploit** pokušava da **pozove privilegovanu akciju**. U RC svc **A** **proverava** autorizaciju ove **akcije** dok je **svc B prepisao Audit token** (dajući eksploatatoru pristup da pozove privilegovanu akciju).
2. Varijanta 2:
* Servis **B** može pozvati **privilegovanu funkcionalnost** u servisu A koju korisnik ne može
* Eksploit se povezuje sa **servisom A** koji mu **šalje** poruku očekujući odgovor na određenom **replay** **portu**.
* Eksploit šalje **servisu** B poruku prosleđujući **taj replay port**.
* Kada servis **B odgovori**, on šalje poruku servisu A, **dok** **eksploit** šalje drugu **poruku servisu A** pokušavajući da **dostigne privilegovanu funkcionalnost** i očekujući da će odgovor od servisa B prepisati Audit token u savršenom trenutku (Race Condition).

## Varijanta 1: pozivanje xpc\_connection\_get\_audit\_token van event handlera <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

* Dva mach servisa **`A`** i **`B`** kojima možemo oboje da se povežemo (bazirano na profilu peska i autorizacionim proverama pre prihvatanja veze).
* _**A**_ mora imati **autorizacionu proveru** za specifičnu akciju koju **`B`** može proslediti (ali naša aplikacija ne može).
* Na primer, ako B ima neka **prava** ili se izvršava kao **root**, možda mu dozvoljava da zatraži od A da izvrši privilegovanu akciju.
* Za ovu autorizacionu proveru, **`A`** asinhrono dobija audit token, na primer pozivajući `xpc_connection_get_audit_token` iz **`dispatch_async`**.

{% hint style="danger" %}
U ovom slučaju napadač može pokrenuti **Race Condition** praveći **eksploit** koji **traži od A da izvrši akciju** više puta dok **B šalje poruke ka `A`**. Kada RC bude **uspešan**, audit token **B** će biti kopiran u memoriju **dok** zahtev našeg **eksploita** bude **obrađen** od strane A, dajući mu **pristup privilegovanoj akciji koju je samo B mogao zatražiti**.
{% endhint %}

Ovo se desilo sa **`A`** kao `smd` i **`B`** kao `diagnosticd`. Funkcija [`SMJobBless`](https://developer.apple.com/documentation/servicemanagement/1431078-smjobbless?language=objc) iz smb može se koristiti za instaliranje novog privilegovanog pomoćnog alata (kao **root**). Ako **proces koji se izvršava kao root kontaktira** **smd**, neće biti izvršene druge provere.

Stoga je servis **B** **`diagnosticd`** jer se izvršava kao **root** i može se koristiti za **monitorisanje procesa**, tako da kada se monitorisanje pokrene, **šaljeće više poruka u sekundi.**

Za izvođenje napada:

1. Inicirajte **vezu** sa servisom nazvanim `smd` koristeći standardni XPC protokol.
2. Formirajte sekundarnu **vezu** sa `diagnosticd`. Suprotno normalnom postupku, umesto kreiranja i slanja dva nova mach porta, pravo slanja klijentskog porta se zamenjuje sa duplikatom **send prava** povezanog sa vezom `smd`.
3. Kao rezultat, XPC poruke mogu biti prosleđene `diagnosticd`, ali odgovori od `diagnosticd` se preusmeravaju ka `smd`. Za `smd`, izgleda kao da poruke od korisnika i `diagnosticd` potiču iz iste veze.

![Slika koja prikazuje proces eksploatacije](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/exploit.png)

4. Sledeći korak uključuje instrukciju `diagnosticd` da pokrene praćenje odabranog procesa (potencijalno korisnikovog). Istovremeno, šalje se poplava rutinskih 1004 poruka ka `smd`. Cilj ovde je instalirati alat sa povišenim privilegijama.
5. Ova radnja pokreće trku za uslovima unutar funkcije `handle_bless`. Vreme je ključno: poziv funkcije `xpc_connection_get_pid` mora vratiti PID procesa korisnika (jer privilegovani alat se nalazi u korisnikovom paketu aplikacije). Međutim, funkcija `xpc_connection_get_audit_token`, posebno unutar podrutine `connection_is_authorized`, mora se odnositi na audit token koji pripada `diagnosticd`.

## Varijanta 2: prosleđivanje odgovora

U okruženju XPC (Cross-Process Communication), iako rukovaoci događajima ne izvršavaju se istovremeno, obrada odgovora poruka ima jedinstveno ponašanje. Konkretno, postoje dva različita metoda slanja poruka koje očekuju odgovor:

1. **`xpc_connection_send_message_with_reply`**: Ovde se XPC poruka prima i obrađuje na određenom redu.
2. **`xpc_connection_send_message_with_reply_sync`**: Nasuprot tome, u ovom metodu, XPC poruka se prima i obrađuje na trenutnom redu dispečovanja.

Ova razlika je ključna jer omogućava mogućnost **paralelnog parsiranja odgovarajućih paketa sa izvršavanjem rukovaoca događajima XPC**. Važno je napomenuti da, iako `_xpc_connection_set_creds` implementira zaključavanje radi zaštite od delimičnog prepisivanja audit tokena, ova zaštita se ne proširuje na ceo objekat veze. Kao rezultat, stvara se ranjivost gde audit token može biti zamenjen tokom intervala između parsiranja paketa i izvršavanja njegovog rukovaoca događajima.

Da bi se iskoristila ova ranjivost, potrebno je sledeće podešavanje:

* Dve mach usluge, nazvane **`A`** i **`B`**, obe koje mogu uspostaviti vezu.
* Usluga **`A`** treba da uključi proveru autorizacije za određenu radnju koju samo **`B`** može izvršiti (aplikacija korisnika ne može).
* Usluga **`A`** treba da pošalje poruku koja očekuje odgovor.
* Korisnik može poslati poruku **`B`** na koju će odgovoriti.

Proces iskorišćavanja ove ranjivosti uključuje sledeće korake:

1. Sačekati da usluga **`A`** pošalje poruku koja očekuje odgovor.
2. Umesto direktnog odgovora **`A`**, preusmeriti port odgovora i koristiti ga za slanje poruke usluzi **`B`**.
3. Zatim, poslati poruku koja uključuje zabranjenu radnju, sa očekivanjem da će biti obrađena paralelno sa odgovorom od **`B`**.

Ispod je vizuelna reprezentacija opisanog scenarija napada:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)

<figure><img src="../../../../../../.gitbook/assets/image (30).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemi sa otkrivanjem

* **Teškoće u Pronalaženju Instanci**: Pretraga instanci korišćenja `xpc_connection_get_audit_token` bila je izazovna, kako statički, tako i dinamički.
* **Metodologija**: Frida je korišćena za hakovanje funkcije `xpc_connection_get_audit_token`, filtrirajući pozive koji ne potiču od rukovaoca događajima. Međutim, ovaj metod je bio ograničen na hakovan proces i zahtevao je aktivnu upotrebu.
* **Alati za Analizu**: Alati poput IDA/Ghidra korišćeni su za ispitivanje dostupnih mach usluga, ali je proces bio dugotrajan, otežan pozivima koji uključuju dyld deljeni keš.
* **Ograničenja Skriptovanja**: Pokušaji skriptovanja analize poziva `xpc_connection_get_audit_token` iz `dispatch_async` blokova bili su otežani složenošću parsiranja blokova i interakcijama sa dyld deljenim kešom.

## Popravka <a href="#the-fix" id="the-fix"></a>

* **Prijavljene Probleme**: Izveštaj je dostavljen Apple-u detaljno opisujući opšte i specifične probleme pronađene unutar `smd`.
* **Odgovor Apple-a**: Apple je rešio problem u `smd` zamenivši `xpc_connection_get_audit_token` sa `xpc_dictionary_get_audit_token`.
* **Priroda Popravke**: Funkcija `xpc_dictionary_get_audit_token` smatra se sigurnom jer direktno dobavlja audit token iz mach poruke povezane sa primljenom XPC porukom. Međutim, nije deo javnog API-ja, slično kao `xpc_connection_get_audit_token`.
* **Odsustvo Šire Popravke**: Ostaje nejasno zašto Apple nije implementirao sveobuhvatniju popravku, poput odbacivanja poruka koje se ne podudaraju sa sačuvanim audit tokenom veze. Moguće je da je faktor mogućnost legitimnih promena audit tokena u određenim scenarijima (npr. korišćenje `setuid`).
* **Trenutni Status**: Problem i dalje postoji u iOS 17 i macOS 14, predstavljajući izazov za one koji pokušavaju da ga identifikuju i razumeju.
