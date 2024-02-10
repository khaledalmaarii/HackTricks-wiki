# Napad xpc\_connection\_get\_audit\_token na macOS-u

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu u HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

**Za dalje informacije proverite originalni post: [https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/)**. Ovo je sažetak:


## Osnovne informacije o Mach porukama

Ako ne znate šta su Mach poruke, proverite ovu stranicu:

{% content-ref url="../../../../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../../../../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

Za sada zapamtite da ([definicija sa ove stranice](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):\
Mach poruke se šalju preko _mach porta_, koji je **kanal za komunikaciju sa jednim primaocem i više pošiljalaca** ugrađen u mach kernel. **Više procesa može slati poruke** na mach port, ali u svakom trenutku **samo jedan proces može čitati iz njega**. Kao i fajl deskriptori i soketi, mach portovi se dodeljuju i upravljaju od strane kernela, a procesi vide samo celobrojne vrednosti koje mogu koristiti da indikuju kernelu koji od njihovih mach portova žele da koriste.

## XPC konekcija

Ako ne znate kako se uspostavlja XPC konekcija, proverite:

{% content-ref url="../" %}
[..](../)
{% endcontent-ref %}

## Sažetak ranjivosti

Ono što je važno da znate je da je **XPC apstrakcija jedan-na-jedan konekcija**, ali se zasniva na tehnologiji koja **može imati više pošiljalaca, tako da:**

* Mach portovi su jedan primaoc, **više pošiljalaca**.
* Audit token XPC konekcije je audit token **kopiran iz najskorije primljene poruke**.
* Dobijanje **audit tokena** XPC konekcije je ključno za mnoge **bezbednosne provere**.

Iako prethodna situacija zvuči obećavajuće, postoje neki scenariji u kojima to neće izazvati probleme ([sa ove stranice](https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing)):

* Audit tokeni se često koriste za proveru autorizacije kako bi se odlučilo da li prihvatiti konekciju. Pošto se ovo dešava korišćenjem poruke ka servisnom portu, **konekcija još uvek nije uspostavljena**. Dodatne poruke na ovom portu će biti tretirane kao dodatni zahtevi za konekciju. Dakle, **provere pre prihvatanja konekcije nisu ranjive** (ovo takođe znači da je audit token bezbedan unutar `-listener:shouldAcceptNewConnection:`). Zato **tražimo XPC konekcije koje proveravaju određene akcije**.
* XPC event handleri se obrađuju sinhrono. Ovo znači da event handler za jednu poruku mora biti završen pre nego što se pozove za sledeću, čak i na konkurentnim dispatch redovima. Dakle, unutar **XPC event handlera audit token ne može biti prepisan** drugim normalnim (ne-reply!) porukama.

Dve različite metode na kojima ovo može biti iskorišćeno:

1. Varijanta 1:
* **Exploit** se **povezuje** sa servisom **A** i servisom **B**
* Servis **B** može pozvati **privilegovanu funkcionalnost** u servisu A koju korisnik ne može
* Servis **A** poziva **`xpc_connection_get_audit_token`** dok nije unutar **event handlera** za konekciju u **`dispatch_async`**.
* Tako da **različita** poruka može **prepisati Audit Token** jer se asinhrono šalje izvan event handlera.
* Exploit prosleđuje servisu **B SEND pravo za servis A**.
* Tako da će svc **B** zapravo **slati** poruke servisu **A**.
* Exploit pokušava **pozvati privilegovanu akciju**. U RC svc **A** **proverava** autorizaciju ove **akcije** dok je **svc B prepisao Audit token** (dajući exploitu pristup pozivanju privilegovane akcije).
2. Varijanta 2:
* Servis **B** može pozvati **privilegovanu funkcionalnost** u servisu A koju korisnik ne može
* Exploit se povezuje sa **servisom A** koji šalje exploitu poruku očekujući odgovor na određeni **replay port**.
* Exploit šalje servisu **B** poruku prosleđujući **taj reply port**.
* Kada servis **B odgovori**, šalje poruku servisu **A**, **dok** exploit šalje drugu **poruku servisu A** pokušavajući **dostići privilegovanu funkcionalnost** i očekujući da će odgovor od servisa B prepisati Audit token u savršenom trenutku (Race Condition).

## Varijanta 1: pozivanje xpc\_connection\_get\_audit\_token van event handlera <a href="#variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler" id="variant-1-calling-xpc_connection_get_audit_token-outside-of-an-event-handler"></a>

Scenario:

* Dva mach servisa **`A`** i **`B`** sa kojima možemo da se povežemo (na osnovu sandbox profila i provera autorizacije pre prihvatanja konekcije).
* _**A**_ mora imati **proveru autorizacije** za određenu akciju koju **`B`** mo
4. Sledeći korak uključuje instrukciju `diagnosticd`-u da započne praćenje odabranog procesa (potencijalno korisnikovog). Istovremeno, šalje se poplava rutinskih poruka 1004 `smd`-u. Cilj je instalirati alat sa povišenim privilegijama.
5. Ova radnja pokreće trku između uslova unutar funkcije `handle_bless`. Vreme je ključno: poziv funkcije `xpc_connection_get_pid` mora vratiti PID korisnikovog procesa (jer privilegovani alat se nalazi u korisnikovom paketu aplikacije). Međutim, funkcija `xpc_connection_get_audit_token`, tačnije unutar podrutine `connection_is_authorized`, mora se odnositi na audit token koji pripada `diagnosticd`-u.

## Varijanta 2: prosleđivanje odgovora

U okruženju XPC (Interprocesna komunikacija), iako rukovaoci događaja ne izvršavaju se istovremeno, rukovanje odgovorima na poruke ima jedinstveno ponašanje. Konkretno, postoje dva različita načina slanja poruka koje očekuju odgovor:

1. **`xpc_connection_send_message_with_reply`**: Ovde se XPC poruka prima i obrađuje na određenom redosledu.
2. **`xpc_connection_send_message_with_reply_sync`**: Nasuprot tome, u ovom metodu XPC poruka se prima i obrađuje na trenutnom redosledu raspodele.

Ova razlika je ključna jer omogućava mogućnost **paralelnog parsiranja odgovora sa izvršenjem rukovaoca događaja XPC-a**. Treba napomenuti da, iako `_xpc_connection_set_creds` implementira zaključavanje kako bi se zaštitilo od delimičnog prepisivanja audit tokena, ova zaštita se ne odnosi na ceo objekat veze. Kao rezultat toga, stvara se ranjivost gde se audit token može zameniti tokom intervala između parsiranja paketa i izvršenja rukovaoca događaja.

Da bi se iskoristila ova ranjivost, potrebna je sledeća konfiguracija:

- Dve mašinske usluge, nazvane **`A`** i **`B`**, obe mogu uspostaviti vezu.
- Usluga **`A`** treba da uključuje proveru autorizacije za određenu radnju koju samo **`B`** može izvršiti (aplikacija korisnika ne može).
- Usluga **`A`** treba da pošalje poruku koja očekuje odgovor.
- Korisnik može poslati poruku **`B`**-u na koju će on odgovoriti.

Proces iskorišćavanja ove ranjivosti uključuje sledeće korake:

1. Sačekajte da usluga **`A`** pošalje poruku koja očekuje odgovor.
2. Umesto direktnog odgovora na **`A`**, preuzima se i koristi priključak za odgovor kako bi se poslala poruka usluzi **`B`**.
3. Naknadno se šalje poruka koja uključuje zabranjenu radnju, sa očekivanjem da će biti obrađena paralelno sa odgovorom od **`B`**.

Ispod je vizuelni prikaz opisanog scenarija napada:

![https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png](../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png)


<figure><img src="../../../../../../.gitbook/assets/image (1) (1) (1) (1) (1) (1) (1).png" alt="https://sector7.computest.nl/post/2023-10-xpc-audit-token-spoofing/variant2.png" width="563"><figcaption></figcaption></figure>

## Problemi sa otkrivanjem

- **Teškoće u pronalaženju instanci**: Bilo je izazovno pronaći upotrebu `xpc_connection_get_audit_token`, kako statički tako i dinamički.
- **Metodologija**: Frida je korišćena za hakovanje funkcije `xpc_connection_get_audit_token`, filtrirajući pozive koji ne potiču od rukovaoca događaja. Međutim, ovaj metod je bio ograničen na hakovan proces i zahtevao je aktivnu upotrebu.
- **Alati za analizu**: Alati poput IDA/Ghidra korišćeni su za ispitivanje dostupnih mašinskih usluga, ali je proces bio vremenski zahtevan, otežan pozivima koji uključuju keširane deljene biblioteke dyld.
- **Ograničenja skriptiranja**: Pokušaji skriptiranja analize poziva `xpc_connection_get_audit_token` iz `dispatch_async` blokova ometani su složenošću parsiranja blokova i interakcijama sa keširanim deljenim bibliotekama dyld.

## Popravka <a href="#the-fix" id="the-fix"></a>

- **Prijavljene probleme**: Appleu je dostavljen izveštaj koji detaljno opisuje opšte i specifične probleme pronađene u `smd`.
- **Odgovor Applea**: Apple je rešio problem u `smd` zamenom `xpc_connection_get_audit_token` sa `xpc_dictionary_get_audit_token`.
- **Priroda popravke**: Funkcija `xpc_dictionary_get_audit_token` smatra se sigurnom jer direktno dobavlja audit token iz mašinske poruke povezane sa primljenom XPC porukom. Međutim, nije deo javnog API-ja, slično kao i `xpc_connection_get_audit_token`.
- **Odsustvo šire popravke**: Nije jasno zašto Apple nije implementirao sveobuhvatniju popravku, poput odbacivanja poruka koje se ne podudaraju sa sačuvanim audit tokenom veze. Mogući faktor može biti mogućnost legitimnih promena audit tokena u određenim scenarijima (npr. upotreba `setuid`).
- **Trenutni status**: Problem i dalje postoji u iOS-u 17 i macOS-u 14, što predstavlja izazov za one koji pokušavaju da ga identifikuju i razumeju.

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **oglašavanje vaše kompanije u HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, pogledajte [**PLANOVE PRETPLATE**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
