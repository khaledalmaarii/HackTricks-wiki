{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **nas pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
{% endhint %}


# Identifikacija pakovanih binarnih datoteka

* **nedostatak stringova**: Uobičajeno je da pakovane binarne datoteke nemaju gotovo nikakve stringove
* Puno **neiskorišćenih stringova**: Takođe, kada malware koristi neku vrstu komercijalnog pakera, uobičajeno je pronaći puno stringova bez međureferenci. Čak i ako ovi stringovi postoje, to ne znači da binarna datoteka nije pakovana.
* Takođe možete koristiti neke alate da pokušate da otkrijete koji je pakera korišćen za pakovanje binarne datoteke:
* [PEiD](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/PEiD-updated.shtml)
* [Exeinfo PE](http://www.softpedia.com/get/Programming/Packers-Crypters-Protectors/ExEinfo-PE.shtml)
* [Language 2000](http://farrokhi.net/language/)

# Osnovne preporuke

* **Započnite** analizu pakovane binarne datoteke **od dna u IDA-i i pomerajte se ka vrhu**. Rasklopnici izlaze kada rasklopljeni kod izlazi, tako da je malo verovatno da će rasklopnik preneti izvršenje na rasklopljeni kod na početku.
* Pretražujte za **JMP-ovima** ili **CALL-ovima** ka **registrima** ili **regionima** **memorije**. Takođe pretražujte za **funkcijama koje prosleđuju argumente i adresu, a zatim pozivaju `retn`**, jer povratak funkcije u tom slučaju može pozvati adresu koja je upravo stavljena na stek pre pozivanja.
* Postavite **prekidač** na `VirtualAlloc` jer ovo alocira prostor u memoriji gde program može pisati rasklopljeni kod. "Pokreni do korisničkog koda" ili koristite F8 da **dobijete vrednost unutar EAX** nakon izvršavanja funkcije i "**pratite tu adresu u dump-u**". Nikada ne znate da li je to region gde će biti sačuvan rasklopljeni kod.
* **`VirtualAlloc`** sa vrednošću "**40**" kao argument znači Čitanje+Pisanje+Izvršavanje (neki kod koji treba da se izvrši će biti kopiran ovde).
* **Tokom rasklapanja** koda normalno je pronaći **several calls** ka **aritmetičkim operacijama** i funkcijama kao što su **`memcopy`** ili **`Virtual`**`Alloc`. Ako se nađete u funkciji koja očigledno samo vrši aritmetičke operacije i možda neki `memcopy`, preporuka je da pokušate da **pronađete kraj funkcije** (možda JMP ili poziv nekog registra) **ili** barem **poziv poslednje funkcije** i pokrenete do tada jer kod nije zanimljiv.
* Tokom rasklapanja koda **napomena** kada god **promenite region memorije** jer promena regiona memorije može ukazivati na **početak rasklopnog koda**. Možete lako dumpovati region memorije koristeći Process Hacker (proces --> svojstva --> memorija).
* Dok pokušavate da rasklopite kod, dobar način da **znate da li već radite sa rasklopljenim kodom** (tako da ga možete samo dumpovati) je da **proverite stringove binarne datoteke**. Ako u nekom trenutku izvršite skok (možda menjajući region memorije) i primetite da su **dodani mnogi više stringova**, tada možete znati **da radite sa rasklopljenim kodom**.\
Međutim, ako pakera već sadrži puno stringova, možete videti koliko stringova sadrži reč "http" i videti da li se ovaj broj povećava.
* Kada dumpujete izvršnu datoteku iz regiona memorije, možete popraviti neke zaglavlja koristeći [PE-bear](https://github.com/hasherezade/pe-bear-releases/releases).

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **nas pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
</details>
{% endhint %}
