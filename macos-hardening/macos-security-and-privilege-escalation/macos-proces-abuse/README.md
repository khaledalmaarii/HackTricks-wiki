# Zloupotreba procesa na macOS-u

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite svoju **kompaniju reklamiranu na HackTricks-u** ili da **preuzmete HackTricks u PDF formatu** proverite [**PLANOVE ZA PRIJAVU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**Porodicu PEASS**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Zloupotreba Procesa na macOS-u

macOS, kao i svaki drugi operativni sistem, pruža različite metode i mehanizme za **procese da interaguju, komuniciraju i dele podatke**. Iako su ove tehnike neophodne za efikasno funkcionisanje sistema, mogu biti zloupotrebljene od strane napadača za **izvođenje zlonamernih aktivnosti**.

### Umetanje Biblioteke

Umetanje biblioteke je tehnika u kojoj napadač **prisiljava proces da učita zlonamernu biblioteku**. Jednom ubačena, biblioteka se izvršava u kontekstu ciljnog procesa, pružajući napadaču iste dozvole i pristup kao i proces.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Hakovanje Funkcija

Hakovanje funkcija podrazumeva **interceptovanje poziva funkcija** ili poruka unutar softverskog koda. Hakovanjem funkcija, napadač može **modifikovati ponašanje** procesa, posmatrati osetljive podatke ili čak preuzeti kontrolu nad tokom izvršenja.

{% content-ref url="macos-function-hooking.md" %}
[macos-function-hooking.md](macos-function-hooking.md)
{% endcontent-ref %}

### Komunikacija Između Procesa

Komunikacija između procesa (IPC) odnosi se na različite metode kojima odvojeni procesi **doležu i razmenjuju podatke**. Iako je IPC fundamentalan za mnoge legitimne aplikacije, može biti zloupotrebljen za zaobilaženje izolacije procesa, curenje osetljivih informacija ili izvođenje neovlašćenih akcija.

{% content-ref url="macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Umetanje Elektronskih Aplikacija

Elektronske aplikacije izvršene sa specifičnim env promenljivima mogu biti ranjive na ubacivanje procesa:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Umetanje u Chromium

Moguće je koristiti zastave `--load-extension` i `--use-fake-ui-for-media-stream` za izvođenje **napada čoveka u pregledaču** koji omogućava krađu pritisaka tastera, saobraćaja, kolačića, ubacivanje skripti na stranice...:

{% content-ref url="macos-chromium-injection.md" %}
[macos-chromium-injection.md](macos-chromium-injection.md)
{% endcontent-ref %}

### Prljavi NIB

NIB fajlovi **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije unutar aplikacije. Međutim, oni mogu **izvršiti proizvoljne komande** i **Gatekeeper ne sprečava** već izvršenu aplikaciju da se izvrši ako je **NIB fajl modifikovan**. Stoga, mogu se koristiti za izvršavanje proizvoljnih programa:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Umetanje u Java Aplikacije

Moguće je zloupotrebiti određene java mogućnosti (kao što je **`_JAVA_OPTS`** env promenljiva) da se java aplikacija natera da izvrši **proizvoljan kod/komande**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Umetanje u .Net Aplikacije

Moguće je ubaciti kod u .Net aplikacije **zloupotrebom .Net debagovanja** (nije zaštićeno macOS zaštitama kao što je runtime ojačavanje).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Umetanje u Perl

Proverite različite opcije za izvođenje proizvoljnog koda u Perl skripti:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Umetanje u Ruby

Takođe je moguće zloupotrebiti ruby env promenljive da se proizvoljne skripte izvrše proizvoljni kod:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Umetanje u Python

Ako je env promenljiva **`PYTHONINSPECT`** postavljena, python proces će preći u python cli nakon završetka. Takođe je moguće koristiti **`PYTHONSTARTUP`** da se naznači python skripta za izvršavanje na početku interaktivne sesije.\
Međutim, imajte na umu da **`PYTHONSTARTUP`** skripta neće biti izvršena kada **`PYTHONINSPECT`** kreira interaktivnu sesiju.

Druge env promenljive poput **`PYTHONPATH`** i **`PYTHONHOME`** takođe mogu biti korisne za izvršavanje proizvoljnog koda putem python komande.

Imajte na umu da izvršni fajlovi kompajlirani sa **`pyinstaller`** neće koristiti ove env promenljive čak i ako se izvršavaju koristeći ugrađeni python.

{% hint style="opasnost" %}
U globalu, nisam uspeo da pronađem način da python izvrši proizvoljni kod zloupotrebom env promenljivih.\
Međutim, većina ljudi instalira python koristeći **Hombrew**, koji će instalirati python na **zapisivu lokaciju** za podrazumevanog admin korisnika. Možete ga preuzeti nečim poput:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
## Detekcija

### Štit

[**Štit**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) je otvorena aplikacija koja može **detektovati i blokirati akcije ubacivanja procesa**:

* Korišćenje **Okružnih Promenljivih**: Pratiće prisustvo bilo koje od sledećih okružnih promenljivih: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** i **`ELECTRON_RUN_AS_NODE`**
* Korišćenje poziva **`task_for_pid`**: Da bi pronašao kada jedan proces želi da dobije **zadatak porta drugog** što omogućava ubacivanje koda u proces.
* **Parametri Electron aplikacija**: Neko može koristiti **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`** komandnu liniju da pokrene Electron aplikaciju u režimu debagovanja, i tako ubaci kod u nju.
* Korišćenje **simboličkih linkova** ili **čvrstih linkova**: Tipično najčešća zloupotreba je da **postavimo link sa privilegijama našeg korisnika**, i **usmerimo ga ka lokaciji sa većim privilegijama**. Detekcija je veoma jednostavna za oba čvrsta i simbolička linka. Ako proces koji kreira link ima **različit nivo privilegija** od ciljnog fajla, mi stvaramo **upozorenje**. Nažalost, u slučaju simboličkih linkova blokiranje nije moguće, jer nemamo informacije o destinaciji linka pre kreiranja. Ovo je ograničenje Apple-ovog EndpointSecuriy okvira.

### Pozivi koje vrše drugi procesi

U [**ovom blog postu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete pronaći kako je moguće koristiti funkciju **`task_name_for_pid`** da dobijete informacije o drugim **procesima koji ubacuju kod u proces** i zatim dobijete informacije o tom drugom procesu.

Imajte na umu da da biste pozvali tu funkciju morate biti **isti uid** kao onaj koji pokreće proces ili **root** (i vraća informacije o procesu, ne način za ubacivanje koda).

## Reference

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)
