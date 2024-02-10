# Zloupotreba procesa na macOS-u

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini podrške HackTricks-u:

* Ako želite da vidite **vašu kompaniju reklamiranu na HackTricks-u** ili **preuzmete HackTricks u PDF formatu**, proverite [**PLANOVE ZA PRETPLATU**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>

## Zloupotreba procesa na macOS-u

macOS, kao i svaki drugi operativni sistem, pruža razne metode i mehanizme za **interakciju, komunikaciju i deljenje podataka između procesa**. Iako su ove tehnike neophodne za efikasno funkcionisanje sistema, mogu biti zloupotrebljene od strane napadača za **izvršavanje zlonamernih aktivnosti**.

### Ubacivanje biblioteke

Ubacivanje biblioteke je tehnika u kojoj napadač **prisiljava proces da učita zlonamernu biblioteku**. Jednom ubačena, biblioteka se izvršava u kontekstu ciljnog procesa, pružajući napadaču iste dozvole i pristup kao i proces.

{% content-ref url="macos-library-injection/" %}
[macos-library-injection](macos-library-injection/)
{% endcontent-ref %}

### Hakovanje funkcija

Hakovanje funkcija podrazumeva **presretanje poziva funkcija** ili poruka unutar softverskog koda. Hakovanjem funkcija, napadač može **izmeniti ponašanje** procesa, posmatrati osetljive podatke ili čak preuzeti kontrolu nad tokom izvršavanja.

{% content-ref url="../mac-os-architecture/macos-function-hooking.md" %}
[macos-function-hooking.md](../mac-os-architecture/macos-function-hooking.md)
{% endcontent-ref %}

### Međuprocesna komunikacija

Međuprocesna komunikacija (IPC) se odnosi na različite metode kojima se odvojeni procesi **deljenje i razmenjuju podaci**. Iako je IPC osnovan za mnoge legitimne aplikacije, može biti zloupotrebljen radi narušavanja izolacije procesa, curenja osetljivih informacija ili izvršavanja neovlašćenih radnji.

{% content-ref url="../mac-os-architecture/macos-ipc-inter-process-communication/" %}
[macos-ipc-inter-process-communication](../mac-os-architecture/macos-ipc-inter-process-communication/)
{% endcontent-ref %}

### Ubacivanje Electron aplikacija

Elektron aplikacije izvršene sa određenim okruženjskim promenljivama mogu biti ranjive na ubacivanje procesa:

{% content-ref url="macos-electron-applications-injection.md" %}
[macos-electron-applications-injection.md](macos-electron-applications-injection.md)
{% endcontent-ref %}

### Prljavi NIB

NIB fajlovi **definišu elemente korisničkog interfejsa (UI)** i njihove interakcije unutar aplikacije. Međutim, oni mogu **izvršavati proizvoljne komande** i **Gatekeeper ne sprečava** izvršavanje već pokrenute aplikacije ako je NIB fajl izmenjen. Stoga, mogu se koristiti za izvršavanje proizvoljnih programa:

{% content-ref url="macos-dirty-nib.md" %}
[macos-dirty-nib.md](macos-dirty-nib.md)
{% endcontent-ref %}

### Ubacivanje Java aplikacija

Moguće je zloupotrebiti određene mogućnosti Jave (poput okruženjske promenljive **`_JAVA_OPTS`**) da bi se java aplikacija izvršila **proizvoljni kod/komande**.

{% content-ref url="macos-java-apps-injection.md" %}
[macos-java-apps-injection.md](macos-java-apps-injection.md)
{% endcontent-ref %}

### Ubacivanje .Net aplikacija

Moguće je ubaciti kod u .Net aplikacije **zloupotrebom .Net debagovanja** (koje nije zaštićeno macOS zaštitama kao što je ojačavanje izvršavanja).

{% content-ref url="macos-.net-applications-injection.md" %}
[macos-.net-applications-injection.md](macos-.net-applications-injection.md)
{% endcontent-ref %}

### Perl ubacivanje

Proverite različite opcije za izvršavanje proizvoljnog koda u Perl skripti:

{% content-ref url="macos-perl-applications-injection.md" %}
[macos-perl-applications-injection.md](macos-perl-applications-injection.md)
{% endcontent-ref %}

### Ruby ubacivanje

Takođe je moguće zloupotrebiti Ruby okruženske promenljive da bi proizvoljne skripte izvršile proizvoljni kod:

{% content-ref url="macos-ruby-applications-injection.md" %}
[macos-ruby-applications-injection.md](macos-ruby-applications-injection.md)
{% endcontent-ref %}

### Python ubacivanje

Ako je postavljena okruženska promenljiva **`PYTHONINSPECT`**, python proces će preći u python CLI nakon završetka. Takođe je moguće koristiti **`PYTHONSTARTUP`** da bi se naznačila python skripta koja će se izvršiti na početku interaktivne sesije.\
Međutim, treba napomenuti da se **`PYTHONSTARTUP`** skripta neće izvršiti kada **`PYTHONINSPECT`** kreira interaktivnu sesiju.

Druge okruženske promenljive poput **`PYTHONPATH`** i **`PYTHONHOME`** takođe mogu biti korisne za izvršavanje proizvoljnog koda pomoću python komande.

Imajte na umu da izvršni fajlovi kompajlirani sa **`pyinstaller`** neće koristiti ove okruženske promenljive čak i ako se izvršavaju pomoću ugrađenog pythona.

{% hint style="danger" %}
Ukupno gledano, nisam pronašao način da python izvrši proizvoljni kod zloupotrebom okruženskih promenljivih.\
Međutim, većina ljudi instalira python koristeći **Hombrew**, koji će instalirati python na **mestu gde je moguće upisivanje** za podrazumevanog administratorskog korisnika. Možete ga preuzeti pomoću nečega kao što je:
```bash
mv /opt/homebrew/bin/python3 /opt/homebrew/bin/python3.old
cat > /opt/homebrew/bin/python3 <<EOF
#!/bin/bash
# Extra hijack code
/opt/homebrew/bin/python3.old "$@"
EOF
chmod +x /opt/homebrew/bin/python3
```
Čak i **root** će pokrenuti ovaj kod prilikom pokretanja pythona.
{% endhint %}

## Detekcija

### Shield

[**Shield**](https://theevilbit.github.io/shield/) ([**Github**](https://github.com/theevilbit/Shield)) je open source aplikacija koja može **detektovati i blokirati akcije ubacivanja procesa**:

* Korišćenje **okružnih promenljivih**: Pratiće prisustvo bilo koje od sledećih okružnih promenljivih: **`DYLD_INSERT_LIBRARIES`**, **`CFNETWORK_LIBRARY_PATH`**, **`RAWCAMERA_BUNDLE_PATH`** i **`ELECTRON_RUN_AS_NODE`**
* Korišćenje poziva **`task_for_pid`**: Da bi pronašao kada jedan proces želi da dobije **task port druge** što omogućava ubacivanje koda u proces.
* **Parametri Electron aplikacija**: Neko može koristiti komandnu liniju **`--inspect`**, **`--inspect-brk`** i **`--remote-debugging-port`** da pokrene Electron aplikaciju u režimu za debagovanje i tako ubaci kod u nju.
* Korišćenje **simlinkova** ili **hardlinkova**: Tipično najčešća zloupotreba je da **postavimo link sa privilegijama našeg korisnika**, i **usmerimo ga ka lokaciji sa višim privilegijama**. Detekcija je veoma jednostavna za hardlinkove i simlinkove. Ako proces koji kreira link ima **različit nivo privilegija** od ciljnog fajla, kreiramo **upozorenje**. Nažalost, u slučaju simlinkova blokiranje nije moguće, jer nemamo informacije o odredištu linka pre kreiranja. Ovo je ograničenje Apple-ovog EndpointSecurity okvira.

### Pozivi koje vrše drugi procesi

U [**ovom blog postu**](https://knight.sc/reverse%20engineering/2019/04/15/detecting-task-modifications.html) možete saznati kako je moguće koristiti funkciju **`task_name_for_pid`** da biste dobili informacije o drugim **procesima koji ubacuju kod u proces** i zatim dobili informacije o tom drugom procesu.

Imajte na umu da da biste pozvali tu funkciju, morate biti **isti uid** kao onaj koji pokreće proces ili **root** (i ona vraća informacije o procesu, ne način za ubacivanje koda).

## Reference

* [https://theevilbit.github.io/shield/](https://theevilbit.github.io/shield/)
* [https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f](https://medium.com/@metnew/why-electron-apps-cant-store-your-secrets-confidentially-inspect-option-a49950d6d51f)

<details>

<summary><strong>Naučite hakovanje AWS-a od nule do heroja sa</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Drugi načini da podržite HackTricks:

* Ako želite da vidite **vašu kompaniju reklamiranu u HackTricks-u** ili **preuzmete HackTricks u PDF formatu** Proverite [**SUBSCRIPTION PLANS**](https://github.com/sponsors/carlospolop)!
* Nabavite [**zvanični PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Otkrijte [**The PEASS Family**](https://opensea.io/collection/the-peass-family), našu kolekciju ekskluzivnih [**NFT-ova**](https://opensea.io/collection/the-peass-family)
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitter-u** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Podelite svoje hakovanje trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
