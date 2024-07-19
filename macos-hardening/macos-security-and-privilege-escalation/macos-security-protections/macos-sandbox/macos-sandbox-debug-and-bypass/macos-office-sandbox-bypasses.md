# macOS Office Sandbox Bypasses

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

### Word Sandbox bypass via Launch Agents

Aplikacija koristi **prilagođeni Sandbox** koristeći pravo **`com.apple.security.temporary-exception.sbpl`** i ovaj prilagođeni sandbox omogućava pisanje fajlova bilo gde sve dok ime fajla počinje sa `~$`: `(require-any (require-all (vnode-type REGULAR-FILE) (regex #"(^|/)~$[^/]+$")))`

Stoga, bekstvo je bilo lako kao **pisanje `plist`** LaunchAgent-a u `~/Library/LaunchAgents/~$escape.plist`.

Check the [**original report here**](https://www.mdsec.co.uk/2018/08/escaping-the-sandbox-microsoft-office-on-macos/).

### Word Sandbox bypass via Login Items and zip

Zapamtite da iz prvog bekstva, Word može pisati proizvoljne fajlove čija imena počinju sa `~$` iako nakon zakrpe prethodne ranjivosti nije bilo moguće pisati u `/Library/Application Scripts` ili u `/Library/LaunchAgents`.

Otkriveno je da je iz sandbox-a moguće kreirati **Login Item** (aplikacije koje će se izvršiti kada se korisnik prijavi). Međutim, ove aplikacije **neće se izvršiti osim ako** nisu **notarizovane** i **nije moguće dodati argumente** (tako da ne možete samo pokrenuti reverznu ljusku koristeći **`bash`**).

Iz prethodnog Sandbox zaobilaženja, Microsoft je onemogućio opciju pisanja fajlova u `~/Library/LaunchAgents`. Međutim, otkriveno je da ako stavite **zip fajl kao Login Item**, `Archive Utility` će jednostavno **raspakovati** na trenutnoj lokaciji. Dakle, pošto po defaultu folder `LaunchAgents` iz `~/Library` nije kreiran, bilo je moguće **zipovati plist u `LaunchAgents/~$escape.plist`** i **staviti** zip fajl u **`~/Library`** tako da kada se raspakuje, doći će do odredišta za postojanost.

Check the [**original report here**](https://objective-see.org/blog/blog\_0x4B.html).

### Word Sandbox bypass via Login Items and .zshenv

(Zapamtite da iz prvog bekstva, Word može pisati proizvoljne fajlove čija imena počinju sa `~$`).

Međutim, prethodna tehnika imala je ograničenje, ako folder **`~/Library/LaunchAgents`** postoji jer ga je neka druga aplikacija kreirala, to bi propalo. Tako je otkrivena drugačija lanac Login Items za ovo.

Napadač bi mogao kreirati fajlove **`.bash_profile`** i **`.zshenv`** sa teretom za izvršavanje, a zatim ih zipovati i **pisati zip u folder korisnika žrtve**: **`~/~$escape.zip`**.

Zatim, dodajte zip fajl u **Login Items** i zatim aplikaciju **`Terminal`**. Kada se korisnik ponovo prijavi, zip fajl bi bio raspakovan u korisničkom folderu, prepisujući **`.bash_profile`** i **`.zshenv`** i stoga će terminal izvršiti jedan od ovih fajlova (u zavisnosti od toga da li se koristi bash ili zsh).

Check the [**original report here**](https://desi-jarvis.medium.com/office365-macos-sandbox-escape-fcce4fa4123c).

### Word Sandbox Bypass with Open and env variables

Iz sandboxovanih procesa još uvek je moguće pozvati druge procese koristeći **`open`** alat. Štaviše, ovi procesi će se izvršavati **unutar svog vlastitog sandbox-a**.

Otkriveno je da open alat ima opciju **`--env`** za pokretanje aplikacije sa **specifičnim env** varijablama. Stoga, bilo je moguće kreirati **`.zshenv` fajl** unutar foldera **unutar** **sandbox-a** i koristiti `open` sa `--env` postavljajući **`HOME` varijablu** na taj folder otvarajući aplikaciju `Terminal`, koja će izvršiti `.zshenv` fajl (iz nekog razloga takođe je bilo potrebno postaviti varijablu `__OSINSTALL_ENVIROMENT`).

Check the [**original report here**](https://perception-point.io/blog/technical-analysis-of-cve-2021-30864/).

### Word Sandbox Bypass with Open and stdin

Alat **`open`** takođe podržava parametar **`--stdin`** (i nakon prethodnog zaobilaženja više nije bilo moguće koristiti `--env`).

Stvar je u tome da čak i ako je **`python`** potpisan od strane Apple-a, **neće izvršiti** skriptu sa **`quarantine`** atributom. Međutim, bilo je moguće proslediti mu skriptu iz stdin-a tako da neće proveravati da li je bila u karantinu ili ne:&#x20;

1. Postavite **`~$exploit.py`** fajl sa proizvoljnim Python komandama.
2. Pokrenite _open_ **`–stdin='~$exploit.py' -a Python`**, što pokreće Python aplikaciju sa našim postavljenim fajlom kao njenim standardnim ulazom. Python rado izvršava naš kod, a pošto je to podproces _launchd_, nije vezan za pravila Word-ovog sandbox-a.

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
