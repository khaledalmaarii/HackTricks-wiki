{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks obuka AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks obuka GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}

**Manipulacija audio i video fajlovima** je osnovna tehnika u **CTF forenzičkim izazovima**, koristeći **steganografiju** i analizu metapodataka za skrivanje ili otkrivanje tajnih poruka. Alati poput **[mediainfo](https://mediaarea.net/en/MediaInfo)** i **`exiftool`** su neophodni za pregledanje metapodataka fajlova i identifikaciju vrsta sadržaja.

Za audio izazove, **[Audacity](http://www.audacityteam.org/)** se ističe kao vodeći alat za pregled talasnih oblika i analizu spektrograma, neophodnih za otkrivanje teksta kodiranog u audio formatu. **[Sonic Visualiser](http://www.sonicvisualiser.org/)** se visoko preporučuje za detaljnu analizu spektrograma. **Audacity** omogućava manipulaciju zvuka poput usporavanja ili obrtanja traka radi otkrivanja skrivenih poruka. **[Sox](http://sox.sourceforge.net/)**, alat za komandnu liniju, odličan je za konvertovanje i uređivanje audio fajlova.

**Manipulacija najmanje značajnim bitovima (LSB)** je česta tehnika u audio i video steganografiji, iskorišćavajući fiksne delove fajlova medija za skriveno ugrađivanje podataka. **[Multimon-ng](http://tools.kali.org/wireless-attacks/multimon-ng)** je koristan za dekodiranje poruka skrivenih kao **DTMF tonovi** ili **Morseov kod**.

Video izazovi često uključuju kontejnerske formate koji grupišu audio i video tokove. **[FFmpeg](http://ffmpeg.org/)** je osnovni alat za analizu i manipulaciju ovih formata, sposoban za demultipleksiranje i reprodukciju sadržaja. Za programere, **[ffmpy](http://ffmpy.readthedocs.io/en/latest/examples.html)** integriše mogućnosti FFmpeg-a u Python za napredne skriptne interakcije.

Ovaj niz alata ističe potrebnu raznovrsnost u CTF izazovima, gde učesnici moraju primeniti širok spektar tehnika analize i manipulacije kako bi otkrili skrivene podatke unutar audio i video fajlova.

## Reference
* [https://trailofbits.github.io/ctf/forensics/](https://trailofbits.github.io/ctf/forensics/)
  
{% hint style="success" %}
Naučite i vežbajte hakovanje AWS-a:<img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks obuka AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Naučite i vežbajte hakovanje GCP-a: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks obuka GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili nas **pratite** na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Delite hakovanje trikova slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
