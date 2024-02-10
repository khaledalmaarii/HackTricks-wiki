# Υπηρεσίες και πρωτόκολλα δικτύου για macOS

<details>

<summary><strong>Μάθετε το χάκινγκ στο AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στην** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

## Υπηρεσίες απομακρυσμένης πρόσβασης

Αυτές είναι οι κοινές υπηρεσίες του macOS για πρόσβαση απομακρυσμένα.\
Μπορείτε να ενεργοποιήσετε/απενεργοποιήσετε αυτές τις υπηρεσίες στις `Ρυθμίσεις Συστήματος` --> `Κοινή χρήση`

* **VNC**, γνωστό ως "Κοινή χρήση Οθόνης" (tcp:5900)
* **SSH**, ονομάζεται "Απομακρυσμένη Σύνδεση" (tcp:22)
* **Apple Remote Desktop** (ARD), ή "Απομακρυσμένη Διαχείριση" (tcp:3283, tcp:5900)
* **AppleEvent**, γνωστό ως "Απομακρυσμένο Apple Event" (tcp:3031)

Ελέγξτε εάν κάποια από αυτές είναι ενεργοποιημένη εκτελώντας:
```bash
rmMgmt=$(netstat -na | grep LISTEN | grep tcp46 | grep "*.3283" | wc -l);
scrShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.5900" | wc -l);
flShrng=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | egrep "\*.88|\*.445|\*.548" | wc -l);
rLgn=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.22" | wc -l);
rAE=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.3031" | wc -l);
bmM=$(netstat -na | grep LISTEN | egrep 'tcp4|tcp6' | grep "*.4488" | wc -l);
printf "\nThe following services are OFF if '0', or ON otherwise:\nScreen Sharing: %s\nFile Sharing: %s\nRemote Login: %s\nRemote Mgmt: %s\nRemote Apple Events: %s\nBack to My Mac: %s\n\n" "$scrShrng" "$flShrng" "$rLgn" "$rmMgmt" "$rAE" "$bmM";
```
### Πεντεστάρισμα ARD

Το Apple Remote Desktop (ARD) είναι μια βελτιωμένη έκδοση του [Virtual Network Computing (VNC)](https://en.wikipedia.org/wiki/Virtual_Network_Computing) σχεδιασμένη για το macOS, προσφέροντας επιπλέον χαρακτηριστικά. Μια σημαντική ευπάθεια στο ARD είναι η μέθοδος πιστοποίησης για τον κωδικό πρόσβασης της οθόνης ελέγχου, η οποία χρησιμοποιεί μόνο τους πρώτους 8 χαρακτήρες του κωδικού, καθιστώντας το ευάλωτο σε επιθέσεις [brute force](https://thudinh.blogspot.com/2017/09/brute-forcing-passwords-with-thc-hydra.html) με εργαλεία όπως το Hydra ή το [GoRedShell](https://github.com/ahhh/GoRedShell/), καθώς δεν υπάρχουν προεπιλεγμένα όρια ρυθμού.

Οι ευπάθειες περιπτώσεις μπορούν να ανιχνευθούν χρησιμοποιώντας το σενάριο `vnc-info` του **nmap**. Οι υπηρεσίες που υποστηρίζουν την `VNC Authentication (2)` είναι ιδιαίτερα ευάλωτες σε επιθέσεις brute force λόγω της περικοπής του κωδικού σε 8 χαρακτήρες.

Για να ενεργοποιήσετε το ARD για διάφορες διαχειριστικές εργασίες όπως η ανέλιξη προνομίων, η πρόσβαση στο γραφικό περιβάλλον ή η παρακολούθηση χρηστών, χρησιμοποιήστε την παρακάτω εντολή:
```bash
sudo /System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart -activate -configure -allowAccessFor -allUsers -privs -all -clientopts -setmenuextra -menuextra yes
```
Το ARD παρέχει ευέλικτα επίπεδα ελέγχου, συμπεριλαμβανομένης της παρατήρησης, του κοινόχρηστου ελέγχου και του πλήρους ελέγχου, με τις συνεδρίες να διατηρούνται ακόμα και μετά από αλλαγές κωδικού πρόσβασης του χρήστη. Επιτρέπει την αποστολή εντολών Unix απευθείας και την εκτέλεσή τους ως root για διαχειριστικούς χρήστες. Οι εξαιρετικές δυνατότητες περιλαμβάνουν τον προγραμματισμό εργασιών και την αναζήτηση μέσω του Remote Spotlight, που διευκολύνουν την απομακρυσμένη αναζήτηση για ευαίσθητα αρχεία σε πολλές μηχανές.

## Πρωτόκολλο Bonjour

Το Bonjour, μια τεχνολογία που σχεδιάστηκε από την Apple, επιτρέπει στις συσκευές στο ίδιο δίκτυο να ανιχνεύουν τις προσφερόμενες υπηρεσίες η μίας της άλλης. Επίσης γνωστό ως Rendezvous, Zero Configuration ή Zeroconf, επιτρέπει σε μια συσκευή να ενταχθεί σε ένα δίκτυο TCP/IP, να επιλέξει αυτόματα μια διεύθυνση IP και να μεταδώσει τις υπηρεσίες της σε άλλες συσκευές του δικτύου.

Το Zero Configuration Networking, που παρέχεται από το Bonjour, εξασφαλίζει ότι οι συσκευές μπορούν:
* Να αποκτήσουν αυτόματα μια διεύθυνση IP ακόμα και σε περίπτωση που δεν υπάρχει DHCP server.
* Να πραγματοποιήσουν μετάφραση ονόματος σε διεύθυνση χωρίς την ανάγκη ενός DNS server.
* Να ανακαλύψουν τις διαθέσιμες υπηρεσίες στο δίκτυο.

Οι συσκευές που χρησιμοποιούν το Bonjour θα αναθέσουν μια διεύθυνση IP από την περιοχή 169.254/16 και θα επαληθεύσουν την μοναδικότητά της στο δίκτυο. Οι Mac διατηρούν μια καταχώρηση πίνακα δρομολόγησης για αυτό το υποδίκτυο, που μπορεί να επαληθευτεί μέσω της εντολής `netstat -rn | grep 169`.

Για το DNS, το Bonjour χρησιμοποιεί το πρωτόκολλο Multicast DNS (mDNS). Το mDNS λειτουργεί στη θύρα 5353/UDP, χρησιμοποιώντας τυπικές ερωτήσεις DNS αλλά στοχεύοντας στην πολυεκπομπή διεύθυνση 224.0.0.251. Με αυτήν την προσέγγιση, εξασφαλίζεται ότι όλες οι συσκευές που ακούνε στο δίκτυο μπορούν να λάβουν και να απαντήσουν στις ερωτήσεις, διευκολύνοντας την ενημέρωση των εγγραφών τους.

Μετά την ενταξή του στο δίκτυο, κάθε συσκευή επιλέγει αυτόματα ένα όνομα, που συνήθως τελειώνει σε .local, το οποίο μπορεί να προέρχεται από το όνομα του υπολογιστή ή να δημιουργείται τυχαία.

Η ανακάλυψη υπηρεσιών εντός του δικτύου διευκολύνεται από το DNS Service Discovery (DNS-SD). Χρησιμοποιώντας τη μορφή των εγγραφών DNS SRV, το DNS-SD χρησιμοποιεί εγγραφές DNS PTR για να επιτρέψει τη λίστα πολλαπλών υπηρεσιών. Ένας πελάτης που αναζητά μια συγκεκριμένη υπηρεσία θα ζητήσει μια εγγραφή PTR για το `<Υπηρεσία>.<Domain>`, λαμβάνοντας ως απάντηση μια λίστα εγγραφών PTR με τη μορφή `<Παράδειγμα>.<Υπηρεσία>.<Domain>` αν η υπηρεσία είναι διαθέσιμη από πολλούς υπολογιστές.

Το εργαλείο `dns-sd` μπορεί να χρησιμοποιηθεί για την ανακάλυψη και τη διαφήμιση υπηρεσιών δικτύου. Παρακάτω παρουσιάζονται μερικά παραδείγματα χρήσης του:

### Αναζήτηση για υπηρεσίες SSH

Για να αναζητήσετε υπηρεσίες SSH στο δίκτυο, χρησιμοποιείται η παρακάτω εντολή:
```bash
dns-sd -B _ssh._tcp
```
Αυτή η εντολή ξεκινά την αναζήτηση για υπηρεσίες _ssh._tcp και εμφανίζει λεπτομέρειες όπως χρονική σήμανση, σημαίες, διεπαφή, τομέας, τύπος υπηρεσίας και όνομα παράδειγμα.

### Διαφήμιση μιας υπηρεσίας HTTP

Για να διαφημίσετε μια υπηρεσία HTTP, μπορείτε να χρησιμοποιήσετε:
```bash
dns-sd -R "Index" _http._tcp . 80 path=/index.html
```
Αυτή η εντολή καταχωρεί ένα υπηρεσία HTTP με το όνομα "Index" στη θύρα 80 με μονοπάτι `/index.html`.

Για να αναζητήσετε στη συνέχεια υπηρεσίες HTTP στο δίκτυο:
```bash
dns-sd -B _http._tcp
```
Όταν ένας υπηρεσία ξεκινά, ανακοινώνει τη διαθεσιμότητά της σε όλες τις συσκευές στο υποδίκτυο μεταδίδοντας πολλαπλά μηνύματα για την παρουσία της. Οι συσκευές που ενδιαφέρονται για αυτές τις υπηρεσίες δεν χρειάζεται να στείλουν αιτήματα, αλλά απλά να ακούν για αυτές τις ανακοινώσεις.

Για μια πιο φιλική προς τον χρήστη διεπαφή, η εφαρμογή **Discovery - DNS-SD Browser**, διαθέσιμη στο Apple App Store, μπορεί να οπτικοποιήσει τις υπηρεσίες που προσφέρονται στο τοπικό δίκτυο σας.

Εναλλακτικά, μπορούν να γραφούν προσαρμοσμένα scripts για την αναζήτηση και ανακάλυψη υπηρεσιών χρησιμοποιώντας τη βιβλιοθήκη `python-zeroconf`. Το script [**python-zeroconf**](https://github.com/jstasiak/python-zeroconf) δείχνει πώς να δημιουργήσετε έναν περιηγητή υπηρεσιών για τις υπηρεσίες `_http._tcp.local.`, εκτυπώνοντας τις προστιθέμενες ή αφαιρεθείσες υπηρεσίες:
```python
from zeroconf import ServiceBrowser, Zeroconf

class MyListener:

def remove_service(self, zeroconf, type, name):
print("Service %s removed" % (name,))

def add_service(self, zeroconf, type, name):
info = zeroconf.get_service_info(type, name)
print("Service %s added, service info: %s" % (name, info))

zeroconf = Zeroconf()
listener = MyListener()
browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
try:
input("Press enter to exit...\n\n")
finally:
zeroconf.close()
```
### Απενεργοποίηση του Bonjour
Εάν υπάρχουν ανησυχίες για την ασφάλεια ή άλλους λόγους για να απενεργοποιηθεί το Bonjour, μπορεί να γίνει απενεργοποίηση χρησιμοποιώντας την παρακάτω εντολή:
```bash
sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist
```
## Αναφορές

* [**The Mac Hacker's Handbook**](https://www.amazon.com/-/es/Charlie-Miller-ebook-dp-B004U7MUMU/dp/B004U7MUMU/ref=mt\_other?\_encoding=UTF8\&me=\&qid=)
* [**https://taomm.org/vol1/analysis.html**](https://taomm.org/vol1/analysis.html)
* [**https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html**](https://lockboxx.blogspot.com/2019/07/macos-red-teaming-206-ard-apple-remote.html)

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**The PEASS Family**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
