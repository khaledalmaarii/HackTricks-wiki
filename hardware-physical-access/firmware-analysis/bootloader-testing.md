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
{% endhint %}

Τα παρακάτω βήματα συνιστώνται για την τροποποίηση των ρυθμίσεων εκκίνησης συσκευών και των bootloaders όπως το U-boot:

1. **Πρόσβαση στο Shell του Bootloader**:
- Κατά την εκκίνηση, πατήστε "0", space ή άλλους αναγνωρισμένους "μαγικούς κωδικούς" για να αποκτήσετε πρόσβαση στο shell του bootloader.

2. **Τροποποίηση Boot Arguments**:
- Εκτελέστε τις παρακάτω εντολές για να προσθέσετε '`init=/bin/sh`' στα boot arguments, επιτρέποντας την εκτέλεση μιας εντολής shell:
%%%
#printenv
#setenv bootargs=console=ttyS0,115200 mem=63M root=/dev/mtdblock3 mtdparts=sflash:<partitiionInfo> rootfstype=<fstype> hasEeprom=0 5srst=0 init=/bin/sh
#saveenv
#boot
%%%

3. **Ρύθμιση TFTP Server**:
- Ρυθμίστε έναν TFTP server για να φορτώσετε εικόνες μέσω τοπικού δικτύου:
%%%
#setenv ipaddr 192.168.2.2 #τοπική IP της συσκευής
#setenv serverip 192.168.2.1 #IP του TFTP server
#saveenv
#reset
#ping 192.168.2.1 #έλεγχος πρόσβασης στο δίκτυο
#tftp ${loadaddr} uImage-3.6.35 #loadaddr παίρνει τη διεύθυνση για να φορτώσει το αρχείο και το όνομα αρχείου της εικόνας στον TFTP server
%%%

4. **Χρήση του `ubootwrite.py`**:
- Χρησιμοποιήστε το `ubootwrite.py` για να γράψετε την εικόνα U-boot και να σπρώξετε ένα τροποποιημένο firmware για να αποκτήσετε πρόσβαση root.

5. **Έλεγχος Λειτουργιών Debug**:
- Ελέγξτε αν οι λειτουργίες debug όπως η λεπτομερής καταγραφή, η φόρτωση αυθαίρετων πυρήνων ή η εκκίνηση από μη αξιόπιστες πηγές είναι ενεργοποιημένες.

6. **Προσοχή σε Παρεμβολές Υλικού**:
- Να είστε προσεκτικοί όταν συνδέετε ένα ακίδα στο έδαφος και αλληλεπιδράτε με SPI ή NAND flash chips κατά τη διάρκεια της διαδικασίας εκκίνησης της συσκευής, ιδιαίτερα πριν αποσυμπιεστεί ο πυρήνας. Συμβουλευτείτε το datasheet του NAND flash chip πριν βραχυκυκλώσετε ακίδες.

7. **Ρύθμιση Rogue DHCP Server**:
- Ρυθμίστε έναν rogue DHCP server με κακόβουλες παραμέτρους για να τις καταναλώσει η συσκευή κατά την εκκίνηση PXE. Χρησιμοποιήστε εργαλεία όπως το auxiliary server DHCP του Metasploit (MSF). Τροποποιήστε την παράμετρο 'FILENAME' με εντολές injection όπως `'a";/bin/sh;#'` για να δοκιμάσετε την επικύρωση εισόδου για τις διαδικασίες εκκίνησης της συσκευής.

**Σημείωση**: Τα βήματα που περιλαμβάνουν φυσική αλληλεπίδραση με τις ακίδες της συσκευής (*σημειωμένα με αστερίσκους) θα πρέπει να προσεγγίζονται με εξαιρετική προσοχή για να αποφευχθεί η ζημιά στη συσκευή.


## Αναφορές
* [https://scriptingxss.gitbook.io/firmware-security-testing-methodology/](https://scriptingxss.gitbook.io/firmware-security-testing-methodology/)

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
</details>
{% endhint %}
