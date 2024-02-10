<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF** ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>

Αυτό το cheatsheet βασίζεται σε μέρος στην [τεκμηρίωση του angr](https://docs.angr.io/_/downloads/en/stable/pdf/).

# Εγκατάσταση
```bash
sudo apt-get install python3-dev libffi-dev build-essential
python3 -m pip install --user virtualenv
python3 -m venv ang
source ang/bin/activate
pip install angr
```
# Βασικές Ενέργειες

## Εισαγωγή

Το angr είναι ένα εργαλείο ανάλυσης δυναμικής εκτέλεσης που χρησιμοποιείται για την ανάλυση και την αυτοματοποίηση της αντίστροφης μηχανικής λογισμικού. Παρέχει μια πληθώρα βασικών ενεργειών που μπορούν να χρησιμοποιηθούν για την εξερεύνηση και την ανάλυση εκτελέσιμων αρχείων.

## Βασικές Ενέργειες

Παρακάτω παρουσιάζονται οι βασικές ενέργειες που μπορούν να εκτελεστούν με το angr:

- **load_binary()**: Φορτώνει ένα εκτελέσιμο αρχείο για ανάλυση.
- **project.factory.entry_state()**: Δημιουργεί ένα αρχικό κατάσταση εκτέλεσης για το εκτελέσιμο αρχείο.
- **project.factory.simgr()**: Δημιουργεί έναν αρχικό διαχειριστή καταστάσεων για το εκτελέσιμο αρχείο.
- **simgr.explore()**: Εξερευνά τον χώρο καταστάσεων του εκτελέσιμου αρχείου.
- **simgr.active**: Επιστρέφει τις ενεργές καταστάσεις από τον διαχειριστή καταστάσεων.
- **state.solver.eval()**: Υπολογίζει την τιμή μιας μεταβλητής σε μια κατάσταση εκτέλεσης.
- **state.solver.constraints**: Επιστρέφει τους περιορισμούς που ισχύουν για μια κατάσταση εκτέλεσης.
- **state.solver.add()**: Προσθέτει έναν περιορισμό σε μια κατάσταση εκτέλεσης.
- **state.solver.satisfiable()**: Ελέγχει αν οι περιορισμοί μιας κατάστασης εκτέλεσης είναι ικανοποιήσιμοι.
- **state.solver.eval_upto()**: Υπολογίζει τις πρώτες n τιμές μιας μεταβλητής σε μια κατάσταση εκτέλεσης.
- **state.solver.BVS()**: Δημιουργεί μια μεταβλητή με μη γνωστή τιμή (Symbolic Variable).
- **state.solver.Solver()**: Δημιουργεί έναν αντικείμενο Solver για την επίλυση περιορισμών.
- **state.solver.add()**: Προσθέτει έναν περιορισμό στον Solver.
- **state.solver.check()**: Ελέγχει αν οι περιορισμοί του Solver είναι ικανοποιήσιμοι.
- **state.solver.model()**: Επιστρέφει μια μοντελοποίηση που ικανοποιεί τους περιορισμούς του Solver.
- **state.solver.eval()**: Υπολογίζει την τιμή μιας μεταβλητής στο πλαίσιο της μοντελοποίησης.
```python
import angr
import monkeyhex # this will format numerical results in hexadecimal
#Load binary
proj = angr.Project('/bin/true')

#BASIC BINARY DATA
proj.arch #Get arch "<Arch AMD64 (LE)>"
proj.arch.name #'AMD64'
proj.arch.memory_endness #'Iend_LE'
proj.entry #Get entrypoint "0x4023c0"
proj.filename #Get filename "/bin/true"

#There are specific options to load binaries
#Usually you won't need to use them but you could
angr.Project('examples/fauxware/fauxware', main_opts={'backend': 'blob', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
```
The loaded data refers to the information that is stored in the memory when a program is executed. This data includes variables, constants, and other resources that are necessary for the program to run properly.

## Main Object

The main object is the central component of a program. It is responsible for controlling the flow of execution and coordinating the actions of other objects. In many programming languages, the main object is the entry point of the program, meaning that it is the first object to be created and executed.

## Information about the Loaded Data and Main Object

When analyzing a program, it is important to gather information about the loaded data and the main object. This information can provide valuable insights into how the program works and can help in identifying vulnerabilities or potential areas of exploitation.

To gather information about the loaded data, you can use various techniques such as static analysis, dynamic analysis, or debugging. These techniques can help you identify the types of data that are loaded into memory, their locations, and their values.

Similarly, to gather information about the main object, you can use techniques such as reverse engineering or code analysis. These techniques can help you understand the structure and behavior of the main object, including its methods, properties, and interactions with other objects.

By gathering information about the loaded data and the main object, you can gain a deeper understanding of the program and its inner workings. This knowledge can be invaluable when it comes to hacking or reverse engineering the program, as it can help you identify potential vulnerabilities or weaknesses that can be exploited.
```python
#LOADED DATA
proj.loader #<Loaded true, maps [0x400000:0x5004000]>
proj.loader.min_addr #0x400000
proj.loader.max_addr #0x5004000
proj.loader.all_objects #All loaded
proj.loader.shared_objects #Loaded binaries
"""
OrderedDict([('true', <ELF Object true, maps [0x400000:0x40a377]>),
('libc.so.6',
<ELF Object libc-2.31.so, maps [0x500000:0x6c4507]>),
('ld-linux-x86-64.so.2',
<ELF Object ld-2.31.so, maps [0x700000:0x72c177]>),
('extern-address space',
<ExternObject Object cle##externs, maps [0x800000:0x87ffff]>),
('cle##tls',
<ELFTLSObjectV2 Object cle##tls, maps [0x900000:0x91500f]>)])
"""
proj.loader.all_elf_objects #Get all ELF objects loaded (Linux)
proj.loader.all_pe_objects #Get all binaries loaded (Windows)
proj.loader.find_object_containing(0x400000)#Get object loaded in an address "<ELF Object fauxware, maps [0x400000:0x60105f]>"
```
## Κύριος Στόχος

The main objective of this document is to provide an introduction to the angr framework and its basic usage. It aims to help beginners understand the fundamentals of angr and how to use it for binary analysis and reverse engineering tasks. By the end of this document, readers should have a clear understanding of angr's capabilities and be able to apply it to solve simple challenges.
```python
#Main Object (main binary loaded)
obj = proj.loader.main_object #<ELF Object true, maps [0x400000:0x60721f]>
obj.execstack #"False" Check for executable stack
obj.pic #"True" Check PIC
obj.imports #Get imports
obj.segments #<Regions: [<ELFSegment flags=0x5, relro=0x0, vaddr=0x400000, memsize=0xa74, filesize=0xa74, offset=0x0>, <ELFSegment flags=0x4, relro=0x1, vaddr=0x600e28, memsize=0x1d8, filesize=0x1d8, offset=0xe28>, <ELFSegment flags=0x6, relro=0x0, vaddr=0x601000, memsize=0x60, filesize=0x50, offset=0x1000>]>
obj.find_segment_containing(obj.entry) #Get segment by address
obj.sections #<Regions: [<Unnamed | offset 0x0, vaddr 0x0, size 0x0>, <.interp | offset 0x238, vaddr 0x400238, size 0x1c>, <.note.ABI-tag | offset 0x254, vaddr 0x400254, size 0x20>, <.note.gnu.build-id ...
obj.find_section_containing(obj.entry) #Get section by address
obj.plt['strcmp'] #Get plt address of a funcion (0x400550)
obj.reverse_plt[0x400550] #Get function from plt address ('strcmp')
```
## Σύμβολα και Επανατοποθετήσεις

Symbols and relocations are important concepts in reverse engineering and binary analysis. They play a crucial role in understanding the structure and behavior of a binary executable.

### Symbols

Symbols are identifiers used to represent various elements in a binary executable, such as functions, variables, and data structures. They provide a way to refer to these elements within the binary and are essential for analyzing and modifying the binary.

Symbols can be classified into two types: global symbols and local symbols. Global symbols are accessible from other parts of the binary, while local symbols are only accessible within a specific scope, such as a function or a module.

In reverse engineering, symbols are often used to identify and analyze specific functions or variables within a binary. They can be used to understand the flow of execution, identify vulnerabilities, and modify the behavior of the binary.

### Relocations

Relocations are instructions or records in a binary executable that specify how to modify the binary's code or data during the linking process. They are used to resolve references to symbols that are not yet known at compile time.

When a binary is compiled, references to symbols are typically represented as placeholders or offsets. During the linking process, relocations are applied to these placeholders to calculate the actual addresses of the symbols.

Relocations are important in reverse engineering because they provide information about the binary's structure and help in understanding how the binary is linked and loaded into memory. By analyzing relocations, reverse engineers can identify and modify the behavior of a binary.

### Conclusion

Symbols and relocations are fundamental concepts in reverse engineering and binary analysis. They provide valuable information about the structure and behavior of a binary executable, enabling reverse engineers to understand, analyze, and modify the binary.
```python
strcmp = proj.loader.find_symbol('strcmp') #<Symbol "strcmp" in libc.so.6 at 0x1089cd0>

strcmp.name #'strcmp'
strcmp.owne #<ELF Object libc-2.23.so, maps [0x1000000:0x13c999f]>
strcmp.rebased_addr #0x1089cd0
strcmp.linked_addr #0x89cd0
strcmp.relative_addr #0x89cd0
strcmp.is_export #True, as 'strcmp' is a function exported by libc

#Get strcmp from the main object
main_strcmp = proj.loader.main_object.get_symbol('strcmp')
main_strcmp.is_export #False
main_strcmp.is_import #True
main_strcmp.resolvedby #<Symbol "strcmp" in libc.so.6 at 0x1089cd0>
```
## Μπλοκ

Τα μπλοκ είναι ένα σημαντικό χαρακτηριστικό του angr που χρησιμοποιείται για την αναπαράσταση των διαφόρων τμημάτων του προγράμματος που αναλύουμε. Ένα μπλοκ αντιπροσωπεύει μια συνεχή ακολουθία εντολών στον κώδικα. Κάθε μπλοκ έχει έναν μοναδικό αριθμό αναγνώρισης (address) που το αναγνωρίζει μοναδικά. Οι μπλοκ μπορούν να περιέχουν εντολές υποκατάστασης (call instructions) που αναφέρονται σε άλλα μπλοκ, δημιουργώντας έτσι ένα γραφοκατάσταση (control flow graph) του προγράμματος.

Οι μπλοκ μπορούν να ανακτηθούν από ένα αντικείμενο `angr.Project` χρησιμοποιώντας τη μέθοδο `project.factory.block()`. Μπορούμε να προσπελάσουμε τις εντολές ενός μπλοκ χρησιμοποιώντας την ιδιότητα `block.instructions`. Επίσης, μπορούμε να πάρουμε τη διεύθυνση (address) ενός μπλοκ χρησιμοποιώντας την ιδιότητα `block.addr`.

Για να εξερευνήσουμε τον γράφο κατάστασης (state graph) του προγράμματος, μπορούμε να προσπελάσουμε τους γείτονες ενός μπλοκ χρησιμοποιώντας τη μέθοδο `block.successors()`. Αυτή η μέθοδος επιστρέφει μια λίστα από αντικείμενα `angr.Block` που αντιπροσωπεύουν τους γείτονες του μπλοκ. Μπορούμε επίσης να πάρουμε την κατάσταση (state) που προκύπτει από την εκτέλεση ενός μπλοκ χρησιμοποιώντας τη μέθοδο `block.final_state()`.
```python
#Blocks
block = proj.factory.block(proj.entry) #Get the block of the entrypoint fo the binary
block.pp() #Print disassembly of the block
block.instructions #"0xb" Get number of instructions
block.instruction_addrs #Get instructions addresses "[0x401670, 0x401672, 0x401675, 0x401676, 0x401679, 0x40167d, 0x40167e, 0x40167f, 0x401686, 0x40168d, 0x401694]"
```
# Δυναμική Ανάλυση

## Διαχειριστής Προσομοίωσης, Καταστάσεις

Ο διαχειριστής προσομοίωσης (Simulation Manager) είναι ένα εργαλείο που χρησιμοποιείται στο πλαίσιο του angr για τη διεξαγωγή δυναμικής ανάλυσης. Ο διαχειριστής προσομοίωσης είναι υπεύθυνος για τη διαχείριση των καταστάσεων (states) κατά την εκτέλεση του προγράμματος.

Οι καταστάσεις (states) αναπαριστούν την κατάσταση του προγράμματος κατά την εκτέλεση. Κάθε κατάσταση περιέχει πληροφορίες όπως την τρέχουσα εντολή, την κατάσταση των μνημών και των μεταβλητών, καθώς και την κατάσταση των μηχανισμών ελέγχου (control flow) του προγράμματος.

Ο διαχειριστής προσομοίωσης επιτρέπει τη δημιουργία και την επεξεργασία καταστάσεων, καθώς και την παρακολούθηση της εκτέλεσης του προγράμματος. Μπορεί επίσης να χρησιμοποιηθεί για την εξαγωγή πληροφοριών από τις καταστάσεις, όπως τις τιμές των μεταβλητών και τις εντολές που εκτελούνται.

Ο διαχειριστής προσομοίωσης είναι ένα ισχυρό εργαλείο που μπορεί να χρησιμοποιηθεί για την ανάλυση και την εξαγωγή πληροφοριών από εκτελέσιμα αρχεία.
```python
#Live States
#This is useful to modify content in a live analysis
state = proj.factory.entry_state()
state.regs.rip #Get the RIP
state.mem[proj.entry].int.resolved #Resolve as a C int (BV)
state.mem[proj.entry].int.concreteved #Resolve as python int
state.regs.rsi = state.solver.BVV(3, 64) #Modify RIP
state.mem[0x1000].long = 4 #Modify mem

#Other States
project.factory.entry_state()
project.factory.blank_state() #Most of its data left uninitialized
project.factory.full_init_statetate() #Execute through any initializers that need to be run before the main binary's entry point
project.factory.call_state() #Ready to execute a given function.

#Simulation manager
#The simulation manager stores all the states across the execution of the binary
simgr = proj.factory.simulation_manager(state) #Start
simgr.step() #Execute one step
simgr.active[0].regs.rip #Get RIP from the last state
```
## Κλήση συναρτήσεων

* Μπορείτε να περάσετε μια λίστα ορισμάτων μέσω του `args` και ένα λεξικό με μεταβλητές περιβάλλοντος μέσω του `env` στους κατασκευαστές `entry_state` και `full_init_state`. Οι τιμές σε αυτές τις δομές μπορούν να είναι συμβολοσειρές ή bitvectors και θα αποθηκευτούν στην κατάσταση ως ορίσματα και περιβάλλον για την προσομοιωμένη εκτέλεση. Το προεπιλεγμένο `args` είναι μια κενή λίστα, οπότε αν το πρόγραμμα που αναλύετε αναμένει να βρει τουλάχιστον ένα `argv[0]`, πρέπει πάντα να το παρέχετε!
* Εάν θέλετε το `argc` να είναι συμβολικό, μπορείτε να περάσετε ένα συμβολικό bitvector ως `argc` στους κατασκευαστές `entry_state` και `full_init_state`. Προσέχετε, όμως: αν κάνετε αυτό, πρέπει επίσης να προσθέσετε ένα περιορισμό στην παραγόμενη κατάσταση ότι η τιμή του argc σας δεν μπορεί να είναι μεγαλύτερη από τον αριθμό των ορισμάτων που περάσατε στο `args`.
* Για να χρησιμοποιήσετε την κατάσταση κλήσης, πρέπει να την καλέσετε με `.call_state(addr, arg1, arg2, ...)`, όπου `addr` είναι η διεύθυνση της συνάρτησης που θέλετε να καλέσετε και `argN` είναι το Nth όρισμα για αυτήν τη συνάρτηση, είτε ως ακέραιος αριθμός, συμβολοσειρά ή πίνακας python, ή ως bitvector. Εάν θέλετε να γίνει εκχώρηση μνήμης και να περάσετε πραγματικά έναν δείκτη σε ένα αντικείμενο, πρέπει να το τυλίξετε σε έναν PointerWrapper, δηλαδή `angr.PointerWrapper("point to me!")`. Τα αποτελέσματα αυτής της διεπαφής μπορεί να είναι λίγο απρόβλεπτα, αλλά δουλεύουμε πάνω σε αυτό. 

## BitVectors
```python
#BitVectors
state = proj.factory.entry_state()
bv = state.solver.BVV(0x1234, 32) #Create BV of 32bits with the value "0x1234"
state.solver.eval(bv) #Convert BV to python int
bv.zero_extend(30) #Will add 30 zeros on the left of the bitvector
bv.sign_extend(30) #Will add 30 zeros or ones on the left of the BV extending the sign
```
## Συμβολικοί BitVectors και Περιορισμοί

Οι συμβολικοί BitVectors είναι μια τεχνική που χρησιμοποιείται στην ανάπτυξη αντιστροφής λογισμικού για να αναπαραστήσει και να επεξεργαστεί δεδομένα συμβολικά. Αντί να αντιμετωπίζουμε τα δεδομένα ως συγκεκριμένες τιμές, τα αναπαριστούμε ως μεταβλητές που μπορούν να πάρουν οποιαδήποτε τιμή από ένα συγκεκριμένο εύρος.

Οι περιορισμοί είναι συνθήκες που επιβάλλονται στις μεταβλητές για να περιορίσουν τις δυνατές τιμές που μπορούν να πάρουν. Οι περιορισμοί μπορούν να περιλαμβάνουν συνθήκες ισότητας, ανισότητας, αριθμητικές πράξεις και λογικές πράξεις.

Χρησιμοποιώντας τους συμβολικούς BitVectors και τους περιορισμούς, μπορούμε να δημιουργήσουμε μια αναπαράσταση του προγράμματος που είναι ανεξάρτητη από τις συγκεκριμένες τιμές των δεδομένων. Αυτό μας επιτρέπει να αναλύσουμε το πρόγραμμα και να εξάγουμε πληροφορίες για τη συμπεριφορά του, ακόμα και χωρίς να γνωρίζουμε τις συγκεκριμένες τιμές των δεδομένων.

Οι συμβολικοί BitVectors και οι περιορισμοί είναι ιδιαίτερα χρήσιμοι για την αντιστροφή προγραμμάτων, την εύρεση ευπαθειών και την ανάλυση κρυπτογραφικών αλγορίθμων. Με τη χρήση αυτών των τεχνικών, μπορούμε να αυτοματοποιήσουμε τη διαδικασία της ανάλυσης και να εξοικονομήσουμε χρόνο και πόρους.
```python
x = state.solver.BVS("x", 64) #Symbolic variable BV of length 64
y = state.solver.BVS("y", 64)

#Symbolic oprations
tree = (x + 1) / (y + 2)
tree #<BV64 (x_9_64 + 0x1) / (y_10_64 + 0x2)>
tree.op #'__floordiv__' Access last operation
tree.args #(<BV64 x_9_64 + 0x1>, <BV64 y_10_64 + 0x2>)
tree.args[0].op #'__add__' Access of dirst arg
tree.args[0].args #(<BV64 x_9_64>, <BV64 0x1>)
tree.args[0].args[1].op #'BVV'
tree.args[0].args[1].args #(1, 64)

#Symbolic constraints solver
state = proj.factory.entry_state() #Get a fresh state without constraints
input = state.solver.BVS('input', 64)
operation = (((input + 4) * 3) >> 1) + input
output = 200
state.solver.add(operation == output)
state.solver.eval(input) #0x3333333333333381
state.solver.add(input < 2**32)
state.satisfiable() #False

#Solver solutions
solver.eval(expression) #one possible solution
solver.eval_one(expression) #solution to the given expression, or throw an error if more than one solution is possible.
solver.eval_upto(expression, n) #n solutions to the given expression, returning fewer than n if fewer than n are possible.
solver.eval_atleast(expression, n) #n solutions to the given expression, throwing an error if fewer than n are possible.
solver.eval_exact(expression, n) #n solutions to the given expression, throwing an error if fewer or more than are possible.
solver.min(expression) #minimum possible solution to the given expression.
solver.max(expression) #maximum possible solution to the given expression.
```
## Σύνδεση (Hooking)

Η σύνδεση (hooking) είναι μια τεχνική που χρησιμοποιείται στον τομέα του χάκινγκ για να τροποποιηθεί ή να παρακολουθηθεί τη λειτουργία ενός προγράμματος. Με τη χρήση της συγκεκριμένης τεχνικής, ο χάκερ μπορεί να εισχωρήσει στον κώδικα του προγράμματος και να τον τροποποιήσει ή να παρακολουθήσει την εκτέλεση των συναρτήσεων.

Η σύνδεση μπορεί να γίνει σε διάφορα επίπεδα, όπως στο επίπεδο του λειτουργικού συστήματος, του εφαρμογών ή ακόμη και σε επίπεδο υλικού. Οι πιο συνηθισμένες μέθοδοι σύνδεσης περιλαμβάνουν την αντικατάσταση συναρτήσεων (function hooking), την παρακολούθηση κλήσεων συστήματος (system call hooking) και την παρακολούθηση της εκτέλεσης ενός προγράμματος (code hooking).

Η σύνδεση μπορεί να χρησιμοποιηθεί για διάφορους σκοπούς, όπως η παρακολούθηση της δραστηριότητας ενός προγράμματος, η αποκάλυψη ευπαθειών, η αποκρυπτογράφηση κρυπτογραφημένων δεδομένων και η εκτέλεση κακόβουλου κώδικα.

Η σύνδεση είναι μια ισχυρή τεχνική που απαιτεί προηγούμενες γνώσεις και εμπειρία στον τομέα του χάκινγκ. Είναι σημαντικό να χρησιμοποιείται με προσοχή και να τηρούνται όλες οι νομικές προϋποθέσεις και περιορισμοί.
```python
>>> stub_func = angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'] # this is a CLASS
>>> proj.hook(0x10000, stub_func())  # hook with an instance of the class

>>> proj.is_hooked(0x10000)            # these functions should be pretty self-explanitory
True
>>> proj.hooked_by(0x10000)
<ReturnUnconstrained>
>>> proj.unhook(0x10000)

>>> @proj.hook(0x20000, length=5)
... def my_hook(state):
...     state.regs.rax = 1

>>> proj.is_hooked(0x20000)
True
```
Επιπλέον, μπορείτε να χρησιμοποιήσετε την εντολή `proj.hook_symbol(name, hook)`, παρέχοντας το όνομα ενός συμβόλου ως πρώτο όρισμα, για να συνδέσετε τη διεύθυνση όπου βρίσκεται το σύμβολο.

# Παραδείγματα

<details>

<summary><strong>Μάθετε το hacking του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Άλλοι τρόποι για να υποστηρίξετε το HackTricks:

* Εάν θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks** ή να **κατεβάσετε το HackTricks σε μορφή PDF**, ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* Ανακαλύψτε [**την Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Εγγραφείτε στη** 💬 [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στη [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** μας στο **Twitter** 🐦 [**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα hacking tricks σας υποβάλλοντας PRs στα** [**HackTricks**](https://github.com/carlospolop/hacktricks) και [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) αποθετήρια του github.

</details>
