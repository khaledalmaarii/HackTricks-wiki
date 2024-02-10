# Angr - Παραδείγματα

<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΣΧΕΔΙΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Εγγραφείτε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>

{% hint style="info" %}
Εάν το πρόγραμμα χρησιμοποιεί την `scanf` για να λάβει **πολλές τιμές ταυτόχρονα από το stdin**, χρειάζεστε να δημιουργήσετε ένα κατάσταση που ξεκινά μετά την **`scanf`**.
{% endhint %}

Κωδικοί που έχουν ληφθεί από [https://github.com/jakespringer/angr_ctf](https://github.com/jakespringer/angr_ctf)

### Εισαγωγή για να φτάσετε σε μια διεύθυνση (δηλώνοντας τη διεύθυνση)
```python
import angr
import sys

def main(argv):
path_to_binary = argv[1]  # :string
project = angr.Project(path_to_binary)

# Start in main()
initial_state = project.factory.entry_state()
# Start simulation
simulation = project.factory.simgr(initial_state)

# Find the way yo reach the good address
good_address = 0x804867d

# Avoiding this address
avoid_address = 0x080485A8
simulation.explore(find=good_address , avoid=avoid_address ))

# If found a way to reach the address
if simulation.found:
solution_state = simulation.found[0]

# Print the string that Angr wrote to stdin to follow solution_state
print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Είσοδος για να φτάσετε στη διεύθυνση (δείχνοντας εκτυπώσεις)
```python
# If you don't know the address you want to recah, but you know it's printing something
# You can also indicate that info

import angr
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)
initial_state = project.factory.entry_state()
simulation = project.factory.simgr(initial_state)

def is_successful(state):
#Successful print
stdout_output = state.posix.dumps(sys.stdout.fileno())
return b'Good Job.' in stdout_output

def should_abort(state):
#Avoid this print
stdout_output = state.posix.dumps(sys.stdout.fileno())
return b'Try again.' in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]
print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Τιμές του μητρώου

Οι τιμές του μητρώου είναι καταχωρημένες πληροφορίες που αποθηκεύονται στο μητρώο των λειτουργικών συστημάτων Windows. Αυτές οι τιμές περιέχουν σημαντικές πληροφορίες για το σύστημα, τις εφαρμογές και τις ρυθμίσεις του χρήστη. Οι τιμές του μητρώου μπορούν να περιέχουν συμβολοσειρές, αριθμούς, διευθύνσεις URL και άλλα δεδομένα.

Οι τιμές του μητρώου μπορούν να είναι σημαντικές για την ανάλυση αντικειμένων malware και για την εξαγωγή πληροφοριών για τον τρόπο λειτουργίας ενός συστήματος. Οι εργαλείο ανάλυσης malware μπορούν να χρησιμοποιηθούν για να εξάγουν τις τιμές του μητρώου και να αναλύσουν τη σημασία τους.
```python
# Angr doesn't currently support reading multiple things with scanf (Ex:
# scanf("%u %u).) You will have to tell the simulation engine to begin the
# program after scanf is called and manually inject the symbols into registers.

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

# Address were you want to indicate the relation BitVector - registries
start_address = 0x80488d1
initial_state = project.factory.blank_state(addr=start_address)


# Create Bit Vectors
password0_size_in_bits = 32  # :integer
password0 = claripy.BVS('password0', password0_size_in_bits)

password1_size_in_bits = 32  # :integer
password1 = claripy.BVS('password1', password1_size_in_bits)

password2_size_in_bits = 32  # :integer
password2 = claripy.BVS('password2', password2_size_in_bits)

# Relate it Vectors with the registriy values you are interested in to reach an address
initial_state.regs.eax = password0
initial_state.regs.ebx = password1
initial_state.regs.edx = password2

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution0 = solution_state.solver.eval(password0)
solution1 = solution_state.solver.eval(password1)
solution2 = solution_state.solver.eval(password2)

# Aggregate and format the solutions you computed above, and then print
# the full string. Pay attention to the order of the integers, and the
# expected base (decimal, octal, hexadecimal, etc).
solution = ' '.join(map('{:x}'.format, [ solution0, solution1, solution2 ]))  # :string
print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Τιμές στη στοίβα

Οι τιμές στη στοίβα
```python
# Put bit vectors in th stack to find out the vallue that stack position need to
# have to reach a rogram flow

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

# Go to some address after the scanf where values have already being set in the stack
start_address = 0x8048697
initial_state = project.factory.blank_state(addr=start_address)

# Since we are starting after scanf, we are skipping this stack construction
# step. To make up for this, we need to construct the stack ourselves. Let us
# start by initializing ebp in the exact same way the program does.
initial_state.regs.ebp = initial_state.regs.esp

# In this case scanf("%u %u") is used, so 2 BVS are going to be needed
password0 = claripy.BVS('password0', 32)
password1 = claripy.BVS('password1', 32)

# Now, in the address were you have stopped, check were are the scanf values saved
# Then, substrack form the esp registry the needing padding to get to the
# part of the stack were the scanf values are being saved and push the BVS
# (see the image below to understan this -8)
padding_length_in_bytes = 8  # :integer
initial_state.regs.esp -= padding_length_in_bytes

initial_state.stack_push(password0)
initial_state.stack_push(password1)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution0 = solution_state.solver.eval(password0)
solution1 = solution_state.solver.eval(password1)

solution = ' '.join(map(str, [ solution0, solution1 ]))
print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
Σε αυτό το σενάριο, η είσοδος πήρε με τη χρήση της `scanf("%u %u")` και δόθηκε η τιμή `"1 1"`, οπότε οι τιμές **`0x00000001`** του stack προέρχονται από την **είσοδο του χρήστη**. Μπορείτε να δείτε πώς αυτές οι τιμές ξεκινούν στο `$ebp - 8`. Επομένως, στον κώδικα έχουμε **αφαιρέσει 8 bytes από το `$esp` (καθώς τη στιγμή εκείνη το `$ebp` και το `$esp` είχαν την ίδια τιμή)** και στη συνέχεια έχουμε πιέσει το BVS.

![](<../../../.gitbook/assets/image (614).png>)

### Τιμές Στατικής Μνήμης (Παγκόσμιες μεταβλητές)
```python
import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

#Get an address after the scanf. Once the input has already being saved in the memory positions
start_address = 0x8048606
initial_state = project.factory.blank_state(addr=start_address)

# The binary is calling scanf("%8s %8s %8s %8s").
# So we need 4 BVS of size 8*8
password0 = claripy.BVS('password0', 8*8)
password1 = claripy.BVS('password1', 8*8)
password2 = claripy.BVS('password2', 8*8)
password3 = claripy.BVS('password3', 8*8)

# Write the symbolic BVS in the memory positions
password0_address = 0xa29faa0
initial_state.memory.store(password0_address, password0)
password1_address = 0xa29faa8
initial_state.memory.store(password1_address, password1)
password2_address = 0xa29fab0
initial_state.memory.store(password2_address, password2)
password3_address = 0xa29fab8
initial_state.memory.store(password3_address, password3)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

# Get the values the memory addresses should store
solution0 = solution_state.solver.eval(password0,cast_to=bytes).decode()
solution1 = solution_state.solver.eval(password1,cast_to=bytes).decode()
solution2 = solution_state.solver.eval(password2,cast_to=bytes).decode()
solution3 = solution_state.solver.eval(password3,cast_to=bytes).decode()

solution = ' '.join([ solution0, solution1, solution2, solution3 ])

print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Δυναμικές Τιμές Μνήμης (Malloc)

Ο ανιχνευτής αυτόματης ανάλυσης αποτελεί ένα ισχυρό εργαλείο για την ανάλυση αντικειμένων που χρησιμοποιούν δυναμική μνήμη. Με τη χρήση του ανιχνευτή, μπορούμε να εντοπίσουμε τις τιμές της μνήμης που δεσμεύονται με τη χρήση της συνάρτησης `malloc`. Αυτό μας επιτρέπει να ανακτήσουμε πληροφορίες για την κατάσταση της μνήμης κατά την εκτέλεση του προγράμματος.

Για να εκμεταλλευτούμε αυτήν τη λειτουργία, πρέπει να ορίσουμε μια συνάρτηση ανάλυσης που θα καλείται κάθε φορά που γίνεται κλήση της `malloc`. Μέσω αυτής της συνάρτησης, μπορούμε να παρακολουθούμε τις τιμές της μνήμης που δεσμεύονται και να εξάγουμε πληροφορίες για την εκτέλεση του προγράμματος.

Ο ανιχνευτής αυτόματης ανάλυσης μπορεί να χρησιμοποιηθεί για να εντοπίσει πιθανές ευπάθειες ασφάλειας που σχετίζονται με τη διαχείριση της μνήμης, όπως τη διαρροή μνήμης ή την υπερχείλιση του buffer. Επίσης, μπορεί να χρησιμοποιηθεί για να εντοπίσει πιθανές ευπάθειες που σχετίζονται με την αλληλεπίδραση με άλλα αντικείμενα στη μνήμη, όπως την ανάγνωση ή την εγγραφή σε μη επιτρεπτές περιοχές μνήμης.
```python
import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

# Get address after scanf
start_address = 0x804869e
initial_state = project.factory.blank_state(addr=start_address)

# The binary is calling scanf("%8s %8s") so 2 BVS are needed.
password0 = claripy.BVS('password0', 8*8)
password1 = claripy.BVS('password0', 8*8)

# Find a coupble of addresses that aren't used by the binary (like 0x4444444 & 0x4444454)
# The address generated by mallosc is going to be saved in some address
# Then, make that address point to the fake heap addresses were the BVS are going to be saved
fake_heap_address0 = 0x4444444
pointer_to_malloc_memory_address0 = 0xa79a118
initial_state.memory.store(pointer_to_malloc_memory_address0, fake_heap_address0, endness=project.arch.memory_endness)
fake_heap_address1 = 0x4444454
pointer_to_malloc_memory_address1 = 0xa79a120
initial_state.memory.store(pointer_to_malloc_memory_address1, fake_heap_address1, endness=project.arch.memory_endness)

# Save the VBS in the new fake heap addresses created
initial_state.memory.store(fake_heap_address0, password0)
initial_state.memory.store(fake_heap_address1, password1)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution0 = solution_state.solver.eval(password0,cast_to=bytes).decode()
solution1 = solution_state.solver.eval(password1,cast_to=bytes).decode()

solution = ' '.join([ solution0, solution1 ])

print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Προσομοίωση Αρχείου

Η προσομοίωση αρχείου είναι μια τεχνική που χρησιμοποιείται στον τομέα της ανάπτυξης λογισμικού για να αναπαραστήσει τη συμπεριφορά ενός αρχείου χωρίς να χρειάζεται να το εκτελέσει πραγματικά. Αυτή η τεχνική είναι χρήσιμη για την ανάλυση και την αποσφαλμάτωση λογισμικού, καθώς επιτρέπει στους προγραμματιστές να εξετάσουν τη συμπεριφορά του αρχείου χωρίς να το ανοίξουν ή να το εκτελέσουν σε ένα πραγματικό περιβάλλον.

Η προσομοίωση αρχείου μπορεί να γίνει χρησιμοποιώντας εργαλεία όπως το angr. Το angr είναι ένα εργαλείο ανάλυσης αρχείων που μπορεί να χρησιμοποιηθεί για την εξέταση και την ανάλυση της συμπεριφοράς ενός αρχείου. Με το angr, μπορείτε να προσομοιώσετε την εκτέλεση ενός αρχείου, να εξετάσετε την αλληλεπίδρασή του με άλλα αρχεία και να ανακτήσετε πληροφορίες για τον κώδικα που εκτελείται.

Η προσομοίωση αρχείου με το angr μπορεί να γίνει με τη χρήση της γλώσσας προγραμματισμού Python. Μπορείτε να ορίσετε το αρχείο που θέλετε να προσομοιώσετε και να εξετάσετε τη συμπεριφορά του χρησιμοποιώντας τις διάφορες δυνατότητες του angr. Αυτό σας επιτρέπει να εντοπίσετε πιθανές ευπάθειες ή αδυναμίες στον κώδικα του αρχείου και να προβλέψετε τη συμπεριφορά του σε διάφορες συνθήκες.

Η προσομοίωση αρχείου είναι ένα ισχυρό εργαλείο που μπορεί να χρησιμοποιηθεί για την ανάλυση και την αποσφαλμάτωση λογισμικού. Με τη χρήση του angr και άλλων αντίστοιχων εργαλείων, μπορείτε να αποκτήσετε μια καλύτερη κατανόηση της συμπεριφοράς των αρχείων και να βελτιώσετε την ασφάλεια και την απόδοση του λογισμικού σας.
```python
#In this challenge a password is read from a file and we want to simulate its content

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

# Get an address just before opening the file with th simbolic content
# Or at least when the file is not going to suffer more changes before being read
start_address = 0x80488db
initial_state = project.factory.blank_state(addr=start_address)

# Specify the filena that is going to open
# Note that in theory, the filename could be symbolic.
filename = 'WCEXPXBW.txt'
symbolic_file_size_bytes = 64

# Create a BV which is going to be the content of the simbolic file
password = claripy.BVS('password', symbolic_file_size_bytes * 8)

# Create the file simulation with the simbolic content
password_file = angr.storage.SimFile(filename, content=password)

# Add the symbolic file we created to the symbolic filesystem.
initial_state.fs.insert(filename, password_file)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution = solution_state.solver.eval(password,cast_to=bytes).decode()

print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
{% hint style="info" %}
Να σημειωθεί ότι το συμβολικό αρχείο μπορεί επίσης να περιέχει σταθερά δεδομένα που έχουν συγχωνευτεί με συμβολικά δεδομένα:
```python
# Hello world, my name is John.
# ^                       ^
# ^ address 0             ^ address 24 (count the number of characters)
# In order to represent this in memory, we would want to write the string to
# the beginning of the file:
#
# hello_txt_contents = claripy.BVV('Hello world, my name is John.', 30*8)
#
# Perhaps, then, we would want to replace John with a
# symbolic variable. We would call:
#
# name_bitvector = claripy.BVS('symbolic_name', 4*8)
#
# Then, after the program calls fopen('hello.txt', 'r') and then
# fread(buffer, sizeof(char), 30, hello_txt_file), the buffer would contain
# the string from the file, except four symbolic bytes where the name would be
# stored.
# (!)
```
{% endhint %}

### Εφαρμογή Περιορισμών

{% hint style="info" %}
Μερικές φορές απλές ανθρώπινες λειτουργίες όπως η σύγκριση 2 λέξεων μήκους 16 **χαρακτήρων χαρακτήρα προς χαρακτήρα** (βρόχος), **κοστίζουν πολύ στο angr** επειδή χρειάζεται να δημιουργήσει κλαδιά **εκθετικά** επειδή δημιουργεί 1 κλάδο ανά if: `2^16`\
Για αυτόν τον λόγο, είναι πιο εύκολο να **ζητήσετε από το angr να φτάσει σε ένα προηγούμενο σημείο** (όπου η πραγματικά δύσκολη μέρα έχει ήδη γίνει) και να **ορίσετε αυτούς τους περιορισμούς χειροκίνητα**.
{% endhint %}
```python
# After perform some complex poperations to the input the program checks
# char by char the password against another password saved, like in the snippet:
#
# #define REFERENCE_PASSWORD = "AABBCCDDEEFFGGHH";
# int check_equals_AABBCCDDEEFFGGHH(char* to_check, size_t length) {
#   uint32_t num_correct = 0;
#   for (int i=0; i<length; ++i) {
#     if (to_check[i] == REFERENCE_PASSWORD[i]) {
#       num_correct += 1;
#     }
#   }
#   return num_correct == length;
# }
#
# ...
#
# char* input = user_input();
# char* encrypted_input = complex_function(input);
# if (check_equals_AABBCCDDEEFFGGHH(encrypted_input, 16)) {
#   puts("Good Job.");
# } else {
#   puts("Try again.");
# }
#
# The function checks if *to_check == "AABBCCDDEEFFGGHH". This is very RAM consumming
# as the computer needs to branch every time the if statement in the loop was called (16
# times), resulting in 2^16 = 65,536 branches, which will take too long of a
# time to evaluate for our needs.

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

simulation = project.factory.simgr(initial_state)

# Get an address to check after the complex function and before the "easy compare" operation
address_to_check_constraint = 0x8048671
simulation.explore(find=address_to_check_constraint)


if simulation.found:
solution_state = simulation.found[0]

# Find were the input that is going to be compared is saved in memory
constrained_parameter_address = 0x804a050
constrained_parameter_size_bytes = 16
# Set the bitvector
constrained_parameter_bitvector = solution_state.memory.load(
constrained_parameter_address,
constrained_parameter_size_bytes
)

# Indicate angr that this BV at this point needs to be equal to the password
constrained_parameter_desired_value = 'BWYRUBQCMVSBRGFU'.encode()
solution_state.add_constraints(constrained_parameter_bitvector == constrained_parameter_desired_value)

print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
{% hint style="danger" %}
Σε ορισμένα σενάρια μπορείτε να ενεργοποιήσετε το **veritesting**, το οποίο θα συγχωνεύσει παρόμοιες καταστάσεις, προκειμένου να εξοικονομήσει άχρηστα κλαδιά και να βρει τη λύση: `simulation = project.factory.simgr(initial_state, veritesting=True)`
{% endhint %}

{% hint style="info" %}
Μια άλλη πράξη που μπορείτε να κάνετε σε αυτά τα σενάρια είναι να **συνδέσετε τη συνάρτηση δίνοντας στο angr κάτι που μπορεί να κατανοήσει** πιο εύκολα.
{% endhint %}

### Διαχειριστές Προσομοίωσης

Ορισμένοι διαχειριστές προσομοίωσης μπορεί να είναι πιο χρήσιμοι από άλλους. Στο προηγούμενο παράδειγμα υπήρχε ένα πρόβλημα καθώς δημιουργήθηκαν πολλά χρήσιμα κλαδιά. Εδώ, η τεχνική **veritesting** θα συγχωνεύσει αυτά τα κλαδιά και θα βρει μια λύση.\
Αυτός ο διαχειριστής προσομοίωσης μπορεί επίσης να ενεργοποιηθεί με: `simulation = project.factory.simgr(initial_state, veritesting=True)`
```python
import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

simulation = project.factory.simgr(initial_state)
# Set simulation technique
simulation.use_technique(angr.exploration_techniques.Veritesting())


def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())

return 'Good Job.'.encode() in stdout_output  # :boolean

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output  # :boolean

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]
print(solution_state.posix.dumps(sys.stdin.fileno()))
else:
raise Exception('Could not find the solution')


if __name__ == '__main__':
main(sys.argv)
```
### Σύνδεση/Παράκαμψη μίας κλήσης σε μία συνάρτηση

Για να γίνει σύνδεση ή παράκαμψη μίας κλήσης σε μία συνάρτηση, μπορούμε να χρησιμοποιήσουμε την τεχνική του hooking. Η τεχνική αυτή επιτρέπει την αντικατάσταση της κλήσης μίας συνάρτησης με μία δική μας υλοποίηση.

Για να επιτευχθεί αυτό, μπορούμε να χρησιμοποιήσουμε το εργαλείο angr. Το angr μας παρέχει τη δυνατότητα να αναλύσουμε τον κώδικα και να εντοπίσουμε τις κλήσεις συναρτήσεων. Έπειτα, μπορούμε να χρησιμοποιήσουμε τη μέθοδο `hook` για να αντικαταστήσουμε την κλήση με τη δική μας υλοποίηση.

Η αντικατάσταση μίας κλήσης μπορεί να χρησιμοποιηθεί για πολλούς σκοπούς, όπως για παράκαμψη ελέγχων ασφαλείας ή για την παρακολούθηση της ροής του προγράμματος.
```python
# This level performs the following computations:
#
# 1. Get 16 bytes of user input and encrypt it.
# 2. Save the result of check_equals_AABBCCDDEEFFGGHH (or similar)
# 3. Get another 16 bytes from the user and encrypt it.
# 4. Check that it's equal to a predefined password.
#
# The ONLY part of this program that we have to worry about is #2. We will be
# replacing the call to check_equals_ with our own version, using a hook, since
# check_equals_ will run too slowly otherwise.

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

# Hook the address of the call to hook indicating th length of the instruction (of the call)
check_equals_called_address = 0x80486b8
instruction_to_skip_length = 5
@project.hook(check_equals_called_address, length=instruction_to_skip_length)
def skip_check_equals_(state):
#Load the input of the function reading direcly the memory
user_input_buffer_address = 0x804a054
user_input_buffer_length = 16
user_input_string = state.memory.load(
user_input_buffer_address,
user_input_buffer_length
)

# Create a simbolic IF that if the loaded string frommemory is the expected
# return True (1) if not returns False (0) in eax
check_against_string = 'XKSPZSJKJYQCQXZV'.encode() # :string

state.regs.eax = claripy.If(
user_input_string == check_against_string,
claripy.BVV(1, 32),
claripy.BVV(0, 32)
)

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]
solution = solution_state.posix.dumps(sys.stdin.fileno()).decode()
print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Σύνδεση μιας συνάρτησης / Συνδιαδικασία

Η σύνδεση μιας συνάρτησης (hooking) είναι μια τεχνική που χρησιμοποιείται στον αντίστροφο μηχανισμό για να αντικαταστήσει μια συνάρτηση με μια δική μας υλοποίηση. Αυτό μας επιτρέπει να ελέγχουμε τη ροή του προγράμματος και να παρακολουθούμε τις ενέργειες που πραγματοποιούνται από τη συνάρτηση.

Για να επιτευχθεί αυτό, χρησιμοποιούμε μια συνδιαδικασία (simprocedure) που αντικαθιστά την αρχική συνάρτηση. Η συνδιαδικασία αυτή εκτελείται αντί της αρχικής συνάρτησης και μπορούμε να την προγραμματίσουμε ώστε να εκτελεί τις ενέργειες που επιθυμούμε.

Με αυτόν τον τρόπο, μπορούμε να παρακολουθούμε τις παραμέτρους που περνούνται στη συνάρτηση, να τροποποιούμε τις επιστρεφόμενες τιμές και να ελέγχουμε την εκτέλεση του προγράμματος. Αυτή η τεχνική είναι χρήσιμη για την ανάλυση και την αντιμετώπιση κακόβουλου λογισμικού.
```python
# Hook to the function called check_equals_WQNDNKKWAWOLXBAC

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

# Define a class and a tun method to hook completelly a function
class ReplacementCheckEquals(angr.SimProcedure):
# This C code:
#
# int add_if_positive(int a, int b) {
#   if (a >= 0 && b >= 0) return a + b;
#   else return 0;
# }
#
# could be simulated with python:
#
# class ReplacementAddIfPositive(angr.SimProcedure):
#   def run(self, a, b):
#     if a >= 0 and b >=0:
#       return a + b
#     else:
#       return 0
#
# run(...) receives the params of the hooked function
def run(self, to_check, length):
user_input_buffer_address = to_check
user_input_buffer_length = length

# Read the data from the memory address given to the function
user_input_string = self.state.memory.load(
user_input_buffer_address,
user_input_buffer_length
)

check_against_string = 'WQNDNKKWAWOLXBAC'.encode()

# Return 1 if equals to the string, 0 otherways
return claripy.If(
user_input_string == check_against_string,
claripy.BVV(1, 32),
claripy.BVV(0, 32)
)


# Hook the check_equals symbol. Angr automatically looks up the address
# associated with the symbol. Alternatively, you can use 'hook' instead
# of 'hook_symbol' and specify the address of the function. To find the
# correct symbol, disassemble the binary.
# (!)
check_equals_symbol = 'check_equals_WQNDNKKWAWOLXBAC' # :string
project.hook_symbol(check_equals_symbol, ReplacementCheckEquals())

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

solution = solution_state.posix.dumps(sys.stdin.fileno()).decode()
print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Προσομοίωση της συνάρτησης scanf με πολλαπλά ορίσματα

Για να προσομοιώσουμε τη συμπεριφορά της συνάρτησης scanf με πολλαπλά ορίσματα, μπορούμε να χρησιμοποιήσουμε το εργαλείο angr. Το angr είναι ένα εργαλείο ανάλυσης δυναμικού κώδικα που μας επιτρέπει να προσομοιώσουμε την εκτέλεση ενός προγράμματος και να ελέγξουμε την κατάσταση της μνήμης και των μεταβλητών.

Για να προσομοιώσουμε τη συνάρτηση scanf με πολλαπλά ορίσματα, πρέπει να ορίσουμε τις τιμές που θέλουμε να διαβάσει η scanf και να τις εισάγουμε στη μνήμη του προγράμματος. Στη συνέχεια, μπορούμε να χρησιμοποιήσουμε το angr για να προσομοιώσουμε την εκτέλεση του προγράμματος και να ελέγξουμε τις τιμές που διαβάστηκαν από τη scanf.

Ένα παράδειγμα κώδικα σε C που χρησιμοποιεί τη συνάρτηση scanf με πολλαπλά ορίσματα είναι το εξής:

```c
#include <stdio.h>

int main() {
    int num1, num2;
    printf("Enter two numbers: ");
    scanf("%d %d", &num1, &num2);
    printf("You entered: %d and %d\n", num1, num2);
    return 0;
}
```

Για να προσομοιώσουμε την εκτέλεση αυτού του προγράμματος με το angr, μπορούμε να χρησιμοποιήσουμε τον παρακάτω κώδικα Python:

```python
import angr

def main():
    project = angr.Project("./program")
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state)

    simulation.explore(find=lambda s: b"You entered:" in s.posix.dumps(1))

    if simulation.found:
        solution_state = simulation.found[0]
        num1 = solution_state.solver.eval(solution_state.memory.load(num1_address, 4), cast_to=int)
        num2 = solution_state.solver.eval(solution_state.memory.load(num2_address, 4), cast_to=int)
        print(f"You entered: {num1} and {num2}")
    else:
        print("Solution not found.")

if __name__ == "__main__":
    main()
```

Σε αυτόν τον κώδικα, ορίζουμε το αρχείο προγράμματος που θέλουμε να προσομοιώσουμε (στην περίπτωσή μας το "program"), δημιουργούμε έναν αρχικό κατάστασης για το angr και εκτελούμε την προσομοίωση. Στη συνέχεια, ελέγχουμε αν βρέθηκε μια λύση και αν ναι, εξάγουμε τις τιμές που διαβάστηκαν από τη scanf και τις εκτυπώνουμε.

Με αυτόν τον τρόπο, μπορούμε να προσομοιώσουμε τη συνάρτηση scanf με πολλαπλά ορίσματα χρησιμοποιώντας το angr.
```python
# This time, the solution involves simply replacing scanf with our own version,
# since Angr does not support requesting multiple parameters with scanf.

import angr
import claripy
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

class ReplacementScanf(angr.SimProcedure):
# The code uses: 'scanf("%u %u", ...)'
def run(self, format_string, param0, param1):
scanf0 = claripy.BVS('scanf0', 32)
scanf1 = claripy.BVS('scanf1', 32)

# Get the addresses from the params and store the BVS in memory
scanf0_address = param0
self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
scanf1_address = param1
self.state.memory.store(scanf1_address, scanf1, endness=project.arch.memory_endness)

# Now, we want to 'set aside' references to our symbolic values in the
# globals plugin included by default with a state. You will need to
# store multiple bitvectors. You can either use a list, tuple, or multiple
# keys to reference the different bitvectors.
self.state.globals['solutions'] = (scanf0, scanf1)

scanf_symbol = '__isoc99_scanf'
project.hook_symbol(scanf_symbol, ReplacementScanf())

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]

# Grab whatever you set aside in the globals dict.
stored_solutions = solution_state.globals['solutions']
solution = ' '.join(map(str, map(solution_state.solver.eval, stored_solutions)))

print(solution)
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
### Στατικά Δυαδικά Αρχεία

Τα στατικά δυαδικά αρχεία είναι εκτελέσιμα αρχεία που περιέχουν όλες τις απαραίτητες βιβλιοθήκες και εξαρτήσεις που απαιτούνται για να εκτελεστούν ανεξάρτητα από το σύστημα. Αυτό σημαίνει ότι δεν απαιτείται η εγκατάσταση ή η ύπαρξη εξωτερικών βιβλιοθηκών για να εκτελεστεί το πρόγραμμα.

Τα στατικά δυαδικά αρχεία μπορούν να είναι χρήσιμα στον τομέα της ανάπτυξης λογισμικού, καθώς εξασφαλίζουν ότι το πρόγραμμα θα εκτελεστεί με τις απαιτούμενες εξαρτήσεις, ανεξάρτητα από το περιβάλλον εκτέλεσης. Επίσης, μπορούν να χρησιμοποιηθούν σε αντικείμενα ανάλυσης και αντιστροφής μηχανικής, καθώς επιτρέπουν την εξέταση του προγράμματος χωρίς την ανάγκη για εξωτερικές εξαρτήσεις.

Για να αναλύσουμε ένα στατικό δυαδικό αρχείο, μπορούμε να χρησιμοποιήσουμε εργαλεία όπως το `objdump` ή το `readelf` για να εξάγουμε πληροφορίες για τον κώδικα, τις συναρτήσεις και τις μεταβλητές που περιέχει το αρχείο. Αυτές οι πληροφορίες μπορούν να μας βοηθήσουν να κατανοήσουμε τη λειτουργία του προγράμματος και να ανακαλύψουμε πιθανές ευπάθειες ή ευκαιρίες για εκμετάλλευση.
```python
# This challenge is the exact same as the first challenge, except that it was
# compiled as a static binary. Normally, Angr automatically replaces standard
# library functions with SimProcedures that work much more quickly.
#
# To solve the challenge, manually hook any standard library c functions that
# are used. Then, ensure that you begin the execution at the beginning of the
# main function. Do not use entry_state.
#
# Here are a few SimProcedures Angr has already written for you. They implement
# standard library functions. You will not need all of them:
# angr.SIM_PROCEDURES['libc']['malloc']
# angr.SIM_PROCEDURES['libc']['fopen']
# angr.SIM_PROCEDURES['libc']['fclose']
# angr.SIM_PROCEDURES['libc']['fwrite']
# angr.SIM_PROCEDURES['libc']['getchar']
# angr.SIM_PROCEDURES['libc']['strncmp']
# angr.SIM_PROCEDURES['libc']['strcmp']
# angr.SIM_PROCEDURES['libc']['scanf']
# angr.SIM_PROCEDURES['libc']['printf']
# angr.SIM_PROCEDURES['libc']['puts']
# angr.SIM_PROCEDURES['libc']['exit']
#
# As a reminder, you can hook functions with something similar to:
# project.hook(malloc_address, angr.SIM_PROCEDURES['libc']['malloc']())
#
# There are many more, see:
# https://github.com/angr/angr/tree/master/angr/procedures/libc

import angr
import sys

def main(argv):
path_to_binary = argv[1]
project = angr.Project(path_to_binary)

initial_state = project.factory.entry_state()

#Find the addresses were the lib functions are loaded in the binary
#For example you could find: call   0x804ed80 <__isoc99_scanf>
project.hook(0x804ed40, angr.SIM_PROCEDURES['libc']['printf']())
project.hook(0x804ed80, angr.SIM_PROCEDURES['libc']['scanf']())
project.hook(0x804f350, angr.SIM_PROCEDURES['libc']['puts']())
project.hook(0x8048d10, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

simulation = project.factory.simgr(initial_state)

def is_successful(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Good Job.'.encode() in stdout_output  # :boolean

def should_abort(state):
stdout_output = state.posix.dumps(sys.stdout.fileno())
return 'Try again.'.encode() in stdout_output  # :boolean

simulation.explore(find=is_successful, avoid=should_abort)

if simulation.found:
solution_state = simulation.found[0]
print(solution_state.posix.dumps(sys.stdin.fileno()).decode())
else:
raise Exception('Could not find the solution')

if __name__ == '__main__':
main(sys.argv)
```
<details>

<summary><strong>Μάθετε το χάκινγκ του AWS από το μηδέν μέχρι τον ήρωα με το</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

* Εργάζεστε σε μια **εταιρεία κυβερνοασφάλειας**; Θέλετε να δείτε την **εταιρεία σας να διαφημίζεται στο HackTricks**; Ή θέλετε να έχετε πρόσβαση στην **τελευταία έκδοση του PEASS ή να κατεβάσετε το HackTricks σε μορφή PDF**; Ελέγξτε τα [**ΠΑΚΕΤΑ ΣΥΝΔΡΟΜΗΣ**](https://github.com/sponsors/carlospolop)!
* Ανακαλύψτε την [**Οικογένεια PEASS**](https://opensea.io/collection/the-peass-family), τη συλλογή μας από αποκλειστικά [**NFTs**](https://opensea.io/collection/the-peass-family)
* Αποκτήστε το [**επίσημο PEASS & HackTricks swag**](https://peass.creator-spring.com)
* **Συμμετάσχετε** στην [**💬**](https://emojipedia.org/speech-balloon/) [**ομάδα Discord**](https://discord.gg/hRep4RUj7f) ή στην [**ομάδα telegram**](https://t.me/peass) ή **ακολουθήστε** με στο **Twitter** 🐦[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Μοιραστείτε τα χάκινγκ κόλπα σας υποβάλλοντας PRs στο [αποθετήριο hacktricks](https://github.com/carlospolop/hacktricks) και [αποθετήριο hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud)**.

</details>
