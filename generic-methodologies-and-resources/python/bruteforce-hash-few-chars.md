{% hint style="success" %}
Impara e pratica l'hacking su AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
{% endhint %}
```python
import hashlib

target = '2f2e2e' #/..
candidate = 0
while True:
plaintext = str(candidate)
hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()
if hash[-1*(len(target)):] == target: #End in target
print('plaintext:"' + plaintext + '", md5:' + hash)
break
candidate = candidate + 1
```

```python
#From isHaacK
import hashlib
from multiprocessing import Process, Queue, cpu_count


def loose_comparison(queue, num):
target = '0e'
plaintext = f"a_prefix{str(num)}a_suffix"
hash = hashlib.md5(plaintext.encode('ascii')).hexdigest()

if hash[:len(target)] == target and not any(x in "abcdef" for x in hash[2:]):
print('plaintext: ' + plaintext + ', md5: ' + hash)
queue.put("done") # triggers program exit

def worker(queue, thread_i, threads):
for num in range(thread_i, 100**50, threads):
loose_comparison(queue, num)

def main():
procs = []
queue = Queue()
threads = cpu_count() # 2

for thread_i in range(threads):
proc = Process(target=worker, args=(queue, thread_i, threads ))
proc.daemon = True # kill all subprocess when main process exits.
procs.append(proc)
proc.start()

while queue.empty(): # exits when a subprocess is done
pass
return 0

main()
```
{% hint style="success" %}
Impara e pratica l'hacking su AWS: <img src="/.gitbook/assets/arte.png" alt="" data-size="line">[**HackTricks Training AWS Red Team Expert (ARTE)**](https://training.hacktricks.xyz/courses/arte)<img src="/.gitbook/assets/arte.png" alt="" data-size="line">\
Impara e pratica l'hacking su GCP: <img src="/.gitbook/assets/grte.png" alt="" data-size="line">[**HackTricks Training GCP Red Team Expert (GRTE)**<img src="/.gitbook/assets/grte.png" alt="" data-size="line">](https://training.hacktricks.xyz/courses/grte)

<details>

<summary>Sostieni HackTricks</summary>

* Controlla i [**piani di abbonamento**](https://github.com/sponsors/carlospolop)!
* **Unisciti al** 💬 [**gruppo Discord**](https://discord.gg/hRep4RUj7f) o al [**gruppo telegram**](https://t.me/peass) o **seguici** su **Twitter** 🐦 [**@hacktricks\_live**](https://twitter.com/hacktricks\_live)**.**
* **Condividi trucchi di hacking inviando PR a** [**HackTricks**](https://github.com/carlospolop/hacktricks) e [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos di Github.

</details>
{% endhint %}
