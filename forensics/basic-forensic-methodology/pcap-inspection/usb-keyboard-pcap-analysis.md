Si vous avez un fichier pcap d'une connexion USB avec beaucoup d'interruptions, il s'agit probablement d'une connexion de clavier USB.

Un filtre Wireshark comme celui-ci pourrait être utile: `usb.transfer_type == 0x01 and frame.len == 35 and !(usb.capdata == 00:00:00:00:00:00:00:00)`

Il pourrait être important de savoir que les données qui commencent par "02" sont pressées en utilisant la touche shift.

Vous pouvez trouver plus d'informations et trouver des scripts sur la façon d'analyser cela dans:

* [https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4](https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4)
* [https://github.com/tanc7/HacktheBox\_Deadly\_Arthropod\_Writeup](https://github.com/tanc7/HacktheBox_Deadly_Arthropod_Writeup)



<details>

<summary><a href="https://cloud.hacktricks.xyz/pentesting-cloud/pentesting-cloud-methodology"><strong>☁️ HackTricks Cloud ☁️</strong></a> -<a href="https://twitter.com/hacktricks_live"><strong>🐦 Twitter 🐦</strong></a> - <a href="https://www.twitch.tv/hacktricks_live/schedule"><strong>🎙️ Twitch 🎙️</strong></a> - <a href="https://www.youtube.com/@hacktricks_LIVE"><strong>🎥 Youtube 🎥</strong></a></summary>

- Travaillez-vous dans une entreprise de cybersécurité? Voulez-vous voir votre entreprise annoncée dans HackTricks? ou voulez-vous avoir accès à la dernière version de PEASS ou télécharger HackTricks en PDF? Consultez les [PLANS D'ABONNEMENT](https://github.com/sponsors/carlospolop)!

- Découvrez [La famille PEASS](https://opensea.io/collection/the-peass-family), notre collection d'[NFTs](https://opensea.io/collection/the-peass-family) exclusifs.

- Obtenez le [swag officiel PEASS & HackTricks](https://peass.creator-spring.com)

- Rejoignez le [groupe Discord](https://discord.gg/hRep4RUj7f) ou le [groupe Telegram](https://t.me/peass) ou suivez-moi sur Twitter [@carlospolopm](https://twitter.com/hacktricks_live).

- Partagez vos astuces de piratage en soumettant des PR au [dépôt hacktricks](https://github.com/carlospolop/hacktricks) et au [dépôt hacktricks-cloud](https://github.com/carlospolop/hacktricks-cloud).

</details>
