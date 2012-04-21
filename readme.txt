+------------------------------------------------------------------------------+
| ~~~~~~~~~~~~~~~~~~~  Readme k projektu do predmetu PDS  ~~~~~~~~~~~~~~~~~~~~ |
+------------------------------------------------------------------------------+
| Autor: Tomas Mlcoch (xmlcoc06@stud.fit.vutbr.cz)                             |
| Datum: 21.4.2012                                                             |
+------------------------------------------------------------------------------+

            _____        __ _                                      
           / ____|      / _| |                                     
          | (___   ___ | |_| |___      ____ _ _ __ _____   ___   _ 
           \___ \ / _ \|  _| __\ \ /\ / / _` | '__/ _ \ \ / / | | |
           ____) | (_) | | | |_ \ V  V / (_| | | | (_) \ V /| |_| |
          |_____/ \___/|_|  \__| \_/\_/ \__,_|_|  \___/ \_/  \__, |
                                                              __/ |
                                                             |___/ 
                                     _                  
                                    (_)                 
                _ __  _ __ ___ _ __  _ _ __   __ _  ___ 
               | '_ \| '__/ _ \ '_ \| | '_ \ / _` |/ __|
               | |_) | | |  __/ |_) | | | | | (_| | (__ 
               | .__/|_|  \___| .__/|_|_| |_|\__,_|\___|
               | |            | |                       
               |_|            |_|                       



(1) Preklad
====================
 $ make
Vystupni binarka bude pojmenovana "switch".


(2) Spusteni
====================
 $ ./switch
Program musi byt spusten s pravy superuzivatele root.
Bud ji teda spustte primo pod timto uzivatelem, nebo pomoci prikazu sudo.
Program nepouziva parametry prikazove radky.


(3) Ovladani
====================
Program podporuje tyto prikazy
 help - vypise seznam podporovanych prikazu
 cam - vypise obsah cam tabulky
 stat - vypise statistiku prijatych/odeslanych ramcu/bytu pro jednotliva rozhrani
 igmp - vypise obsah igmp tabulky
 quit - ukonci program


(4) Poznamky k implementaci
====================
 - Program po spusteni zacne naslouchat na vsech ethernetovych rozhranich
   (pomoci konstanty PCAP_IF_LOOPBACK identifikuje a vylouci loopbackova rozhrani
   a pomoci funkce pcap_datalink(descriptor) otestuje, zda jde o ethernetove rozhrani)

 - Pro kazde rozhrani je vytvoreno samostatne vlakno, dalsi samostatne vlakno je
   pro uzivatelske rozhrani a posledni samostatne vlakno je vlakno starajici se
   o cisteni tabulky od starych zaznamu. Celkove tedy program vyuziva 2+n vlaken,
   kde n je pocet ethernetovych rozhrani systemu.

