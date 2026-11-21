# VicoVPN — notes de version

## Résumé du 21 novembre 2026 (versions 1.1.2 à 1.1.5)

**Réseau et sécurité**
- L'IPv6 du PC revient dès qu'on désactive VicoVPN, même après un plantage ou un redémarrage en plein mode Tor.
- « Restaurer auto » remet vraiment les DNS en automatique (IPv4 et IPv6, toutes les cartes), sans écraser la sauvegarde d'origine.
- Si tun2socks plante, plus aucune fuite : le trafic est bloqué au lieu de sortir en clair par la box.
- L'outil de réparation remet aussi l'IPv6.

**Protection maison**
- Nouveau bouton « Basculer tous les appareils maintenant » : redémarrage automatique du Wi-Fi sur Freebox, marche à suivre pour Livebox, Bbox, SFR et les autres.
- Nouvelle option « Au démarrage du PC : ouvrir VicoVPN et relancer la protection maison » : la fenêtre s'ouvre à l'ouverture de session et la protection repart dès que le réseau est prêt (au lieu de 40 secondes).

**Interface**
- Le tuto de démarrage réapparaît correctement ; la case « Ne plus afficher » reflète le vrai réglage.
- Chaque bannière pub ouvre la page de son logiciel sur hardware24.fr.

**Projet**
- VicoVPN devient open source sous licence GPL-3.0 : code publié sur GitHub (vico-hardware/VicoVPN), compilation automatique de l'installateur, préparation de la signature gratuite SignPath.
- Droits protégés : copyright vico-hardware dans chaque fichier, fichier NOTICE, marque et visuels Vico réservés.
- L'installateur affiche le copyright et la licence ; les accents cassés de l'installateur sont corrigés.

## 1.1.5 — 21 novembre 2026
- **Démarrage du PC :** l'option de l'onglet Maison devient « Au démarrage du PC : ouvrir VicoVPN et relancer la protection maison ». Cochée, elle ouvre aussi la fenêtre de VicoVPN à l'ouverture de session, pour voir la relance en direct.
- **Relance plus rapide :** la protection maison repart dès que le réseau est prêt, au lieu d'attendre 40 secondes.
- La désinstallation retire VicoVPN du démarrage de Windows.
- **Open source :** code publié sous GPL-3.0 (copyright vico-hardware, marque Vico réservée — voir `NOTICE`). L'installateur affiche la licence et le copyright.

## 1.1.4 — 21 novembre 2026
- **Nouveau : « Basculer tous les appareils maintenant »** (onglet Maison, protection active). Avec une Freebox, VicoVPN éteint puis rallume le Wi-Fi de la box : tous les appareils se reconnectent en passant par le PC. Avec les autres box (Livebox, Bbox, SFR…), le bouton affiche la marche à suivre.
- **Bannières :** chaque pub ouvre directement la page de son logiciel sur hardware24.fr (`logiciels.html#vicovox`, `#vicowave`, `#vicoforge`, `#vicomedia`, `#vicovoice-ai`).

## 1.1.3 — 21 novembre 2026
- **Nouveau :** option pour relancer la protection maison au démarrage du PC (case à cocher dans l'onglet Maison).
- **Sécurité :** si tun2socks plante pendant le mode Tor, le trafic du PC et des appareils de la maison est bloqué au lieu de sortir en clair par la box.
- **Tuto :** la case « Ne plus afficher au démarrage » montre le vrai réglage ; la décocher remet le tuto au démarrage.
- L'outil de réparation remet aussi l'IPv6 des cartes réseau.

## 1.1.2 — 21 novembre 2026
- **IPv6 :** désactiver VicoVPN rallume l'IPv6 du PC, même après un plantage ou un redémarrage pendant le mode Tor. Le coupe-circuit est retiré avant, pour que la box puisse redonner une adresse IPv6 tout de suite.
- **Restaurer auto :** remet vraiment les DNS en automatique, en IPv4 et en IPv6, sur toutes les cartes. La sauvegarde des DNS d'origine n'est plus écrasée à chaque « Appliquer ».

## 1.1.1 — 20 novembre 2026
- **Nouvelle disposition :** bannière en haut sur toute la largeur, cartes VicoVPN et DNS côte à côte, journal en dessous sur toute la largeur.
- La fenêtre s'adapte à l'écran à l'ouverture et la page se met à l'échelle si l'écran est petit.
- Le DNS s'appelle **AdZ-Vanced** (marqué « conseillé » dans la liste).
- Le tuto s'affiche de nouveau au lancement : la case « Ne plus afficher » est décochée par défaut.

## 1.1.0 — 18 novembre 2026
- **Protection maison** (onglet 2) : tous les appareils de la maison passent par Tor via ce PC, sans rien installer dessus. La Freebox est pilotée automatiquement ; pour les autres box, un mode guidé est proposé.
- Liste des appareils connectés, avec leurs noms et le volume de données.
- Guide de démarrage illustré.
- Bannières Vico au-dessus de l'interface.
