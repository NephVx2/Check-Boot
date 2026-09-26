# Check-Boot

🇬🇧 [English version](README.md)

**Auteur :** Nephren ([github.com/NephVx2](https://github.com/NephVx2))
**Version :** 5.6
**Compatible :** Windows 10/11 — UEFI / BIOS Legacy — GPT / MBR — Windows en anglais et en français

---

## Sommaire

- [Présentation](#présentation)
- [Captures d'écran](#captures-décran)
- [Ce que le script vérifie](#ce-que-le-script-vérifie)
- [Prérequis](#prérequis)
- [Premier lancement (étape par étape)](#premier-lancement-étape-par-étape)
- [Utilisation](#utilisation)
- [Comprendre le score](#comprendre-le-score)
- [Rapports générés](#rapports-générés)
- [Pourquoi c'est utile](#pourquoi-cest-utile)

---

## Présentation

Check-Boot est un script PowerShell de diagnostic, en lecture seule, qui audite en une seule exécution toute la chaîne de démarrage de Windows : firmware, BCD, Secure Boot, TPM, fichiers EFI/bootloader, pilotes chargés au démarrage, BitLocker, WinRE, la partition Recovery, l'état SMART des disques, l'intégrité de l'image système, et le journal d'évènements de boot.

Les problèmes de démarrage sont en général invisibles jusqu'au jour où Windows ne démarre plus — et à ce moment-là, il est trop tard pour récupérer des éléments de diagnostic. Ce script est pensé pour être exécuté *avant* que cela n'arrive : sur une machine saine, il établit une baseline (hash de `winload.efi`/`bootmgfw.efi`, taille de la liste de révocation DBX, historique du score) et signale tout ce qui semble anormal, avoir dérivé, ou être mal configuré — pour qu'une véritable panne de démarrage plus tard soit plus rapide à diagnostiquer, voire n'arrive jamais.

Il ne modifie jamais la configuration de démarrage. La seule action d'écriture optionnelle est la création d'un point de restauration Windows (`-CreateRestorePoint`) avant les vérifications les plus lentes.

---

## Captures d'écran

<p align="center">
  <img src="https://raw.githubusercontent.com/NephVx2/Check-Boot/main/screenshots/01-banner-sysinfo.png" width="49%">
  <img src="https://raw.githubusercontent.com/NephVx2/Check-Boot/main/screenshots/04-banner-html.png" width="49%">
</p>

D'autres captures (section Secure Boot, le résumé final « Audit Complete », le tableau détaillé du rapport HTML, un avertissement Boot Log signalé) sont disponibles dans le [dossier screenshots](https://github.com/NephVx2/Check-Boot/tree/main/screenshots).

---

## Ce que le script vérifie

| Catégorie | Ce qui est contrôlé |
|---|---|
| Système | Version/build Windows, heure du dernier démarrage, uptime |
| Firmware | UEFI ou BIOS Legacy |
| Disque | Style de la partition système (GPT/MBR) |
| BCD | Accessibilité du Boot Configuration Data, présence du Boot Manager, nombre d'entrées de boot Windows, nombre d'objets BCD (registre) |
| Secure Boot | Etat activé/désactivé |
| TPM | Présence et version de la spécification |
| EFI | Présence et espace libre de la partition EFI, présence de `winload.efi`/`bootmgfw.efi`, hash SHA256 et dérive par rapport à l'exécution précédente |
| Legacy BIOS | Présence de `winload.exe` (systèmes non-UEFI) |
| Clés Secure Boot | Bases de certificats DB / KEK / DBX, détection de régression de la DBX |
| Sécurité | Mitigation du bootkit BlackLotus, VBS (Virtualization Based Security), HVCI (Memory Integrity) |
| Pilotes boot | Pilotes non signés chargés en BootStart/SystemStart |
| Fast Boot | Etat du démarrage rapide Windows (Hiberboot) |
| BitLocker | Etat de la protection sur le disque système |
| WinRE | Etat de l'environnement de récupération Windows |
| Recovery | Présence de la partition Recovery et détection d'une exposition anormale (lettre de lecteur assignée) |
| SMART | Etat de santé des disques physiques |
| Intégrité système | Résultats de `SFC /verifyonly` et `DISM /CheckHealth` |
| Boot Order | Accessibilité de l'ordre de démarrage firmware |
| Dual Boot | Détection d'un bootloader Linux (GRUB/shim) ou d'une partition Linux |
| Hackintosh | Détection d'entrées de bootloader OpenCore/Clover |
| Compatibilité Win11 | Conformité de la configuration de boot actuelle (UEFI + GPT) avec les prérequis Windows 11 de Microsoft |
| Journal Boot | Erreurs Kernel-Boot récentes et arrêts non planifiés (Event ID 41) sur les 7/30 derniers jours |

Chaque contrôle reçoit un statut : `OK`, `AVERTISSEMENT`, ou `ERREUR`. Chaque catégorie a aussi son propre score pondéré sur 100, en plus du score de santé global.

---

## Prérequis

- Windows 10 ou 11
- PowerShell exécuté en tant qu'administrateur (le script s'auto-élève via une invite UAC si lancé depuis une session non élevée)

---

## Premier lancement (étape par étape)

1. Copier `Check-Boot.ps1` sur la machine cible.

2. Ouvrir PowerShell (l'élévation n'est pas nécessaire pour le lancer — le script s'auto-élève lui-même via une invite UAC). Se placer dans le dossier contenant le script (adapter le chemin ; garder les guillemets s'il contient des espaces) :

   ```powershell
   cd "$HOME\Downloads"
   ```

3. **Débloquer le script** s'il a été téléchargé depuis Internet. Windows marque les fichiers téléchargés, et la politique d'exécution de PowerShell (`RemoteSigned`, par exemple) refuse de lancer un script marqué. Depuis le dossier du script :

   ```powershell
   Unblock-File .\Check-Boot.ps1
   ```

   Si PowerShell indique à la place que l'exécution de scripts est désactivée sur ce système (la politique par défaut de Windows est `Restricted`), autoriser d'abord les scripts pour le compte courant (le changement ne s'applique qu'à ce compte, pas à toute la machine) :

   ```powershell
   Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
   ```

   Toujours bloqué ? Voir le [guide étape par étape](https://github.com/NephVx2/Script-blocked-Look-at-this).

4. Lancer d'abord le self-test — aucun fichier écrit, aucune modification système :

   ```powershell
   .\Check-Boot.ps1 -SelfTest
   ```

   Exécute 16 assertions internes (scoring d'`Add-Result`, filtrage `-Category`, `Safe-CommandExists`, `Get-FileSha256`, et détection de partition Recovery en MBR/GPT). Code de sortie 0 = tout passe, 1 = au moins un échec.

5. Lancer l'analyse complète :

   ```powershell
   .\Check-Boot.ps1
   ```

   Prend largement moins d'une minute sur la plupart des machines — `SFC /verifyonly` et `DISM /CheckHealth` sont les étapes les plus lentes (à ignorer avec `-SkipSlowChecks` pour un passage rapide). La console affiche en direct une ligne colorée par contrôle au fur et à mesure de chaque section.

6. Une fois terminé, la console affiche une boîte `SUMMARY` (totaux, score pondéré, évolution par rapport au run précédent) puis une boîte `AUDIT COMPLETE` avec une barre de score en caractères et les chemins des rapports générés.

7. Ouvrir le rapport HTML généré (le script propose de le faire automatiquement sauf avec `-Silent`) — regarder d'abord les liens des findings critiques en haut s'il y a des échecs, puis utiliser la barre de recherche et les filtres de statut pour le reste.

8. Aux **exécutions suivantes**, les boîtes SUMMARY/AUDIT COMPLETE affichent en plus la tendance du score par rapport au run précédent, et le rapport signale toute dérive des hash `winload.efi`/`bootmgfw.efi` ou une DBX qui rétrécit — anormal en dehors d'une mise à jour Windows.

---

## Utilisation

```powershell
.\Check-Boot.ps1
```

### Paramètres

| Paramètre | Description |
|---|---|
| `-Silent` | Aucune sortie console — utile pour les tâches planifiées. Les rapports sont générés quand même. |
| `-SelfTest` | Exécute 16 assertions internes sur les fonctions cœur du script puis quitte (aucun contrôle système n'est effectué). |
| `-SkipSlowChecks` | Ignore `SFC /verifyonly` et `DISM /CheckHealth`, les deux contrôles les plus lents. |
| `-CreateRestorePoint` | Crée un point de restauration système avant les vérifications DISM. |
| `-Category <nom(s)>` | N'exécute que la ou les catégories indiquées (voir le tableau ci-dessus pour les noms valides), en plus du Résumé toujours affiché. |

### Exemples

```powershell
# Exécution complète
.\Check-Boot.ps1

# Exécution rapide, sans SFC/DISM, sans sortie console
.\Check-Boot.ps1 -Silent -SkipSlowChecks

# Ne vérifier que Secure Boot et le TPM
.\Check-Boot.ps1 -Category "Secure Boot","TPM"

# Vérifier la logique interne du script
.\Check-Boot.ps1 -SelfTest
```

---

## Comprendre le score

**Score de santé global** (100 → 0, `-15` par erreur, `-5` par avertissement) :

| Score | Etat |
|---|---|
| ≥ 90 | EXCELLENT |
| ≥ 75 | BON |
| ≥ 50 | MOYEN |
| < 50 | CRITIQUE |

**Score par catégorie** : chacune des 22 catégories part de 100 et est déduite indépendamment (`-30` par erreur, `-10` par avertissement dans cette catégorie), puis combinée à un poids (BCD, Secure Boot et Intégrité système pèsent le plus lourd ; Boot Order, Dual Boot et Hackintosh le moins) — pour qu'une catégorie faible ne se dilue pas dans la moyenne globale.

---

## Rapports générés

Chaque exécution écrit des rapports horodatés dans `%USERPROFILE%\Desktop\Rapports_Maintenance\Boot\` :

- `Rapport_Boot_<horodatage>.csv`
- `Rapport_Boot_<horodatage>.json`
- `Rapport_Boot_<horodatage>.html` — un tableau de bord en thème sombre avec jauge de score, tendance par rapport à l'exécution précédente, sparkline de l'historique des scores, tuiles par catégorie, section des findings critiques, et un tableau de résultats filtrable
- `Baseline_Boot.json` — conservé entre les exécutions pour détecter une dérive (changement de hash des binaires, DBX qui rétrécit, tendance du score)

---

## Pourquoi c'est utile

- Détecte une chaîne de démarrage qui se dégrade silencieusement (`bootmgfw.efi` corrompu, Secure Boot désactivé, une DBX qui a rétréci, un pilote de démarrage non signé) bien avant que cela ne se traduise par une machine qui ne démarre plus.
- Donne aux utilisateurs en dual-boot ou en Hackintosh une visibilité sur la façon dont leur configuration interagit avec la chaîne de démarrage native de Windows, sans partir du principe qu'une config mono-OS serait la seule valide.
- Fonctionne à l'identique sur une installation Windows en français et en anglais : toute détection dépendante de la langue (`sfc`, `dism`) reconnaît les deux langues, et les détections les plus sensibles (entrées BCD, GUID EFI) reposent sur des chemins de fichiers et des GUID littéraux, jamais traduits par Windows.
- `-SelfTest` et `-Category` facilitent son intégration dans une suite de maintenance plus large ou dans une tâche planifiée, sans devoir relancer systématiquement l'ensemble des contrôles (plus lent).

---
*Fait partie de la suite de scripts de maintenance/sécurité Windows 11 de Nephren.*
