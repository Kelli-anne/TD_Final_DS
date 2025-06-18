# Ce script lit les bulletins d'alerte et d'avis publiés par l'ANSSI, il extrait les vulnérabilités CVE mentionnées,
# et enrichit avec des données venant des fichiers mitre et first.
# Le résultat est ensuite sauvegardé dans un fichier CSV nommé "cves_enriched_local.csv".

import os
import json
import pandas as pd
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText

load_dotenv()
EMAIL_EXPEDITEUR = os.getenv("EMAIL_EXPEDITEUR")
EMAIL_MDP = os.getenv("EMAIL_MDP")

#REPERTOIRES
DOSSIER_BASE = "data_pour_TD_final"
REPERTOIRES_BULLETINS = ["alertes", "Avis"] #on récupère les deux types de bulletins à traiter
REPERTOIRE_MITRE = "mitre"
REPERTOIRE_EPSS = "first"

rows = [] #permet de stocker toutes les lignes du futur fichier .csv

#PARTIE 1 : Parcours des bulletins
#parcours de chaque fichier json présent dans le dossier correspondant : alertes et avis
for dossier in REPERTOIRES_BULLETINS:
    dossier_path = os.path.join(DOSSIER_BASE, dossier) #chemin absolu vers le dossier
    for nom_fichier in os.listdir(dossier_path): #liste tous les fichiers contenus dans le dossier
        chemin = os.path.join(dossier_path, nom_fichier) #chemin
        try:
            with open(chemin, encoding="utf-8") as f:
                data = json.load(f)
        except:
            continue #on ignore les fichiers illisibles

        #on récupère les infos du bulletin
        id_anssi = data.get("reference", nom_fichier.replace(".json", ""))
        titre = data.get("title", "Non disponible")
        type_bulletin = "Alerte" if "alerte" in dossier else "Avis"

        #on récupère la date depuis différentes sources
        date = (
            data.get("closed_at") or
            data.get("initial_release_date") or
            data.get("first_seen") or
            (data.get("revisions", [{}])[-1].get("revision_date") if data.get("revisions") else None) or
            "Non disponible"
        )

        lien = f"https://www.cert.ssi.gouv.fr/{dossier}/{id_anssi}/" #lien vers le bulletin sur le site de l'anssi
        cve_list = [ref.get("name") for ref in data.get("cves", []) if ref.get("name")]

        #PARTIE 2 : Extraction des données mitre
        #on parcourt chaque CVE mentionnée dans le bulletin
        for cve in cve_list:
            chemin_mitre = os.path.join(DOSSIER_BASE, REPERTOIRE_MITRE, cve)
            try:
                with open(chemin_mitre, encoding="utf-8") as f:
                    mitre_data = json.load(f)
            except:
                mitre_data = {} #si le fichier mitre n'existe pas

            cna = mitre_data.get("containers", {}).get("cna", {})

            description = cna.get("descriptions", [{}])[0].get("value", "Non disponible")

#Partie 3 : enrichissement avec CVSS / CWE et EPSS
            #récupération du score cvss dans plusieurs formats
            cvss_score = "Non disponible" #initialisation des variables par défaut à "Non disponible" au cas où aucune donnée ne serait trouvée
            cvss_severity = "Non disponible" #pareil

            #1) on cherche dans le bloc "cna" qui contient souvent les données principales
            for metric in cna.get("metrics", []):
                for key in ["cvssV3_1", "cvssV3_0", "cvssV2"]: #pour chaque bloc de métriques on essaie de trouver les informations selon les différentes versions possibles du CVSS
                    if key in metric:
                        cvss = metric[key]
                        cvss_score = cvss.get("baseScore", "Non disponible") #on extrait le score de base
                        cvss_severity = cvss.get("baseSeverity", "Non disponible") #on extrait la base Severity
                        break #on arrête dès qu'on trouve une version valide
                if cvss_score != "Non disponible":
                    break #pareil on arrête de chercher si un score a été trouvé

            #2) si aucune info CVSS n’est présente dans le bloc "cna", on regarde dans la partie "adp"
            if cvss_score == "Non disponible":
                for bloc in mitre_data.get("containers", {}).get("adp", []):
                    for metric in bloc.get("metrics", []):
                        cvss = metric.get("cvssV3_1") or metric.get("cvssV3_0") #on regarde si un bloc CVSS version 3.1 ou 3.0 existe
                        if cvss:
                            cvss_score = cvss.get("baseScore", "Non disponible") #on extrait le score de base
                            cvss_severity = cvss.get("baseSeverity", "Non disponible") #on extrait la base Severity
                            break
                    if cvss_score != "Non disponible":
                        break

            #Type et description CWE
            #1) on commence par chercher la valeur du CWE dans le bloc "cna"
            cwe = "Non disponible"
            for pt in cna.get("problemTypes", []):
                for desc in pt.get("descriptions", []):
                    if "cweId" in desc:
                        cwe = desc["cweId"] #si un identifiant CWE est présent, on le récupère
                        break
                    elif desc.get("description", "").startswith("CWE-"):
                        cwe = desc["description"] ##sinon on vérifie si la description commence par "CWE-"
                        break
                if cwe != "Non disponible":
                    break #on arrête des qu'on trouve une info

            #description CWE
            cwe_description = "Non disponible"
            for pt in cna.get("problemTypes", []):
                for desc in pt.get("descriptions", []):
                    if desc.get("lang") == "en": #on cherche les descriptions en anglais
                        cwe_description = desc.get("description", "Non disponible")
                        break
                if cwe_description != "Non disponible":
                    break

            #2) si aucune info est trouvée dans "cna" on regarde dans "adp"
            if cwe == "Non disponible" or cwe_description == "Non disponible":
                for bloc in mitre_data.get("containers", {}).get("adp", []):
                    for pt in bloc.get("problemTypes", []):
                        for desc in pt.get("descriptions", []):
                            if cwe == "Non disponible":
                                if "cweId" in desc:
                                    cwe = desc["cweId"]
                                elif desc.get("description", "").startswith("CWE-"): #pareil on regarde si la description commence par "CWE-"
                                    cwe = desc.get("description")
                            if cwe_description == "Non disponible":
                                if desc.get("lang") == "en":
                                    cwe_description = desc.get("description", "Non disponible")
                            #si on a récupéré les deux infos, on peut sortir de toutes les boucles
                            if cwe != "Non disponible" and cwe_description != "Non disponible":
                                break
                        if cwe != "Non disponible" and cwe_description != "Non disponible":
                            break
                    if cwe != "Non disponible" and cwe_description != "Non disponible":
                        break

            vendor = "Non disponible"
            product = "Non disponible"
            versions = []
            for aff in cna.get("affected", []):
                vendor = aff.get("vendor", vendor) #récupération du nom du vendeur
                product = aff.get("product", product) #récupération du nom du produit
                #récupèration des versions affectées uniquement si leur statut est "affected"
                versions += [v.get("version") for v in aff.get("versions", []) if v.get("status") == "affected"]

            #conversion des valeurs n/a en non disponible
            if vendor == "n/a":
                vendor = "Non disponible"
            if product == "n/a":
                product = "Non disponible"
            if versions == ["n/a"]:
                versions = []

            #EPSS
            chemin_epss = os.path.join(DOSSIER_BASE, REPERTOIRE_EPSS, cve) #chemin json
            epss = "Non disponible" #valeur par défaut
            try:
                with open(chemin_epss, encoding="utf-8") as f:
                    epss_data = json.load(f)
                    epss_list = epss_data.get("data", [])
                    if epss_list:
                        epss_raw = epss_list[0].get("epss") #récupération du champ "epss" de la 1ere entrée
                        if epss_raw:
                            epss = round(float(epss_raw), 3) #si la valeur est bien présente, on la convertit en float et on l'arrondit à 3 décimales
            except: #si l'ouverture ne se fait pas alors on garde la valeur par défaut "non disponible" définit plus haut
                pass

            ##construction d'une ligne de donnée (sous forme de dictionnaire) pour le csv final
            rows.append({
                "ID du bulletin (ANSSI)": id_anssi,
                "Titre du bulletin (ANSSI)": titre,
                "Type de bulletin": type_bulletin,
                "Date de publication": date,
                "Identifiant CVE": cve,
                "Score CVSS": cvss_score,
                "Base Severity": cvss_severity,
                "Type CWE": cwe,
                "Description CWE":cwe_description,
                "Score EPSS": epss,
                "Lien du bulletin (ANSSI)": lien,
                "Description": description,
                "Éditeur/Vendor": vendor,
                "Produit": product,
                "Versions affectées": ", ".join(versions)
            })

#Partie 4 : Consolidation des données
#fichier CSV final
df = pd.DataFrame(rows) #transformation de la liste 'rows' en dataframe pandas
df.to_csv("cves_enriched_local.csv", index=False) #on exporte sous forme de fichier CSV
print("Fichier cves_enriched_local.csv généré avec succès.")
print("Nombre de lignes :", len(df)) #affichage du nombre de ligne de CVE au total, il y en a 60799
print("Fin du script.")
print(df.head(3))

# Partie 6 : Génération d’alertes critiques et notification par email

def envoyer_email(destinataire, sujet, corps):
    msg = MIMEText(corps)
    msg["From"] = EMAIL_EXPEDITEUR
    msg["To"] = destinataire
    msg["Subject"] = sujet

    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login(EMAIL_EXPEDITEUR, EMAIL_MDP)
        server.sendmail(EMAIL_EXPEDITEUR, destinataire, msg.as_string())

# Seuils critiques
SEUIL_CVSS = 9.0
SEUIL_EPSS = 0.9

# Lecture du fichier généré
df = pd.read_csv("cves_enriched_local.csv")

# Nettoyage des champs numériques
df["Score CVSS"] = pd.to_numeric(df["Score CVSS"], errors="coerce")
df["Score EPSS"] = pd.to_numeric(df["Score EPSS"], errors="coerce")

# Filtrage des CVE critiques
df_critique = df[
    (df["Score CVSS"] >= SEUIL_CVSS) | (df["Score EPSS"] >= SEUIL_EPSS)
].copy()

# Destinataires des alertes (à adapter selon ton besoin)
destinataires = ["destinataire@example.com"]

# Envoi des emails
for _, ligne in df_critique.iterrows():
    produit = ligne["Produit"]
    cve = ligne["Identifiant CVE"]
    lien = ligne["Lien du bulletin (ANSSI)"]
    score_cvss = ligne["Score CVSS"]
    score_epss = ligne["Score EPSS"]
    description = ligne["Description"]

    sujet = f"[Alerte Critique] {cve} - Produit : {produit}"
    corps = f"""Alerte de vulnérabilité critique détectée :

Produit : {produit}
CVE : {cve}
Score CVSS : {score_cvss}
Score EPSS : {score_epss}
Description : {description}
Lien ANSSI : {lien}

Veuillez appliquer les mesures nécessaires.
"""
    for destinataire in destinataires:
        envoyer_email(destinataire, sujet, corps)

print(f"{len(df_critique)} alertes critiques envoyées par email.")
