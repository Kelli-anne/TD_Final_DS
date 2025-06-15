
import feedparser
#installer feedparser

# --- URLs des flux RSS ---
flux_urls = {
    "avis": "https://www.cert.ssi.gouv.fr/avis/feed",
    "alertes": "https://www.cert.ssi.gouv.fr/alerte/feed"
}

# Étape 1 : Extraction des flux RSS
def extraire_flux_rss(url):
    rss_feed = feedparser.parse(url)
    for entry in rss_feed.entries:
        print("Titre :", entry.title)
        print("Description:", entry.description)
        print("Lien :", entry.link)
        print("Date :", entry.published)
        print("---------------------------")

# Exemple d'utilisation
extraire_flux_rss(flux_urls["avis"])
extraire_flux_rss(flux_urls["alertes"])

# Étape 2 : Extraction des CVE

import requests 
import re 
 
def extraire_et_afficher_cves(flux_urls):

    liens = []
    # Extraction de tous les liens des flux
    for url in flux_urls.values():
        rss_feed = feedparser.parse(url)
        for entry in rss_feed.entries:
            liens.append(entry.link)

    # Pour chaque lien, on rajoute /json/ et on applique le code du sujet
    for lien in liens:
        url_json = lien.rstrip('/') + "/json/"
        response = requests.get(url_json)
        data = response.json()

        # Extraction des CVE dans la clé "cves"
        ref_cves = list(data["cves"])
        print("CVE référencés", ref_cves)

        # Extraction des CVE avec une regex
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_list = list(set(re.findall(cve_pattern, str(data))))
        print("CVE trouvés :", cve_list)
        print("=====================================")

# Exemple d'utilisation
extraire_et_afficher_cves(flux_urls)
