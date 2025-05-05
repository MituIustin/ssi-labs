import hashlib
import requests
import sys

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
    except Exception:
        print("Eroare la citirea fisierului.")
        sys.exit(1)
    return sha256_hash.hexdigest()

def query_virustotal(file_hash, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
    except Exception as e:
        print("Eroare la interogarea VirusTotal:" + str(e))
        sys.exit(1)
    return response.json()

def main():
    file_path = "fisier_test.txt"
    api_key = "1e8dc1993f4d0f41893af2df645d7253652f5be80b65ed20842979ff8c4083a4"
    file_hash = calculate_sha256(file_path)
    data = query_virustotal(file_hash, api_key)
    try:
        stats = data["data"]["attributes"]["last_analysis_stats"]
        print(f"Detectii malitioase: {stats.get('malicious', 0)} din {sum(stats.values())} vendori")
    except Exception:
        print("Eroare la interpretarea raspunsului.")

if __name__ == "__main__":
    main()
