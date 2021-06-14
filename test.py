import requests
import json
from datetime import date

def main():
    token = requests.get("http://localhost:5000/login", auth=("Alejandro", "1646sa")).json()["token"]
    exchange_rate = requests.get('http://localhost:5000/exchange_rate', headers={'Authorization': token}).json()
    print(json.dumps(exchange_rate, indent=4, sort_keys=True))

if __name__ == "__main__":
    main()