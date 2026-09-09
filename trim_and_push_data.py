import os
import sys
import json

import pandas as pd
import pymongo
from dotenv import load_dotenv

load_dotenv()
MONGO_DB_URL = os.getenv("MONGO_DB_URL")

DROP_COLUMNS = [
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
]

SOURCE_CSV = os.path.join("Network_Data", "phisingData.csv")
BACKUP_CSV = os.path.join("Network_Data", "phisingData_full_backup.csv")
TRIMMED_CSV = os.path.join("Network_Data", "phisingData.csv")

DATABASE = "NIMISHAI"
COLLECTION = "NetworkData"


def main():
    if not os.path.exists(SOURCE_CSV):
        print(f"Could not find {SOURCE_CSV}")
        sys.exit(1)

    df = pd.read_csv(SOURCE_CSV)
    print(f"Loaded {SOURCE_CSV} with columns: {list(df.columns)}")

    missing = [c for c in DROP_COLUMNS if c not in df.columns]
    if missing:
        print(f"Warning: these expected columns were not found (already trimmed?): {missing}")

    if not os.path.exists(BACKUP_CSV):
        df.to_csv(BACKUP_CSV, index=False)
        print(f"Backed up original data to {BACKUP_CSV}")

    trimmed_df = df.drop(columns=[c for c in DROP_COLUMNS if c in df.columns])
    print(f"Trimmed columns, {len(trimmed_df.columns)} columns remain: {list(trimmed_df.columns)}")

    trimmed_df.to_csv(TRIMMED_CSV, index=False)
    print(f"Wrote trimmed CSV to {TRIMMED_CSV}")

    if not MONGO_DB_URL:
        print("MONGO_DB_URL not set in .env - skipping Mongo re-push. "
              "Set it and re-run if you also want Mongo updated.")
        return

    records = json.loads(trimmed_df.reset_index(drop=True).T.to_json()).values()
    records = list(records)

    client = pymongo.MongoClient(MONGO_DB_URL)
    collection = client[DATABASE][COLLECTION]

    deleted = collection.delete_many({})
    print(f"Cleared {deleted.deleted_count} old documents from {DATABASE}.{COLLECTION}")

    result = collection.insert_many(records)
    print(f"Inserted {len(result.inserted_ids)} trimmed records into {DATABASE}.{COLLECTION}")


if __name__ == "__main__":
    main()