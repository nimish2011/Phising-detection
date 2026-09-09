import sys
import os
from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI, File, UploadFile, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from uvicorn import run as app_run
import pandas as pd
from Network_Security.exception.exception import NetworkSecurityException
from Network_Security.utils.main_utils.utils import load_object
from Network_Security.utils.ml_utils.model.estimator import NetworkModel
from pydantic import BaseModel
from Network_Security.utils.blocklist import is_known_phishing
from Network_Security.utils.feature_extraction import extract_features, FEATURE_COLUMNS, normalize_url


app = FastAPI()
app.mount("/assets", StaticFiles(directory=os.path.dirname(__file__)), name="assets")

origins = ["*"]

class URLRequest(BaseModel):
    url: str

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(
    directory=os.path.join(os.path.dirname(__file__), "Network_Security", "templates")
)

@app.get("/", tags=["authentication"])
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")

@app.post("/predict_url")
async def predict_url_route(request_data: URLRequest):
    try:
        url = normalize_url(request_data.url)
        features = extract_features(url)
        df = pd.DataFrame([features], columns=FEATURE_COLUMNS)

        preprocessor = load_object("final_model/preprocessor.pkl")
        final_model = load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocessor, model=final_model)

        y_pred = network_model.predict(df)[0]
        label = "Legitimate" if y_pred == 1 else "Phishing"

        blocklisted = is_known_phishing(url)
        if blocklisted:
            label = "Phishing"

        return {
            "url": url,
            "prediction": label,
            "raw_output": int(y_pred),
            "blocklisted": blocklisted,
            "features": features,
        }
    except Exception as e:
        raise NetworkSecurityException(e, sys)

@app.post("/predict")
async def predict_route(request: Request,file: UploadFile = File(...)):
    try:
        df = pd.read_csv(file.file)
        preprocessor = load_object("final_model/preprocessor.pkl")
        final_model = load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocessor,model=final_model)
        y_pred = network_model.predict(df)
        df["predicted_column"] = y_pred
        os.makedirs("prediction_output", exist_ok=True)
        df.to_csv("prediction_output/output.csv",index=False)
        table_html = df.to_html(classes="table table-striped",index=False)
        return templates.TemplateResponse(request, "table.html", {"table": table_html})

    except Exception as e:
        raise NetworkSecurityException(e, sys)

if __name__ == "__main__":
    app_run(app,host="127.0.0.1",port=int(os.environ.get("PORT", 8000)))