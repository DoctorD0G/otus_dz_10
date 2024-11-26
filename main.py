from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
import pickle
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from typing import List
from auth import get_current_user, role_required

app = FastAPI()

model: MultinomialNB = None
vectorizer: CountVectorizer = None


class RequestBody(BaseModel):
    samples: List[str]


class ResponseBody(BaseModel):
    samples: List[str]
    predictions: List[str]


def load_model_and_vectorizer():
    global model, vectorizer
    with open("model.pkl", "rb") as model_file:
        model = pickle.load(model_file)
    with open("vector.pkl", "rb") as vectorizer_file:
        vectorizer = pickle.load(vectorizer_file)


@app.on_event("startup")
async def startup_event():
    load_model_and_vectorizer()


@app.post("/predict", response_model=ResponseBody)
async def predict(request: RequestBody, current_user=Depends(get_current_user)):
    if model is None or vectorizer is None:
        raise HTTPException(status_code=500, detail="Модель не загружена")
    samples = request.samples
    features = vectorizer.transform(samples)
    predictions = model.predict(features)
    return ResponseBody(samples=samples, predictions=predictions.tolist())


@app.get("/admin-data")
async def admin_data(current_user=Depends(role_required(["admin"]))):
    return {"message": "Доступ только для администраторов"}
