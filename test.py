from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_predict_endpoint():
    response = client.post("/predict", json={"samples": ["test message", "you won a prize"]})
    assert response.status_code == 200
    assert "predictions" in response.json()


def test_upload_model():
    with open("model.pkl", "rb") as f:
        response = client.post("/upload_model", files={"model_file": f})
    assert response.status_code == 200
    assert response.json()["detail"] == "Модель успешно обновлена."
