from typing import List
from pydantic import Field, BaseModel


class RequestBody(BaseModel):
    samples: List[str] = Field(..., description="Список текстов для предсказаний")


class ResponseBody(BaseModel):
    samples: List[str] = Field(..., description="Тексты, отправленные клиентом")
    predictions: List[str] = Field(..., description="Предсказания модели для каждого текста")
