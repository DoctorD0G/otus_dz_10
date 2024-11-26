from fastapi import HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List

from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

users_db = {
    "user1": {"username": "user1", "hashed_password": "fadfgdfdgdrtrrfg", "roles": ["user"]},
    "admin": {"username": "admin", "hashed_password": "dfggherfdgfdgdfg", "roles": ["admin", "user"]}
}


def verify_password(plain_password, hashed_password):
    return plain_password == hashed_password


def authenticate_user(username: str, password: str):
    user = users_db.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Недействительный токен")
        return users_db.get(username)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Недействительный токен")


def role_required(roles: List[str]):
    async def role_dependency(current_user=Depends(get_current_user)):
        if current_user is None or not set(current_user["roles"]).intersection(roles):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Доступ запрещен")
        return current_user
    return role_dependency
