from typing import Annotated
from datetime import datetime, timedelta
from typing import Union
import sqlite3
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel


#задаем секретный ключ(случайный) и способ шифрования
SECRET_KEY = "7f2e21e5e44c721dc0c7d6b4940f91daba249bb10ca02bdb767401fee0e825c1"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

#создаем базу данных
conn = sqlite3.connect('newdb.db')
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT)''')
conn.commit()


#описываем модели для валидации данных
class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


#это для хеширования паролей и отключения устаревших схем
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#это нужно для проверки аутентификации перед доступом к защищенным эндпоинтам или ресурсам
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()





#для проверки соответствия введённого пользователем пароля его хэш-версии
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

#тут пароль хешируется
def get_password_hash(password):
    return pwd_context.hash(password)

#получаем пользователя(если такой есть)
def get_user(username: str):
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    return user

#проверяем есть ли пользователь и верен ли введенный пароль
def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user[2]):
        return False
    return user

# используется для создания безопасного JWT-токена с ограниченным сроком действия
def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

#теперь асинхронные функции
#для проверки авторизации пользователей
async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    #возвращается, если проверка токена провалилась(неавторизован)
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        #расшифровывает полученный JWT-токен с использованием секретного ключа и указанного алгоритма шифрования 
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        #извлечение идентификатора пользователя из декодированного словаря данных
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

#вот это не совсем поняла, какая то проверка на активность
async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

#регистрация пользователя
@app.post("/register")
async def register(username: str, password: str):
    user = get_user(username)
    #проверяем нет ли уже такого юзера
    if user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="There is a user with the same nickname. Take another",
        )
    #если все гут, регистрируем
    hashed_password = pwd_context.hash(password)
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    return {"username": username}


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    #Аутентификация пользователя
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    #Если аутентификация прошла успешно, функция создает JWT-токен
    access_token = create_access_token(
        data={"sub": user[1]}, expires_delta=access_token_expires
    )
    #возвращает JSON-ответ, содержащий полученный токен доступа и тип токена  
    return {"access_token": access_token, "token_type": "bearer"}

#предоставляет информацию о текущем зарегистрированном и активном пользователе после успешной аутентификации и авторизации
#можно сказать личный кабинет
@app.get("/users/me/", response_model=User)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user

#это для редакции данных, не сильно необходимая штука пока что
@app.get("/users/me/items/")
async def read_own_items(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return [{"item_id": "Foo", "owner": current_user.username}]
