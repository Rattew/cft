from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.responses import RedirectResponse
from jose import JWTError, jwt
from pydantic import BaseModel
from datetime import datetime, timedelta
import mimetypes
import secrets
import ast

#определяем секретный ключ и алгоритм шифрования
SECRET_KEY = 'dd6176a9ce47c93a4d19bc76f558cb21cf1b0322ef56d8497384f4b9ebf56145'
ALGORITHM = 'HS256'

#создаем модель токена
class Token(BaseModel):
    access_token: str
    token_type: str

#запускаем приложение
app = FastAPI(title='SHIFT-CFT Test Project')

#определяем простую процедуру идентификации
security = HTTPBasic()
def validate_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    input_username = credentials.username.encode('utf-8')
    input_password = credentials.password.encode('utf-8')
    input_cred = [input_username, input_password]
    data = open('test_simple_db.txt', 'r')
    cred = []
    for line in data:
        F = ast.literal_eval(line.strip())['username'].encode('utf-8')
        S = ast.literal_eval(line.strip())['password'].encode('utf-8')
        bond = [F, S]
        cred.append(bond)
    data.close()
    if input_cred in cred:
        return credentials.username
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                        detail='Invalid credentials',
                        headers={'WWW-Authenticate': 'Basic'})      

#создаем недолговечный токен(для наглядности 1 минута)
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=1)
    to_encode.update({'exp': expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

#получаем токен на имя залогинившегося юзера 
def get_token(name: str):
    data = {
        'info': 'SHIFT-CFT Test Project',
        'name': name
    }
    token = create_access_token(data=data)
    return token

#проверяем токен
def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = payload['name']
        return user
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate credentials',
        )

#идентифицируемся и запрашиваем токен
@app.get('/auth')
def auth(username: str = Depends(validate_credentials)):
    token = get_token(username)
    file = open('token.txt', 'w')
    file.write(token)
    file.close
    return RedirectResponse('/salary')

#смотрим зарплату(и утираем слезы...)
@app.get('/salary')
def salary():
    reader = open('token.txt', 'r')
    token = reader.read()
    check = verify_token(token)
    data = open('test_simple_db.txt', 'r')
    for line in data:
        db_user = ast.literal_eval(line.strip())['username']
        if db_user == check:
            F = ast.literal_eval(line.strip())['salary']
            S = ast.literal_eval(line.strip())['promotion']
            request = f'зарплата: {F}, следующее повышение: {S}'
    data.close()    
    return {'message': request}
