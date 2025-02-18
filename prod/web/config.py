import uuid

class Config:
    SQLALCHEMY_BINDS = {
        'dckesc': 'postgresql://splav:splav@postgres:5432/dckesc',
        'web': "postgresql://splav:splav@postgres:5432/web"
    }
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = str(uuid.uuid4())
