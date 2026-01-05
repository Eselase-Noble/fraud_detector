import os
from pydantic import BaseSettings

class Settings(BaseSettings):
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    OPENAI_API_KEY: str
    VECTOR_STORE_PATH: str = "fraud_docs_index"

    class Config:
        env_file = "../config.env"

settings = Settings()
