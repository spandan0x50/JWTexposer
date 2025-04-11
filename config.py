import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-please-change-in-production'
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    RESULT_BACKEND = os.environ.get('RESULT_BACKEND') or 'redis://localhost:6379/0'
