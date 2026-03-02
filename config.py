import os
from dotenv import load_dotenv

load_dotenv()

class config:
    SECRET_KEY = os.getenv("Flask_Secret_Key", "No_robes_mi_clave_por_favor")
    JWT_EXPIRATION_HOURS = float(os.getenv("JWT_Expiration_Hours", 0.5))
    JWT_ALGORITHM = os.getenv("JWT_Algorithm", "HS256")