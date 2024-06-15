import uvicorn
from fastapi import FastAPI
from contacts_api.src.database import db, models
from contacts_api.src.routes import contacts, users
from src.database.models import Base

app = FastAPI()

Base.metadata.create_all(bind=db.engine)

app.include_router(contacts.router, prefix="/contacts", tags=["contacts"])
app.include_router(users.router, prefix="/users", tags=["users"])

@app.get("/")
def read_root():
    return {"message": "Witaj w aplikacji kontaktowej!"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)