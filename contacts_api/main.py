import uvicorn
from fastapi import FastAPI
from contacts_api.src.database.db import Base, engine
from contacts_api.src.routes import contacts, users
from contacts_api.src.services.auth import router as auth_router

app = FastAPI()

Base.metadata.create_all(bind=engine)

app.include_router(contacts.router, prefix="/contacts", tags=["contacts"])
app.include_router(users.router, prefix="/users", tags=["users"])
app.include_router(auth_router, prefix="/auth", tags=["auth"])

@app.get("/")
def read_root():
    return {"message": "Witaj w aplikacji kontaktowej!"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
