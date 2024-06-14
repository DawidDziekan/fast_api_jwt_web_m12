from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from src.database import models
from src.repository import contacts
from contacts_api.src import schemas
from src.database import db
from src.database.db import engine, Base 

Base.metadata.create_all(bind=engine)

app = FastAPI()

@app.post("/contacts/", response_model=schemas.Contact)
def create_contact(contact: schemas.ContactCreate, db: Session = Depends(db.get_db)):
    return contacts.create_contact(db, contact)

@app.get("/contacts/", response_model=list[schemas.Contact])
def read_contacts(skip: int = 0, limit: int = 100, db: Session = Depends(db.get_db)):
    all_contacts = contacts.get_contacts(db, skip=skip, limit=limit)
    return all_contacts

@app.get("/contacts/{contact_id}", response_model=schemas.Contact)
def read_contact(contact_id: int, db: Session = Depends(db.get_db)):
    contact = contacts.get_contact(db, contact_id)
    if contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact

@app.put("/contacts/{contact_id}", response_model=schemas.Contact)
def update_contact(contact_id: int, contact: schemas.ContactUpdate, db: Session = Depends(db.get_db)):
    updated_contact = contacts.update_contact(db, contact_id, contact)
    if updated_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return updated_contact

@app.delete("/contacts/{contact_id}", response_model=schemas.Contact)
def delete_contact(contact_id: int, db: Session = Depends(db.get_db)):
    deleted_contact = contacts.delete_contact(db, contact_id)
    if deleted_contact is None:
        raise HTTPException(status_code=404, detail="Contact not found")
    return deleted_contact

@app.get("/search/", response_model=list[schemas.Contact])
def search_contacts(query: str, db: Session = Depends(db.get_db)):
    contacts = db.query(models.Contact).filter(
        models.Contact.first_name.contains(query) |
        models.Contact.last_name.contains(query) |
        models.Contact.email.contains(query)
    ).all()
    return contacts

from datetime import datetime, timedelta

@app.get("/birthdays/", response_model=list[schemas.Contact])
def upcoming_birthdays(db: Session = Depends(db.get_db)):
    today = datetime.today().date()
    upcoming_date = today + timedelta(days=7)
    contacts = db.query(models.Contact).filter(
        models.Contact.birthday.between(today, upcoming_date)
    ).all()
    return contacts
