from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Header
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from fastapi import Body


class RegisterRequest(BaseModel):
    email: str
    password: str

class LoginRequest(BaseModel):
    email: str
    password: str

app = FastAPI()

# ---------------- DATABASE ----------------
DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# ---------------- SECURITY ----------------
SECRET_KEY = "secret"
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_token(data: dict):
    data["exp"] = datetime.utcnow() + timedelta(hours=2)
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# ---------------- MODELS ----------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True)
    password = Column(String)

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True)

class UserRole(Base):
    __tablename__ = "user_roles"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    role_id = Column(Integer, ForeignKey("roles.id"))

class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True)
    title = Column(String)
    content = Column(String)
    company_name = Column(String)
    document_type = Column(String)
    uploaded_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# ---------------- DEPENDENCY ----------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ---------------- AUTH ----------------
def get_current_user(db: Session = Depends(get_db)):
    return db.query(User).first()
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = db.query(User).filter_by(id=payload["user_id"]).first()
        return user
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

# ---------------- RBAC ----------------
def get_user_roles(user_id, db):
    roles = db.query(Role).join(UserRole).filter(UserRole.user_id == user_id).all()
    return [r.name for r in roles]

def require_role(allowed_roles: list):
    def role_checker(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        roles = get_user_roles(user.id, db)
        if not any(role in roles for role in allowed_roles):
            raise HTTPException(status_code=403, detail="Permission denied")
        return user
    return role_checker

# ---------------- AUTH APIs ----------------
@app.post("/auth/register")
def register(data: RegisterRequest = Body(...), db: Session = Depends(get_db)):
    try:
        user = User(email=data.email, password=hash_password(data.password))
        db.add(user)
        db.commit()
        return {"message": "User registered"}
    except Exception as e:
        return {"error": str(e)}

@app.post("/auth/login")
def login(data: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=data.email).first()

    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token({"user_id": user.id})
    return {"access_token": token}

# ---------------- ROLE APIs ----------------
@app.post("/roles/create")
def create_role(name: str, db: Session = Depends(get_db)):
    role = Role(name=name)
    db.add(role)
    db.commit()
    return {"message": "Role created"}

@app.post("/users/assign-role")
def assign_role(user_id: int, role_id: int, db: Session = Depends(get_db)):
    ur = UserRole(user_id=user_id, role_id=role_id)
    db.add(ur)
    db.commit()
    return {"message": "Role assigned"}

@app.get("/users/{id}/roles")
def get_roles(id: int, db: Session = Depends(get_db)):
    roles = get_user_roles(id, db)
    return {"roles": roles}

# ---------------- DOCUMENT APIs ----------------
@app.post("/documents/upload")
async def upload(
    file: UploadFile = File(...),
    company_name: str = "",
    document_type: str = "",
    db: Session = Depends(get_db)
):
    content = (await file.read()).decode("utf-8")

    doc = Document(
        title=file.filename,
        content=content,
        company_name=company_name,
        document_type=document_type,
        uploaded_by=1
    )

    db.add(doc)
    db.commit()
    db.refresh(doc)

    return {"message": "Uploaded", "doc_id": doc.id}

@app.get("/documents")
def get_all(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Document).all()

@app.get("/documents/search")
@app.get("/documents/search")
def search(
    company_name: str = "",
    document_type: str = "",
    db: Session = Depends(get_db)
):
    query = db.query(Document)

    if company_name:
        query = query.filter(Document.company_name == company_name)

    if document_type:
        query = query.filter(Document.document_type == document_type)

    return query.all()

@app.get("/documents/{doc_id}")
def get_one(doc_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(Document).filter_by(id=doc_id).first()
    if not doc:
        raise HTTPException(404, "Not found")
    return doc

@app.delete("/documents/{doc_id}")
def delete(
    doc_id: int,db: Session = Depends(get_db)):
    doc = db.query(Document).filter_by(id=doc_id).first()
    if not doc:
        raise HTTPException(404, "Not found")

    db.delete(doc)
    db.commit()
    return {"message": "Deleted"}

# ---------------- METADATA SEARCH ----------------
@app.get("/documents/search")
def search(
    company_name: str = None,
    document_type: str = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    query = db.query(Document)

    if company_name:
        query = query.filter(Document.company_name == company_name)

    if document_type:
        query = query.filter(Document.document_type == document_type)

    return query.all()

@app.get("/create-test-user")
def create_test_user(db: Session = Depends(get_db)):
    try:
        existing = db.query(User).filter_by(email="test@gmail.com").first()
        if existing:
            return {"message": "User already exists"}

        user = User(email="test@gmail.com", password="1234",role="admin")
        db.add(user)
        db.commit()
        return {"message": "test user created"}

    except Exception as e:
        return {"error": str(e)}
# ---------------- SIMPLE EMBEDDING ----------------

import numpy as np

def fake_embedding(text: str):
    return np.array([ord(c) for c in text[:50]])

def similarity(a, b):
    min_len = min(len(a), len(b))
    a = a[:min_len]
    b = b[:min_len]
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-9)
VECTOR_DB = {}


# ----------- PART 2 (RAG) -----------

@app.post("/rag/index/{doc_id}")
def index_doc(doc_id: int, db: Session = Depends(get_db)):
    doc = db.query(Document).filter_by(id=doc_id).first()

    if not doc:
        return {"error": "Document not found"}

    VECTOR_DB[doc_id] = fake_embedding(doc.content)

    return {"message": "Indexed"}


@app.post("/rag/search")
def rag_search(query: str):
    if not VECTOR_DB:
        return {"error": "No documents indexed"}

    query_vec = fake_embedding(query)

    results = []
    for doc_id, vec in VECTOR_DB.items():
        score = similarity(query_vec, vec)
        results.append((doc_id, score))

    results.sort(key=lambda x: x[1], reverse=True)

    return {"results": results[:5]}