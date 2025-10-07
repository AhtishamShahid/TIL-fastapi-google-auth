# main_with_fastapi_login.py
"""
Using fastapi-login library for simpler authentication management
Install: pip install fastapi-login
"""
import os
import secrets

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi_login import LoginManager
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from typing import List

import models
import schemas
import crud
from database import engine, get_db
from starlette.requests import Request
from starlette.middleware.sessions import SessionMiddleware

from authlib.integrations.starlette_client import OAuth
from dotenv import load_dotenv

from schemas import Token

load_dotenv()

oauth = OAuth()

oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# Create tables
models.Base.metadata.create_all(bind=engine)

# Configuration
SECRET_KEY = "your-secret-key-change-in-production"

app = FastAPI(title="User Management with fastapi-login")

# Initialize LoginManager
manager = LoginManager(SECRET_KEY, token_url='/token')
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)


# User loader - called automatically to get user from token
@manager.user_loader()
def load_user(username: str, db: Session = None):
    if db is None:
        db = next(get_db())
    user = crud.get_user_by_username(db, username)
    return user


# Exception handler for invalid credentials
@app.exception_handler(Exception)
async def unicorn_exception_handler(request, exc):
    if isinstance(exc, HTTPException):
        return exc
    return HTTPException(status_code=500, detail=str(exc))


# Routes
@app.post("/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    # Check if user exists
    db_user = crud.get_user_by_email(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already taken")

    return crud.create_user(db=db, user=user)


@app.post("/token")
def login(
        data: OAuth2PasswordRequestForm = Depends(),
        db: Session = Depends(get_db)
):
    username = data.username
    password = data.password

    user = crud.authenticate_user(db, username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )

    # Create access token using LoginManager
    access_token = manager.create_access_token(
        data={'sub': user.username}
    )

    return {'access_token': access_token, 'token_type': 'bearer'}


@app.get("/users/me", response_model=schemas.UserResponse)
def read_users_me(user: models.User = Depends(manager)):
    # manager dependency automatically validates token and loads user
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


@app.get("/users", response_model=List[schemas.UserResponse])
def read_users(
        skip: int = 0,
        limit: int = 100,
        db: Session = Depends(get_db),
        user: models.User = Depends(manager)
):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    users = crud.get_users(db, skip=skip, limit=limit)
    return users


@app.get("/users/{user_id}", response_model=schemas.UserResponse)
def read_user(
        user_id: int,
        db: Session = Depends(get_db),
        user: models.User = Depends(manager)
):
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")

    db_user = crud.get_user_by_id(db, user_id=user_id)
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user


@app.get("/login/google")
async def login_via_google(request: Request):
    redirect_uri = request.url_for('auth_via_google')
    return await oauth.google.authorize_redirect(request, redirect_uri)


@app.get("/auth/google")
async def auth_via_google(request: Request, db: Session = Depends(get_db)):
    """
    Callback endpoint for Google OAuth2.
    Handles user authentication, registration, and token generation.
    """
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials with Google: {e}"
        )

    user_info = token.get('userinfo')
    if not user_info or not user_info.get('email'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not retrieve user information from Google."
        )

    email = user_info['email']

    # 1. Check if user already exists in the database
    db_user = crud.get_user_by_email(db, email=email)

    if not db_user:
        # 2. If user doesn't exist, register them

        # Create a username from the email, ensuring it's unique
        base_username = user_info.get('given_name', email.split('@')[0])
        username = base_username
        counter = 1
        while crud.get_user_by_username(db, username=username):
            username = f"{base_username}{counter}"
            counter += 1

        # Create a user schema for registration
        # A secure, random password is required by the schema, but the user will not use it
        user_create = schemas.UserCreate(
            username=username,
            email=email,
            password=secrets.token_urlsafe(16)  # Generate a random password
        )
        db_user = crud.create_user(db=db, user=user_create)

    # 3. User exists (either from before or just created), so create an access token
    access_token = manager.create_access_token(
        data={'sub': db_user.username}
    )

    return Token(access_token=access_token, token_type='bearer')


@app.get("/")
def root():
    return {
        "message": "User Management API with fastapi-login",
        "docs": "/docs",
        "library": "fastapi-login"
    }
