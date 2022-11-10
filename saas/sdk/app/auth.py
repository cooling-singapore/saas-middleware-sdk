import os.path
from typing import Optional
from datetime import datetime, timedelta

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Column, String, Boolean, create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from jose import jwt

from saas.core.helpers import generate_random_string
from saas.core.identity import Identity
from saas.core.keystore import Keystore
from saas.rest.schemas import Token
from saas.sdk.app.exceptions import AppRuntimeError

Base = declarative_base()


class UserRecord(Base):
    __tablename__ = 'user'
    username = Column(String(16), primary_key=True)
    name = Column(String, nullable=False)
    email = Column(String, nullable=False)
    disabled = Column(Boolean, nullable=False)
    keystore_id = Column(String(64), nullable=False)
    keystore_password = Column(String, nullable=False)
    hashed_password = Column(String(64), nullable=False)


class User(BaseModel):
    class Config:
        arbitrary_types_allowed = True

    username: str
    name: str
    email: str
    disabled: bool
    hashed_password: str
    keystore: Keystore

    @property
    def identity(self) -> Identity:
        return self.keystore.identity


class UserDB:
    _keystore_path = None
    _engine = None
    _Session = None
    _keystores = {}

    @classmethod
    def initialise(cls, wd_path: str):
        # create directories
        cls._keystore_path = os.path.join(wd_path, 'keystores')
        os.makedirs(cls._keystore_path, exist_ok=True)

        # initialise database things
        db_path = f"sqlite:///{os.path.join(wd_path, 'user.db')}"
        cls._engine = create_engine(db_path)
        Base.metadata.create_all(cls._engine)
        cls._Session = sessionmaker(bind=cls._engine)

    @classmethod
    def get_user(cls, username: str) -> Optional[User]:
        with cls._Session() as session:
            record = session.query(UserRecord).get(username)
            if record:
                if record.username not in cls._keystores:
                    # load the keystore
                    keystore_path = os.path.join(cls._keystore_path, f"{record.keystore_id}.json")
                    cls._keystores[record.username] = Keystore.load(keystore_path, record.keystore_password)

                return User(
                    username=record.username,
                    name=record.name,
                    email=record.email,
                    disabled=record.disabled,
                    hashed_password=record.hashed_password,
                    keystore=cls._keystores[record.username]
                )

            else:
                return None

    @classmethod
    def add_user(cls, username: str, name: str, email: str, password: str) -> User:
        with cls._Session() as session:
            # check if this username already exists
            record = session.query(UserRecord).get(username)
            if record:
                raise AppRuntimeError("Username already exists", details={
                    'username': username
                })

            # create a new keystore
            keystore_password = generate_random_string(16)
            keystore = Keystore.create(cls._keystore_path, name, email, keystore_password)

            # add new user (with a randomly generated password)
            disabled = False
            hashed_password = UserAuth.get_password_hash(password)
            session.add(UserRecord(username=username, name=name, email=email, disabled=disabled,
                                   keystore_id=keystore.identity.id, keystore_password=keystore_password,
                                   hashed_password=hashed_password))
            session.commit()

            # read the record and return the user
            return User(
                username=username,
                name=name,
                email=email,
                disabled=disabled,
                hashed_password=hashed_password,
                keystore=keystore
            )


class UserAuth:
    secret_key = None
    algorithm = 'HS256'
    _access_token_expires_minutes = 30
    _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @classmethod
    def initialise(cls, secret_key: str):
        cls.secret_key = secret_key

    @classmethod
    def _verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return cls._pwd_context.verify(plain_password, hashed_password)

    @classmethod
    def _authenticate_user(cls, username: str, password: str) -> Optional[User]:
        user = UserDB.get_user(username)
        if not user:
            return None

        if not cls._verify_password(password, user.hashed_password):
            return None

        return user

    @classmethod
    def get_password_hash(cls, password: str) -> str:
        return cls._pwd_context.hash(password)

    @classmethod
    async def login_for_access_token(cls, form_data: OAuth2PasswordRequestForm = Depends()) -> Token:
        # get the user
        user = cls._authenticate_user(form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # create the token
        expiry = datetime.utcnow() + timedelta(minutes=cls._access_token_expires_minutes)
        content = {
            'sub': user.username,
            'exp': expiry
        }
        access_token = jwt.encode(content, cls.secret_key, algorithm=cls.algorithm)

        return Token(access_token=access_token, token_type='bearer', expiry=expiry.timestamp())
