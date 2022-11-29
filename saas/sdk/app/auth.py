import os.path
from typing import Optional, List
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
    login = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    disabled = Column(Boolean, nullable=False)
    keystore_id = Column(String(64), nullable=False)
    keystore_password = Column(String, nullable=False)
    hashed_password = Column(String(64), nullable=False)


class User(BaseModel):
    class Config:
        arbitrary_types_allowed = True

    name: str
    login: str
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
    def initialise(cls, wd_path: str) -> None:
        # create directories
        cls._keystore_path = os.path.join(wd_path, 'keystores')
        os.makedirs(cls._keystore_path, exist_ok=True)

        # initialise database things
        db_path = f"sqlite:///{os.path.join(wd_path, 'user.db')}"
        cls._engine = create_engine(db_path)
        Base.metadata.create_all(cls._engine)
        cls._Session = sessionmaker(bind=cls._engine)

    @classmethod
    def _resolve_keystore(cls, keystore_id: str, keystore_password: str) -> Keystore:
        if keystore_id not in cls._keystores:
            keystore_path = os.path.join(cls._keystore_path, f"{keystore_id}.json")
            cls._keystores[keystore_id] = Keystore.load(keystore_path, keystore_password)
        return cls._keystores[keystore_id]

    @classmethod
    def get_user(cls, login: str) -> Optional[User]:
        with cls._Session() as session:
            record = session.query(UserRecord).get(login)
            if record:
                return User(
                    login=record.login,
                    name=record.name,
                    disabled=record.disabled,
                    hashed_password=record.hashed_password,
                    keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password)
                )

            else:
                return None

    @classmethod
    def delete_user(cls, login: str) -> Optional[User]:
        with cls._Session() as session:
            q = session.query(UserRecord).filter_by(login=login)

            # does the user exist?
            record = q.first()
            if not record:
                raise AppRuntimeError(f"User account does not exist", details={
                    'login': login
                })

            # create the user object
            result = User(
                login=record.login,
                name=record.name,
                disabled=record.disabled,
                hashed_password=record.hashed_password,
                keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password)
            )

            # remove the keystore and delete it
            cls._resolve_keystore(record.keystore_id, record.keystore_password)
            keystore = cls._keystores.pop(record.keystore_id)
            keystore.delete()

            # remove the record
            q.delete()
            session.commit()

            return result

    @classmethod
    def all_users(cls) -> List[User]:
        with cls._Session() as session:
            records = session.query(UserRecord).all()
            return [User(
                login=record.login,
                name=record.name,
                disabled=record.disabled,
                hashed_password=record.hashed_password,
                keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password)
            ) for record in records]

    @classmethod
    def add_user(cls, login: str, name: str, password: str) -> User:
        with cls._Session() as session:
            # check if this username already exists
            record = session.query(UserRecord).get(login)
            if record:
                raise AppRuntimeError("User account already exists", details={
                    'login': login
                })

            # create a new keystore
            keystore_password = generate_random_string(16)
            keystore = Keystore.create(cls._keystore_path, name, login, keystore_password)
            cls._keystores[keystore.identity.id] = keystore

            # add new user (with a randomly generated password)
            disabled = False
            hashed_password = UserAuth.get_password_hash(password)
            session.add(UserRecord(login=login, name=name, disabled=disabled,
                                   keystore_id=keystore.identity.id, keystore_password=keystore_password,
                                   hashed_password=hashed_password))
            session.commit()

            # read the record and return the user
            return User(
                login=login,
                name=name,
                disabled=disabled,
                hashed_password=hashed_password,
                keystore=keystore
            )

    @classmethod
    def enable_user(cls, login: str) -> User:
        with cls._Session() as session:
            # check if this username already exists
            record = session.query(UserRecord).get(login)
            if record:
                record.disabled = False
                session.commit()

                return User(
                    login=record.login,
                    name=record.name,
                    disabled=record.disabled,
                    hashed_password=record.hashed_password,
                    keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password)
                )
            else:
                raise AppRuntimeError("Username does not exist", details={
                    'login': login
                })

    @classmethod
    def disable_user(cls, login: str) -> User:
        with cls._Session() as session:
            # check if this username already exists
            record = session.query(UserRecord).get(login)
            if record:
                record.disabled = True
                session.commit()

                return User(
                    login=record.login,
                    name=record.name,
                    disabled=record.disabled,
                    hashed_password=record.hashed_password,
                    keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password)
                )
            else:
                raise AppRuntimeError("Username does not exist", details={
                    'login': login
                })


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
    def _authenticate_user(cls, login: str, password: str) -> Optional[User]:
        user = UserDB.get_user(login)
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
            'sub': user.login,
            'exp': expiry
        }
        access_token = jwt.encode(content, cls.secret_key, algorithm=cls.algorithm)

        return Token(access_token=access_token, token_type='bearer', expiry=expiry.timestamp())
