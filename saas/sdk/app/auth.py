import os.path
from typing import Optional, List, Tuple
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import Column, String, Boolean, create_engine, Integer
from sqlalchemy.orm import sessionmaker, declarative_base
from jose import jwt

from saas.core.helpers import generate_random_string
from saas.core.identity import Identity
from saas.core.keystore import Keystore
from saas.rest.schemas import Token
from saas.sdk.app.exceptions import AppRuntimeError
from saas.sdk.base import publish_identity

Base = declarative_base()


class UserRecord(Base):
    __tablename__ = 'user'
    login = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    disabled = Column(Boolean, nullable=False)
    keystore_id = Column(String(64), nullable=False)
    keystore_password = Column(String, nullable=False)
    hashed_password = Column(String(64), nullable=False)
    login_attempts = Column(Integer, nullable=False)


class User(BaseModel):
    class Config:
        arbitrary_types_allowed = True

    name: str
    login: str
    disabled: bool
    hashed_password: str
    keystore: Keystore
    login_attempts: int

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
    def publish_all_user_identities(cls, node_address: (str, int)) -> None:
        for user in UserDB.all_users():
            publish_identity(node_address, user.identity)

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
                    keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password),
                    login_attempts=record.login_attempts
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
                raise AppRuntimeError("User account does not exist", details={
                    'login': login
                })

            # create the user object
            result = User(
                login=record.login,
                name=record.name,
                disabled=record.disabled,
                hashed_password=record.hashed_password,
                keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password),
                login_attempts=record.login_attempts
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
                keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password),
                login_attempts=record.login_attempts
            ) for record in records]

    @classmethod
    def add_user(cls, login: str, name: str, password: str, node_address: (str, int) = None) -> User:
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
                                   hashed_password=hashed_password, login_attempts=0))
            session.commit()

            # publish the identity (if we have a node address)
            if node_address:
                publish_identity(node_address, keystore.identity)

            # read the record and return the user
            return User(
                login=login,
                name=name,
                disabled=disabled,
                hashed_password=hashed_password,
                keystore=keystore,
                login_attempts=0
            )

    @classmethod
    def enable_user(cls, login: str) -> User:
        with cls._Session() as session:
            # check if this username already exists
            record = session.query(UserRecord).get(login)
            if record:
                record.disabled = False
                record.login_attempts = 0
                session.commit()

                return User(
                    login=record.login,
                    name=record.name,
                    disabled=record.disabled,
                    hashed_password=record.hashed_password,
                    keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password),
                    login_attempts=record.login_attempts
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
                    keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password),
                    login_attempts=record.login_attempts
                )
            else:
                raise AppRuntimeError("Username does not exist", details={
                    'login': login
                })

    @classmethod
    def update_user(cls, login: str, is_admin: bool, password: Tuple[str, str] = None,
                    user_display_name: str = None) -> User:
        with cls._Session() as session:
            # check if this username exists
            record = session.query(UserRecord).get(login)
            if record:
                if user_display_name:
                    record.name = user_display_name
                if password:
                    # admin has access to change other users password
                    if is_admin:
                        record.hashed_password = UserAuth.get_password_hash(password[1])
                    # check previous password when user changing their password
                    elif password[0]:
                        if UserAuth.verify_password(password[0], record.hashed_password):
                            record.hashed_password = UserAuth.get_password_hash(password[1])
                        else:
                            raise AppRuntimeError("Password does not match", details={
                                'login': login
                            })
                    else:
                        raise AppRuntimeError("Please provide the previous password", details={
                            'login': login
                        })

                session.commit()
                return User(
                    login=record.login,
                    name=record.name,
                    disabled=record.disabled,
                    hashed_password=record.hashed_password,
                    keystore=cls._resolve_keystore(record.keystore_id, record.keystore_password),
                    login_attempts=record.login_attempts
                )

            else:
                raise AppRuntimeError("Username does not exist", details={
                    'login': login
                })

    @classmethod
    def update_login_attempts(cls, login: str, successful: bool) -> User:
        with cls._Session() as session:
            # check if this username already exists
            user = session.query(UserRecord).get(login)

            if user:
                # reset the login attempts count, if it's a successful login
                if successful:
                    user.login_attempts = 0
                # increase the login attempts count, if it's a failed login attempt
                else:
                    user.login_attempts += 1
                session.commit()

                return User(
                    login=user.login,
                    name=user.name,
                    disabled=user.disabled,
                    hashed_password=user.hashed_password,
                    keystore=cls._resolve_keystore(user.keystore_id, user.keystore_password),
                    login_attempts=user.login_attempts
                )
            elif not user:
                raise AppRuntimeError("Username does not exist", details={
                    'login': login
                })


class UserAuth:
    secret_key = None
    algorithm = 'HS256'
    _access_token_expires_minutes = 30
    _max_login_attempts = 5
    _pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    @classmethod
    def initialise(cls, secret_key: str):
        cls.secret_key = secret_key

    @classmethod
    def verify_password(cls, plain_password: str, hashed_password: str) -> bool:
        return cls._pwd_context.verify(plain_password, hashed_password)

    @classmethod
    def _authenticate_user(cls, login: str, password: str) -> Optional[User]:
        user = UserDB.get_user(login)
        # not a user
        if not user:
            return None

        # user is not disabled? verify password
        if not user.disabled:
            if not cls.verify_password(password, user.hashed_password):
                # if password is incorrect, update the failed login attempts count
                user = UserDB.update_login_attempts(login, False)
                # if the login attempts count has reached the maximum value, disable the user
                if user.login_attempts >= cls._max_login_attempts:
                    UserDB.disable_user(login)
                    return 'locked'
                return None

            # if credentials and correct and user already has failed login attempts, rest the login attempts count
            if user.login_attempts > 0:
                user = UserDB.update_login_attempts(login, True)

            return user
        else:
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
        # The user account has been disabled due to exceeding the limit for failed login attempts
        elif user == 'locked':
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="The user account is locked due to exceeding the limit for failed login attempts",
                headers={"WWW-Authenticate": "Locked"},
            )
        # The user account has been already disabled due to exceeding the limit for failed login attempts
        elif user.disabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User account has been locked",
                headers={"WWW-Authenticate": "Locked"},
            )

        # create the token
        now = datetime.now(tz=timezone.utc)
        expiry = now + timedelta(minutes=cls._access_token_expires_minutes)
        content = {
            'sub': user.login,
            'exp': expiry
        }
        access_token = jwt.encode(content, cls.secret_key, algorithm=cls.algorithm)

        token = Token(access_token=access_token, token_type='bearer', expiry=expiry.timestamp())
        return token
