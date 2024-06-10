#!/usr/bin/env python3
"""Auth Module"""
import bcrypt
from db import DB
from user import User
from typing import TypeVar
from sqlalchemy.orm.exc import NoResultFound


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> TypeVar("User"):
        """takes mandatory email and password string arguments
        and returns a User object."""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError(f"User {email} already exists.")
        except NoResultFound:
            hashed_password = _hash_password(password)
            return self._db.add_user(email, hashed_password)


def _hash_password(password: str) -> bytes:
    """takes in a password string arguments and returns bytes.
    The returned bytes is a salted hash
    of the input password, hashed with bcrypt.hashpw."""
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password
