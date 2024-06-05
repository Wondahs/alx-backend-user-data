#!/usr/bin/env python3
"""
Auth module for the API
"""
from flask import request
from typing import TypeVar, List


class Auth:
    """Auth class"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        returns True if the path is not in the list of strings excluded_paths
        """
        if path is None or excluded_paths in [[], None]:
            return True
        if not path.endswith("*"):
            path = path if path.endswith('/') else path + '/'
            return path not in excluded_paths
        else:
            path = path.strip("/") if path.endswith('/') else path
            path = path.replace("*", "")
            return not all(path in ex_path for ex_path in excluded_paths)

    def authorization_header(self, request=None) -> str:
        """ validate all requests to secure the API"""
        if request is None:
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """returns None"""
        return None
