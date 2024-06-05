#!/usr/bin/env python3
"""
Basic auth module for the API
"""
import base64
from api.v1.auth.auth import Auth
from typing import Tuple


class BasicAuth(Auth):
	"""Basic auth"""
	
	def extract_base64_authorization_header(self,
										    authorization_header: str) -> str:
		"""returns the Base64 part of the Authorization header
		for a Basic Authentication:"""
		return None if (authorization_header is None
				  		or type(authorization_header) is not str
						or not authorization_header.startswith("Basic "))\
						else authorization_header.split("Basic")[-1].strip()
	
	def decode_base64_authorization_header(self,
										   base64_authorization_header: str) -> str:
		"""returns the decoded value of a Base64 string base64_authorization_header"""
		if (base64_authorization_header is None
	  		or type(base64_authorization_header) is not str):
			return None
		try:
			decoded = base64.b64decode(base64_authorization_header)
			return decoded.decode("utf-8")
		except BaseException:
			return None
		
	def extract_user_credentials(self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
		"""in the class BasicAuth that returns the user email and password
		from the Base64 decoded value."""
		return (None, None) if (decoded_base64_authorization_header is None
						        or type())