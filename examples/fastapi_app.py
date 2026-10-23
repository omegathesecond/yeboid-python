"""Run: pip install fastapi uvicorn; uvicorn examples.fastapi_app:app

Set YEBOID_CLIENT_ID and YEBOID_REDIRECT_URI to the same registration used by
the frontend. This API does not persist PII or print credentials.
"""
import os
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from yeboid import YeboID, YeboIDError

app = FastAPI()
bearer = HTTPBearer(auto_error=False)
identity = YeboID(os.environ["YEBOID_CLIENT_ID"], os.environ["YEBOID_REDIRECT_URI"],
                  client_secret=os.environ.get("YEBOID_CLIENT_SECRET"))


def current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(401, "access_token_required", headers={"WWW-Authenticate": "Bearer"})
    try:
        return identity.verify_access_token(credentials.credentials, ["openid", "profile"])
    except YeboIDError as error:
        status = 401 if error.code == "invalid_token" else 403 if error.code == "insufficient_scope" else 503
        raise HTTPException(status, error.code) from error


@app.get("/me")
def me(claims=Depends(current_user)):
    return {"yeboid_user_id": claims["sub"]}
