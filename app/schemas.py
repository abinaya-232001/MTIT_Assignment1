from pydantic import BaseModel, EmailStr, constr
from pydantic import ConfigDict

class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: constr(min_length=8, max_length=72)

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenRefresh(BaseModel):
    refresh_token: str

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str

    model_config = ConfigDict(from_attributes=True)