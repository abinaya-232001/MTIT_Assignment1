from fastapi import FastAPI, Depends
from app.database import Base, engine
from app.routes import auth
from app.core.dependencies import require_role
from app.models import User

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secure Auth API")

# Include auth router
app.include_router(auth.router)

@app.get("/admin", tags=["Admin"])
def admin_dashboard(current_user: User = Depends(require_role("admin"))):
    return {"message": f"Admin access granted to {current_user.username}"}