from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database import get_db, UserModel
from config import get_jwt_auth_manager
from security.interfaces import JWTAuthManagerInterface

# Переконайся, що цей шлях веде точно на твій POST /login/
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/accounts/login/")


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_manager.decode_access_token(token)
        user_id_raw = payload.get("sub")

        # Валідуємо, що sub є, і це число
        if user_id_raw is None or not str(user_id_raw).isdigit():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: no valid user ID"
            )

        user_id = int(user_id_raw)
    except HTTPException:
        # Перекидаємо нашу помилку валідації далі
        raise
    except Exception:
        # Всі інші помилки декодування (прострочено, кривий підпис тощо)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )

    query = select(UserModel).where(UserModel.id == user_id)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    return user
