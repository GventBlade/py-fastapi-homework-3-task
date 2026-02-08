from datetime import datetime, timezone
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, joinedload

from config import get_jwt_auth_manager, settings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from schemas import UserLoginRequestSchema
from security.dependencies import get_current_user
from security.interfaces import JWTAuthManagerInterface

from schemas.accounts import UserResponseSchema, UserRegistrationRequestSchema, UserActivationRequestSchema, \
    PasswordResetRequestSchema, PasswordResetConfirmSchema, TokenPairResponseSchema, TokenRefreshRequestSchema

router = APIRouter()

@router.post("/register/", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)):
    query = select(UserModel).where(UserModel.email == user_data.email)
    result = await db.execute(query)
    db_user = result.scalar_one_or_none()

    if db_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"A user with this email {user_data.email} already exists.")

    group_query = select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    group_result = await db.execute(group_query)
    group = group_result.scalar_one()

    new_user = UserModel.create(
        email=user_data.email,
        raw_password=user_data.password,
        group_id=group.id
    )
    db.add(new_user)

    try:
        await db.flush()
        from security.utils import generate_secure_token
        activation_token = ActivationTokenModel(
            user_id=cast(int, new_user.id),
            token=generate_secure_token()
        )
        db.add(activation_token)

        await db.commit()
        await db.refresh(new_user)
        return new_user

    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.")

@router.post("/activate/", status_code=status.HTTP_200_OK)
async def activate(data: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)):
    query = select(ActivationTokenModel).options(joinedload(ActivationTokenModel.user)).where(ActivationTokenModel.token == data.token)
    result = await db.execute(query)
    token_record = result.scalar_one_or_none()

    if not token_record or not token_record.user or token_record.user.email != data.email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    current_time = datetime.now(timezone.utc)
    token_expiry = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)

    if token_expiry < current_time:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token."
        )

    if token_record.user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active."
        )

    token_record.user.is_active = True

    await db.delete(token_record)
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
    return {"message": "User account activated successfully."}


@router.post("/password-reset/request/", status_code=status.HTTP_200_OK)
async def request_password_reset(data: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)):
    query = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if user and user.is_active:
        await db.execute(delete(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id))
        from security.utils import generate_secure_token
        reset_token = PasswordResetTokenModel(user_id=cast(int, user.id), token=generate_secure_token())
        db.add(reset_token)
        await db.commit()

    return {"message": "If you are registered, you will receive an email with instructions."}


@router.post("/reset-password/complete/", status_code=status.HTTP_200_OK)
async def confirm_password_reset(data: PasswordResetConfirmSchema, db: AsyncSession = Depends(get_db)):
    # 1. Шукаємо токен
    query = select(PasswordResetTokenModel).options(joinedload(PasswordResetTokenModel.user)).where(PasswordResetTokenModel.token == data.token)
    result = await db.execute(query)
    token_record = result.scalar_one_or_none()

    # 2. Якщо токена немає взагалі
    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    # 3. Перевірка на прострочення (робимо це ДО перевірки імейла)
    current_time = datetime.now(timezone.utc)
    token_expiry = cast(datetime, token_record.expires_at).replace(tzinfo=timezone.utc)

    if token_expiry < current_time:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    # 4. Перевірка імейла (якщо не збігається — ВИДАЛЯЄМО токен, як просив ментор)
    if not token_record.user or token_record.user.email != data.email:
        await db.delete(token_record)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    # 5. Оновлення пароля (використовуємо сетер моделі, він сам захешує)
    token_record.user.password = data.password

    # 6. Видаляємо використаний токен
    await db.delete(token_record)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500,
            detail="An error occurred while resetting the password."
        )

    return {"message": "Password reset successfully."}


@router.post("/login/", response_model=TokenPairResponseSchema)
async def login(
    data: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    query = select(UserModel).where(UserModel.email == data.email)
    result = await db.execute(query)
    user = result.scalar_one_or_none()

    if not user or not user.verify_password(data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated."
        )

    access_token = jwt_manager.create_access_token(payload={"sub": str(user.id)})
    refresh_token = jwt_manager.create_refresh_token(payload={"sub": str(user.id)})

    await db.execute(delete(RefreshTokenModel).where(RefreshTokenModel.user_id == user.id))

    db_refresh_token = RefreshTokenModel.create(
        user_id=cast(int, user.id),
        days_valid=settings.REFRESH_TOKEN_EXPIRE_DAYS,
        token=refresh_token
)
    db.add(db_refresh_token)
    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@router.post("/api/v1/accounts/refresh/")
async def refresh_token(
    data: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager)
):
    try:
        payload = jwt_manager.decode_refresh_token(data.refresh_token)
        token_user_id = payload.get("sub")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired."
        )

    query = select(RefreshTokenModel).options(joinedload(RefreshTokenModel.user)).where(
        RefreshTokenModel.token == data.refresh_token)
    result = await db.execute(query)
    db_token = result.scalar_one_or_none()

    if not db_token or str(db_token.user_id) != str(token_user_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token not found."
        )

    if db_token.user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )

    current_user_id = db_token.user_id

    new_access_token = jwt_manager.create_access_token(payload={"sub": str(current_user_id)})
    new_refresh_token = jwt_manager.create_refresh_token(payload={"sub": str(current_user_id)})

    await db.delete(db_token)

    new_db_token = RefreshTokenModel.create(
        user_id=current_user_id,
        days_valid=settings.REFRESH_TOKEN_EXPIRE_DAYS,
        token=new_refresh_token
    )
    db.add(new_db_token)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request."
        )
    return {"access_token": new_access_token}


@router.get("/me/", response_model=UserResponseSchema)
async def get_me(user: UserModel = Depends(get_current_user)):

    return user
