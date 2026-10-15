from datetime import datetime, timezone, timedelta
from typing import cast

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from schemas.accounts import (
    UserRegistrationResponseSchema,
    UserRegistrationRequestSchema,
    MessageResponseSchema,
    UserActivationRequestSchema,
    PasswordResetRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserLoginRequestSchema,
    UserLoginResponseSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
)
from security.interfaces import JWTAuthManagerInterface

router = APIRouter()


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register_user(
    credentials: UserRegistrationRequestSchema, db: AsyncSession = Depends(get_db)
):
    existing_user = await db.scalar(
        select(UserModel).where(UserModel.email == credentials.email)
    )
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {credentials.email} already exists.",
        )

    user_group_id = await db.scalar(
        select(UserGroupModel.id).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    user = UserModel.create(**credentials.model_dump(), group_id=user_group_id)
    user.activation_token = ActivationTokenModel()

    try:
        db.add(user)
        await db.commit()
        return user
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(
    credentials: UserActivationRequestSchema, db: AsyncSession = Depends(get_db)
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == credentials.email).with_for_update()
    )
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with email {credentials.email} is not found.",
        )
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is already active.",
        )

    db_token = await db.scalar(
        select(ActivationTokenModel)
        .where(ActivationTokenModel.user_id == user.id)
        .with_for_update()
    )
    if not db_token or db_token.token != credentials.token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired activation token.",
        )

    try:
        if cast(datetime, cast(object, db_token.expires_at)).replace(
            tzinfo=timezone.utc
        ) < datetime.now(timezone.utc):
            await db.delete(db_token)
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired activation token.",
            )

        user.is_active = True
        await db.delete(db_token)
        await db.commit()
        return MessageResponseSchema(message="User account activated successfully.")
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while activating the user.",
        )


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def password_reset_request(
    credentials: PasswordResetRequestSchema, db: AsyncSession = Depends(get_db)
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == credentials.email)
    )
    if user and user.is_active:
        try:
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            db.add(PasswordResetTokenModel(user_id=user.id))
            await db.commit()
        except SQLAlchemyError:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="An error occurred while processing the request.",
            )
    return MessageResponseSchema(
        message="If you are registered, you will receive an email with instructions."
    )


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def password_reset_complete(
    credentials: PasswordResetCompleteRequestSchema, db: AsyncSession = Depends(get_db)
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == credentials.email).with_for_update()
    )
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid email or token."
        )

    db_token = await db.scalar(
        select(PasswordResetTokenModel)
        .where(PasswordResetTokenModel.user_id == user.id)
        .with_for_update()
    )

    try:
        if (
            not db_token
            or db_token.token != credentials.token
            or cast(datetime, cast(object, db_token.expires_at)).replace(
                tzinfo=timezone.utc
            )
            < datetime.now(timezone.utc)
        ):
            await db.execute(
                delete(PasswordResetTokenModel).where(
                    PasswordResetTokenModel.user_id == user.id
                )
            )
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid email or token.",
            )

        user.password = credentials.password
        await db.delete(db_token)
        await db.commit()
        return MessageResponseSchema(message="Password reset successfully.")
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login_user(
    credentials: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    user = await db.scalar(
        select(UserModel).where(UserModel.email == credentials.email)
    )
    if not user or not user.verify_password(credentials.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is not activated.",
        )

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token(
        {"user_id": user.id}, timedelta(days=settings.LOGIN_TIME_DAYS)
    )
    refresh_token_model = RefreshTokenModel.create(
        user.id, settings.LOGIN_TIME_DAYS, refresh_token
    )

    try:
        db.add(refresh_token_model)
        await db.commit()
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    return UserLoginResponseSchema(
        access_token=access_token, refresh_token=refresh_token, token_type="bearer"
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh_access_token(
    user_token: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    refresh_token = user_token.refresh_token

    try:
        jwt_data = jwt_manager.decode_refresh_token(refresh_token)
    except BaseSecurityError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token has expired.",
        )

    try:
        db_token = await db.scalar(
            select(RefreshTokenModel)
            .where(RefreshTokenModel.token == refresh_token)
            .options(joinedload(RefreshTokenModel.user))
        )
        if not db_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token not found.",
            )
        if not db_token.user or jwt_data.get("user_id") != db_token.user.id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found.",
            )
    except SQLAlchemyError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while processing the request.",
        )

    access_token = jwt_manager.create_access_token({"user_id": db_token.user.id})
    return TokenRefreshResponseSchema(access_token=access_token)
