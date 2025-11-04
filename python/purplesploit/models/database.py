"""
Database Models
SQLAlchemy ORM models for PurpleSploit databases
Maps to existing SQLite databases created by Bash scripts
"""

from datetime import datetime
from pathlib import Path
from typing import Optional, List
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
from pydantic import BaseModel, Field

# Base class for all models
Base = declarative_base()

# Database paths (compatible with Bash implementation)
DB_DIR = Path.home() / ".purplesploit"
CREDENTIALS_DB = DB_DIR / "credentials.db"
TARGETS_DB = DB_DIR / "targets.db"
WEB_TARGETS_DB = DB_DIR / "web_targets.db"
AD_TARGETS_DB = DB_DIR / "ad_targets.db"
SERVICES_DB = DB_DIR / "services.db"


# ============================================================================
# SQLAlchemy ORM Models
# ============================================================================

class Credential(Base):
    """Credential storage model"""
    __tablename__ = "credentials"
    __table_args__ = {'extend_existing': True}

    name = Column(String, primary_key=True)
    username = Column(String)
    password = Column(String)
    domain = Column(String)
    hash = Column(String)

    def to_dict(self):
        return {
            "name": self.name,
            "username": self.username,
            "password": self.password,
            "domain": self.domain,
            "hash": self.hash,
        }


class Target(Base):
    """Network target model"""
    __tablename__ = "targets"
    __table_args__ = {'extend_existing': True}

    name = Column(String, primary_key=True)
    ip = Column(String)
    description = Column(String)

    def to_dict(self):
        return {
            "name": self.name,
            "ip": self.ip,
            "description": self.description,
        }


class WebTarget(Base):
    """Web target model"""
    __tablename__ = "web_targets"
    __table_args__ = {'extend_existing': True}

    name = Column(String, primary_key=True)
    url = Column(String)
    description = Column(String)

    def to_dict(self):
        return {
            "name": self.name,
            "url": self.url,
            "description": self.description,
        }


class ADTarget(Base):
    """Active Directory target model"""
    __tablename__ = "ad_targets"
    __table_args__ = {'extend_existing': True}

    name = Column(String, primary_key=True)
    domain = Column(String)
    dc_ip = Column(String)
    description = Column(String)

    def to_dict(self):
        return {
            "name": self.name,
            "domain": self.domain,
            "dc_ip": self.dc_ip,
            "description": self.description,
        }


class Service(Base):
    """Detected service model"""
    __tablename__ = "services"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True, autoincrement=True)
    target = Column(String)
    service = Column(String)
    port = Column(Integer)
    version = Column(String)

    def to_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "service": self.service,
            "port": self.port,
            "version": self.version,
        }


# ============================================================================
# Pydantic Schemas (for API validation)
# ============================================================================

class CredentialCreate(BaseModel):
    """Schema for creating credentials"""
    name: str
    username: Optional[str] = None
    password: Optional[str] = None
    domain: Optional[str] = None
    hash: Optional[str] = None


class CredentialResponse(BaseModel):
    """Schema for credential responses"""
    name: str
    username: Optional[str]
    password: Optional[str]
    domain: Optional[str]
    hash: Optional[str]

    class Config:
        from_attributes = True


class TargetCreate(BaseModel):
    """Schema for creating targets"""
    name: str
    ip: str
    description: Optional[str] = None


class TargetResponse(BaseModel):
    """Schema for target responses"""
    name: str
    ip: str
    description: Optional[str]

    class Config:
        from_attributes = True


class ServiceResponse(BaseModel):
    """Schema for service responses"""
    id: int
    target: str
    service: str
    port: int
    version: Optional[str]

    class Config:
        from_attributes = True


# ============================================================================
# Database Manager
# ============================================================================

class DatabaseManager:
    """Manages database connections and sessions"""

    def __init__(self):
        """Initialize database connections"""
        # Ensure database directory exists
        DB_DIR.mkdir(parents=True, exist_ok=True)

        # Create engines for each database
        self.engines = {
            "credentials": create_engine(f"sqlite:///{CREDENTIALS_DB}"),
            "targets": create_engine(f"sqlite:///{TARGETS_DB}"),
            "web_targets": create_engine(f"sqlite:///{WEB_TARGETS_DB}"),
            "ad_targets": create_engine(f"sqlite:///{AD_TARGETS_DB}"),
            "services": create_engine(f"sqlite:///{SERVICES_DB}"),
        }

        # Create session makers
        self.session_makers = {
            name: sessionmaker(bind=engine)
            for name, engine in self.engines.items()
        }

        # Create tables if they don't exist
        self._create_tables()

    def _create_tables(self):
        """Create all tables"""
        Base.metadata.create_all(self.engines["credentials"], tables=[Credential.__table__])
        Base.metadata.create_all(self.engines["targets"], tables=[Target.__table__])
        Base.metadata.create_all(self.engines["web_targets"], tables=[WebTarget.__table__])
        Base.metadata.create_all(self.engines["ad_targets"], tables=[ADTarget.__table__])
        Base.metadata.create_all(self.engines["services"], tables=[Service.__table__])

    def get_session(self, db_name: str) -> Session:
        """Get a database session"""
        return self.session_makers[db_name]()

    def get_credentials_session(self) -> Session:
        """Get credentials database session"""
        return self.get_session("credentials")

    def get_targets_session(self) -> Session:
        """Get targets database session"""
        return self.get_session("targets")

    def get_web_targets_session(self) -> Session:
        """Get web targets database session"""
        return self.get_session("web_targets")

    def get_ad_targets_session(self) -> Session:
        """Get AD targets database session"""
        return self.get_session("ad_targets")

    def get_services_session(self) -> Session:
        """Get services database session"""
        return self.get_session("services")

    # Convenience methods
    def get_all_credentials(self) -> List[Credential]:
        """Get all credentials"""
        session = self.get_credentials_session()
        try:
            return session.query(Credential).all()
        finally:
            session.close()

    def get_all_targets(self) -> List[Target]:
        """Get all targets"""
        session = self.get_targets_session()
        try:
            return session.query(Target).all()
        finally:
            session.close()

    def get_services_for_target(self, target: str) -> List[Service]:
        """Get all services for a target"""
        session = self.get_services_session()
        try:
            return session.query(Service).filter(Service.target == target).all()
        finally:
            session.close()

    def add_credential(self, cred: CredentialCreate) -> Credential:
        """Add a credential"""
        session = self.get_credentials_session()
        try:
            db_cred = Credential(**cred.dict())
            session.add(db_cred)
            session.commit()
            session.refresh(db_cred)
            return db_cred
        finally:
            session.close()

    def add_target(self, target: TargetCreate) -> Target:
        """Add a target"""
        session = self.get_targets_session()
        try:
            db_target = Target(**target.dict())
            session.add(db_target)
            session.commit()
            session.refresh(db_target)
            return db_target
        finally:
            session.close()


# Global database manager instance
db_manager = DatabaseManager()
