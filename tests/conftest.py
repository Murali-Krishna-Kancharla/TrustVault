import os
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app
from app.seed import seed_database
from app.config import VAULT_STORAGE_DIR

# Use dedicated in-memory or temporary test SQLite database for test suite
TEST_DATABASE_URL = "sqlite:///./test_trustvault.db"
test_engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    
    # Run seeding in test database
    import app.seed as seed_module
    old_engine = seed_module.engine
    old_session = seed_module.SessionLocal
    seed_module.engine = test_engine
    seed_module.SessionLocal = TestingSessionLocal
    seed_module.seed_database()
    
    yield
    
    seed_module.engine = old_engine
    seed_module.SessionLocal = old_session
    if os.path.exists("./test_trustvault.db"):
        try:
            os.remove("./test_trustvault.db")
        except OSError:
            pass

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def db_session():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
