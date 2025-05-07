from logging.config import fileConfig
from sqlalchemy import pool, create_engine
from alembic import context
import os
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/../')
from db_sync import Base

config = context.config

# Inject env var into config before usage
# Use the same default as your docker-compose and Helm chart
# (asyncpg for async, or change to postgresql for sync if needed)
db_url = os.getenv("DATABASE_URL")
if not db_url:
    raise Exception("DATABASE_URL environment variable not set")
config.set_main_option("sqlalchemy.url", db_url)

fileConfig(config.config_file_name)
target_metadata = Base.metadata

def run_migrations_online():
    connectable = create_engine(
        config.get_main_option("sqlalchemy.url"),
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata
        )
        with context.begin_transaction():
            context.run_migrations()

def run_migrations_offline():
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url, target_metadata=target_metadata, literal_binds=True
    )
    with context.begin_transaction():
        context.run_migrations()

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online() 