import logging
from models import Base, engine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    try:
        logger.info("Начало создания таблиц...")
        Base.metadata.create_all(engine)
        logger.info("Таблицы успешно созданы")
    except Exception as e:
        logger.error(f"Ошибка при создании таблиц: {str(e)}")
        raise