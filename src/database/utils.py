import subprocess
from pathlib import Path

from loggers.loggers import logger


def alembic_upgrade_head() -> bool:
    """Run alembic upgrade with shell-command"""

    alembic_upgrade_command = "alembic upgrade head"
    alembic_work_dir = Path(__file__).parent.parent.resolve().as_posix()

    with subprocess.Popen(
        alembic_upgrade_command,
        shell=True,
        cwd=alembic_work_dir,
    ) as proc:
        pass
    exit_code = proc.returncode

    if exit_code != 0:
        logger.error("Alembic upgrade error.")
        return False

    else:
        logger.info("Alembic upgrade too head successful.")
        return True
