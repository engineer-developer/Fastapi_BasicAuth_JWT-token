import sys
from pathlib import Path

import uvicorn


root_path = Path(__file__).parent.resolve().as_posix()
sys.path.insert(0, root_path)

from core.fastapi_factory import create_app


app = create_app()

if __name__ == "__main__":
    uvicorn.run(
        "loader:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
