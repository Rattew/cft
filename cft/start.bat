start "chrome.exe" http://127.0.0.1:8000/auth/
uvicorn main:app --reload
