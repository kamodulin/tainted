import sqlite3

from fastapi import FastAPI, HTTPException, status

conn = sqlite3.connect(":memory:")
app = FastAPI()

conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)")


def fetch_one(query: str):
    cursor = conn.cursor()
    result = cursor.execute(query)  # type: taint[sink]
    user = result.fetchone()
    return user


@app.get("/users/{user_id}")
async def get_user(*, user_id: str):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # type: taint[source]
    user = fetch_one(query)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="The requested user does not exist",
        )
    return user
