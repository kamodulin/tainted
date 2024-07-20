from fastapi import FastAPI
from fastapi.responses import FileResponse

app = FastAPI()

"""
Run `uvicorn main:app` to start the web service. 
When you execute `curl  http://127.0.0.1:8000/images?path=../../../../../../../etc/passwd`, 
a path traversal vulnerability will be started. 
"""

@app.get("/images")
async def get_image(path: str):
    def get_absolute_path(rel_path):
        import os
        script_dir = os.path.dirname(__file__)
        abs_file_path = os.path.join(script_dir, rel_path)  # type: taint[sink]
        return abs_file_path

    rel_path = f"./images/{path}"  # type: taint[source]
    image_complete_path = get_absolute_path(rel_path)

    import os
    if os.path.exists(image_complete_path):
        return FileResponse(image_complete_path)
    else:
        return "Not Found"
