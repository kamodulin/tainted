from subprocess import Popen, PIPE

from fastapi import FastAPI

app = FastAPI()


@app.get('/create/{project_name}')
async def create_project_dir(project_name: str):
    # execute generate cmd
    cmd = f'mkdir ./{project_name}'  # type: taint[source]
    p = Popen(cmd, shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE)  # type: taint[sink]
    return 'Create Project Directory Success.'
