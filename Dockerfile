FROM python:3.11

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | POETRY_HOME=/opt/poetry python && \
    cd /usr/local/bin && \
    ln -s /opt/poetry/bin/poetry && \
    poetry config virtualenvs.create false

# Copy using poetry.lock* in case it doesn't exist yet
COPY ./pyproject.toml ./poetry.lock* /app/

WORKDIR  /app/

RUN poetry install --no-root --only main

COPY ./flaskblog /app/

ENV FLASK_APP="run.py"

# RUN poetry install --no-dev
CMD [ "python3", "-m" , "flask", "run", "--host=0.0.0.0"]


# ENV GUNICORN_CMD_ARGS --proxy-protocol
# ENV MODULE_NAME podping_api_ext.main

# CMD ["unicorn", "podping_api_ext.main:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "80"]
# CMD ["gunicorn", "podping_api_ext.main:app","--proxy-protocol", "--workers", "4", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind"  , "0.0.0.0:80"]