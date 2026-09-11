FROM python:3.12-slim
WORKDIR /guard
RUN pip install --no-cache-dir fastapi uvicorn httpx pyjwt
COPY guard/app.py ./app.py
COPY api.py ./api.py
EXPOSE 8090
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090"]
