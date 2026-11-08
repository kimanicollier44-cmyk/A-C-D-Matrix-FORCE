FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN python -m py_compile main.py purple_analyzer/*.py
CMD ["python", "main.py", "demo"]
