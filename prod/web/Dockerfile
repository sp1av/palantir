FROM debian:latest

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    postgresql-client


RUN pip install flask \
	flask_sqlalchemy \
	flask_bcrypt \
	flask_login \
	requests \
	gunicorn \
	argon2-cffi \
	psycopg2-binary --break-system-packages

WORKDIR /app
COPY . .
run chmod +x /app/db_init_stuff/start.sh
EXPOSE 1703

CMD ["python3", "app.py"]
#CMD ["gunicorn", "--bind", "0.0.0.0:1703", "app:app"]
