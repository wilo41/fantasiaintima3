# Usa una imagen oficial de Python
FROM python:3.10

# Establece el directorio de trabajo
WORKDIR /app

# Copia los archivos del proyecto
COPY . /app

# Instala las dependencias
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Expone el puerto para Gunicorn
EXPOSE 8000

# Comando para iniciar Gunicorn
CMD ["gunicorn", "sexshop.wsgi:application", "--bind", "0.0.0.0:8000"]