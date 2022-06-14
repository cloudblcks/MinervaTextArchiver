# Pull a base image
FROM python:3.10.1-slim

# Set environment variables
ENV ENV=test \
  PYTHONFAULTHANDLER=1 \
  PYTHONDONTWRITEBYTECODE=1 \
  PYTHONUNBUFFERED=1 \
  PYTHONHASHSEED=random \
  PIP_NO_CACHE_DIR=off \
  PIP_DISABLE_PIP_VERSION_CHECK=on \
  PIP_DEFAULT_TIMEOUT=100 \
  PIP_VERSION=22.1.1

# Create a working directory for the django project
WORKDIR /src

RUN apt-get update \
   && apt-get -y install libffi-dev libpq-dev gcc python3-dev musl-dev vim less \
   && pip install "pip==$PIP_VERSION" --upgrade \
   && apt-get clean


# Copy requirements to the container
COPY requirements.txt /src/

RUN pip install -r /src/requirements.txt

# Copy the project files into the working directory
COPY . /src/

RUN python /src/manage.py collectstatic --no-input
EXPOSE 8000
