# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory in the container
WORKDIR /app

# Install Autobahn library
RUN pip install autobahn

# Copy the current directory contents into the container at /app
COPY . /app

# Run the Python backend service
CMD bash -c "sleep 10 && python app.py"
