ARG branch=stable
FROM cccs/assemblyline-v4-service-base:$branch

# Python path to the service class: <package>.<module>.<Class>
ENV SERVICE_PATH=pdfstudio_.pdfstudio_.PdfStudio

# Install apt dependencies (git is required to pip-install pdfstudio from source)
USER root
COPY pkglist.txt /tmp/setup/
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/setup/pkglist.txt | tr "\n" " ") && \
    rm -rf /tmp/setup/pkglist.txt /var/lib/apt/lists/*

# Install python dependencies (drop to the assemblyline user)
USER assemblyline
COPY requirements.txt requirements.txt
RUN pip install \
    --no-cache-dir \
    --user \
    --requirement requirements.txt && \
    rm -rf ~/.cache/pip

# Install pdfstudio itself. Override PDFSTUDIO_REF with a commit SHA at build
# time for a reproducible, pinned build:
#   docker build --build-arg PDFSTUDIO_REF=<sha> ...
ARG PDFSTUDIO_REF=main
RUN pip install \
    --no-cache-dir \
    --user \
    "pdfstudio[yara] @ git+https://github.com/boredchilada/pdfstudio.git@${PDFSTUDIO_REF}" && \
    rm -rf ~/.cache/pip

# Copy the service code
WORKDIR /opt/al_service
COPY . .

# Ensure the service code is owned by the unprivileged runtime user
USER root
RUN chown -R assemblyline:assemblyline /opt/al_service

# Drop back to the unprivileged user for execution
USER assemblyline
