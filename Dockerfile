ARG branch=stable
FROM cccs/assemblyline-v4-service-base:$branch

# Python path to the service class: <package>.<module>.<Class>
ENV SERVICE_PATH=pdfstudio_.service.PdfStudio

# System packages (as root). pkglist.txt may be empty.
USER root
COPY pkglist.txt /tmp/setup/
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/setup/pkglist.txt | tr "\n" " ") && \
    rm -rf /tmp/setup/pkglist.txt /var/lib/apt/lists/*

# Python packages (as the unprivileged runtime user). --chown keeps the build independent of
# host file modes: a 0640 checkout would otherwise be unreadable to the assemblyline user.
USER assemblyline
COPY --chown=assemblyline:assemblyline requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && \
    rm -rf ~/.cache/pip

# pdfstudio at a pinned commit of its public repository. Change deliberately; the sample tests
# show what an upgrade changes. The commit is exposed to the service for its tool version.
ARG PDFSTUDIO_COMMIT=75cf957110b3fb69f58b8f05a8eddc64a21d8a3c
ENV PDFSTUDIO_COMMIT=$PDFSTUDIO_COMMIT
RUN pip install --no-cache-dir --user \
    "pdfstudio @ https://github.com/boredchilada/pdfstudio/archive/${PDFSTUDIO_COMMIT}.tar.gz" && \
    rm -rf ~/.cache/pip && \
    python -c "import pdfstudio.cli, pdfstudio.parser"

WORKDIR /opt/al_service
COPY --chown=assemblyline:assemblyline . .

# Stamp the release version into the manifest (CCCS pattern). CI passes the git tag.
ARG version=4.7.0.dev0
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml && \
    chown -R assemblyline:assemblyline /opt/al_service

USER assemblyline
