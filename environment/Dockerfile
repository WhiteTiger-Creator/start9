FROM public.ecr.aws/docker/library/python:3.13-slim-bookworm@sha256:01f42367a0a94ad4bc17111776fd66e3500c1d87c15bbd6055b7371d39c124fb

ENV DEBIAN_FRONTEND=noninteractive

# Least-volatile layers first: fix the working directory before the apt and
# dependency layers so a change to those never invalidates the WORKDIR layer.
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tmux \
        asciinema \
    && rm -rf /var/lib/apt/lists/*

# /app/data/expanded_bindings.json ships holding the previous cycle's SHALLOW
# expansion, exactly as the stalled review left it; the alias-addressed bindings
# and the directory export beside it are the sources it has to be rebuilt from.
COPY app/ /app/
RUN cp /app/workflow/resolve_access.py /app/workflow/.resolve_access.original \
    && chmod a-w /app/workflow/.resolve_access.original
