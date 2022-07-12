FROM getsentry/sentry:latest

COPY . /usr/src/sentry

EXPOSE 9000

# Hook for installing additional plugins
RUN if [ -s /usr/src/sentry/requirements.txt ]; then pip install -r /usr/src/sentry/requirements.txt; fi
